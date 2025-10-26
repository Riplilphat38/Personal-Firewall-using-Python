#!/usr/bin/env python3
"""
Personal firewall: NFQUEUE-based active blocking + passive sniffing mode.

Usage:
  sudo python3 firewall.py --mode active --queue 1 --rules rules.json
  sudo python3 firewall.py --mode passive --iface eth0 --rules rules.json
"""

import argparse
import json
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import os
import signal
import sys
import threading
import time
from collections import deque

# external deps
from scapy.all import IP, TCP, UDP, ICMP, sniff
from netfilterqueue import NetfilterQueue
LOG_FILE = "var/log/personal_firewall.log"
 
# may need root
LIVE_QUEUE_MAX = 500  # in-memory recent items for GUI
# ----------------
logger = logging.getLogger("PersonalFirewall")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=3)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# in-memory recent logs for GUI/CLI display
live_logs = deque(maxlen=LIVE_QUEUE_MAX)
live_logs_lock = threading.Lock()

def live_log(msg):
    with live_logs_lock:
        live_logs.appendleft(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}")
    logger.info(msg)

# --- Rule engine ---
class Rule:
    def __init__(self, rid, action, direction="ANY", ip=None, port=None, proto="ANY", comment=""):
        self.id = rid
        self.action = action.upper()
        self.direction = direction.upper()
        self.ip = ip  # string or None
        self.port = port
        self.proto = proto.upper()
        self.comment = comment

        # preprocess
        self.ip_network = None
        if self.ip:
            try:
                if '/' in self.ip:
                    self.ip_network = ipaddress.ip_network(self.ip, strict=False)
                else:
                    self.ip_network = ipaddress.ip_network(self.ip + '/32')
            except ValueError:
                self.ip_network = None

    def matches_packet(self, pkt_info):
        """pkt_info: dict with keys src, dst, sport, dport, proto, direction"""
        # direction check
        if self.direction != "ANY" and pkt_info.get("direction") != self.direction:
            return False

        # proto check
        if self.proto != "ANY" and self.proto != pkt_info.get("proto"):
            return False

        # ip check: if rule has IP, either src or dst depending on direction or ANY
        if self.ip_network:
            src_in = ipaddress.ip_address(pkt_info["src"]) in self.ip_network
            dst_in = ipaddress.ip_address(pkt_info["dst"]) in self.ip_network
            if not (src_in or dst_in):
                return False

        # port check: if rule has port
        if self.port is not None:
            prule = self.port
            p = pkt_info.get("dport") or pkt_info.get("sport")
            if isinstance(prule, str) and '-' in prule:
                lo, hi = [int(x) for x in prule.split('-', 1)]
                if not (lo <= (p or 0) <= hi):
                    return False
            else:
                if p is None:
                    return False
                if int(prule) != int(p):
                    return False

        return True

    def __repr__(self):
        return f"Rule(id={self.id},action={self.action},dir={self.direction},ip={self.ip},port={self.port},proto={self.proto})"

class RuleSet:
    def __init__(self, default_action="ALLOW"):
        self.rules = []
        self.default_action = default_action.upper()

    @classmethod
    def load_from_file(cls, path):
        rs = cls()
        with open(path, "r") as f:
            data = json.load(f)
        rs.default_action = data.get("default_action", "ALLOW").upper()
        for r in data.get("rules", []):
            rule = Rule(
                rid=r.get("id"),
                action=r.get("action"),
                direction=r.get("direction", "ANY"),
                ip=r.get("ip"),
                port=r.get("port"),
                proto=r.get("proto", "ANY"),
                comment=r.get("comment", "")
            )
            rs.rules.append(rule)
        return rs

    def decide(self, pkt_info):
        # rules evaluated in order they are in file
        for r in self.rules:
            if r.matches_packet(pkt_info):
                return r.action, r
        return self.default_action, None

# --- Packet inspection helpers ---
def pkt_to_info(pkt):
    """Return dictionary with basic packet info from scapy/NetfilterQueue packet"""
    info = {"src": None, "dst": None, "sport": None, "dport": None, "proto": "ANY", "direction": "ANY"}

    # If pkt is scapy packet
    if isinstance(pkt, IP) or pkt.haslayer(IP):
        ip = pkt[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info["sport"] = tcp.sport
            info["dport"] = tcp.dport
            info["proto"] = "TCP"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info["sport"] = udp.sport
            info["dport"] = udp.dport
            info["proto"] = "UDP"
        elif pkt.haslayer(ICMP):
            info["proto"] = "ICMP"
    else:
        # pkt is raw payload from NFQueue: construct using scapy.IP
        try:
            scpkt = IP(pkt.get_payload())
            info["src"] = scpkt.src
            info["dst"] = scpkt.dst
            if scpkt.haslayer(TCP):
                info["sport"] = scpkt[TCP].sport
                info["dport"] = scpkt[TCP].dport
                info["proto"] = "TCP"
            elif scpkt.haslayer(UDP):
                info["sport"] = scpkt[UDP].sport
                info["dport"] = scpkt[UDP].dport
                info["proto"] = "UDP"
            elif scpkt.haslayer(ICMP):
                info["proto"] = "ICMP"
        except Exception:
            pass

    # direction: best-effort. If dst is local addresses then IN else OUT.
    # We'll treat 127.0.0.1 and local configured addresses as local -> require more precise check in prod.
    try:
        # treat RFC1918 and loopback addresses as local (simple heuristic)
        dst_ip = ipaddress.ip_address(info["dst"]) if info["dst"] else None
        if dst_ip and (dst_ip.is_private or dst_ip.is_loopback):
            info["direction"] = "IN"
        else:
            info["direction"] = "OUT"
    except Exception:
        info["direction"] = "ANY"

    return info

# --- Active NFQUEUE mode ---
class ActiveFirewall:
    def __init__(self, queue_num, ruleset):
        self.queue_num = queue_num
        self.ruleset = ruleset
        self.nfqueue = NetfilterQueue()
        self._running = False

    def _callback(self, nf_pkt):
        try:
            pkt_info = pkt_to_info(nf_pkt)  # works because pkt is netfilterqueue packet
        except Exception:
            # fallback: parse payload
            try:
                scpkt = IP(nf_pkt.get_payload())
                pkt_info = pkt_to_info(scpkt)
            except Exception:
                pkt_info = {"src": None, "dst": None, "sport": None, "dport": None, "proto": "ANY", "direction": "ANY"}

        action, rule = self.ruleset.decide(pkt_info)
        summary = f"Pkt src={pkt_info.get('src')} dst={pkt_info.get('dst')} proto={pkt_info.get('proto')} sport={pkt_info.get('sport')} dport={pkt_info.get('dport')} decision={action}"
        if rule:
            summary += f" via rule={rule.id}"
        live_log(summary)

        if action == "BLOCK":
            try:
                nf_pkt.drop()
            except Exception:
                # as fallback, accept
                nf_pkt.accept()
        else:
            nf_pkt.accept()

    def start(self):
        self._running = True
        self.nfqueue.bind(self.queue_num, self._callback)
        live_log(f"Active firewall started on NFQUEUE {self.queue_num}")
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            pass

    def stop(self):
        try:
            self.nfqueue.unbind()
        except Exception:
            pass
        self._running = False
        live_log("Active firewall stopped")

# --- Passive sniffing mode ---
def passive_sniff(iface, ruleset):
    # sniff packets and log rule matches; no dropping
    def _pkt_cb(pkt):
        info = pkt_to_info(pkt)
        action, rule = ruleset.decide(info)
        summary = f"(PASSIVE) src={info.get('src')} dst={info.get('dst')} proto={info.get('proto')} sport={info.get('sport')} dport={info.get('dport')} match={action}"
        if rule:
            summary += f" rule={rule.id}"
        live_log(summary)

    live_log(f"Starting passive sniff on iface {iface}. Ctrl-C to stop.")
    sniff(iface=iface, prn=_pkt_cb, store=False)

# --- iptables helper functions (invoked by user) ---
def run_cmd(cmd):
    import subprocess
    live_log(f"Run: {cmd}")
    return subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def setup_nfqueue(queue_num, chains=("INPUT","FORWARD","OUTPUT")):
    # create iptables rules to send traffic to NFQUEUE
    for c in chains:
        cmd = f"iptables -I {c} -j NFQUEUE --queue-num {queue_num}"
        run_cmd(cmd)
    live_log(f"Inserted iptables NFQUEUE rules (queue {queue_num})")

def clear_nfqueue(queue_num, chains=("INPUT","FORWARD","OUTPUT")):
    for c in chains:
        cmd = f"iptables -D {c} -j NFQUEUE --queue-num {queue_num}"
        run_cmd(cmd)
    live_log(f"Removed iptables NFQUEUE rules (queue {queue_num})")

def insert_block_ip(ip):
    cmd = f"iptables -I INPUT -s {ip} -j DROP"
    run_cmd(cmd)
    live_log(f"Inserted kernel-level drop for {ip}")

# --- CLI & run ---
def main():
    parser = argparse.ArgumentParser(description="Personal firewall (active NFQUEUE or passive sniff)")
    parser.add_argument("--mode", choices=("active","passive"), default="passive")
    parser.add_argument("--queue", type=int, default=1, help="NFQUEUE number (active mode)")
    parser.add_argument("--iface", type=str, default="eth0", help="Interface for passive sniff")
    parser.add_argument("--rules", type=str, default="rules.json", help="Rules JSON file")
    parser.add_argument("--setup-iptables-nfqueue", action="store_true", help="Insert iptables NFQUEUE rules before running (active mode)")
    parser.add_argument("--clear-iptables-nfqueue", action="store_true", help="Remove iptables NFQUEUE rules (useful to cleanup)")
    args = parser.parse_args()

    if not os.path.exists(args.rules):
        print("Rules file not found:", args.rules)
        sys.exit(1)

    ruleset = RuleSet.load_from_file(args.rules)
    live_log(f"Loaded rules from {args.rules}. Default action={ruleset.default_action}")

    if args.clear_iptables_nfqueue:
        clear_nfqueue(args.queue)
        print("Cleared NFQUEUE iptables rules. Exiting.")
        return

    if args.mode == "active":
        if args.setup_iptables_nfqueue:
            setup_nfqueue(args.queue)
        fw = ActiveFirewall(args.queue, ruleset)

        def signal_handler(sig, frame):
            live_log("Signal received, shutting down")
            try:
                fw.stop()
            except Exception:
                pass
            if args.setup_iptables_nfqueue:
                clear_nfqueue(args.queue)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        fw.start()

    else:
        try:
            passive_sniff(args.iface, ruleset)
        except KeyboardInterrupt:
            live_log("Passive sniff stopped by user")

if __name__ == "__main__":
    main()
