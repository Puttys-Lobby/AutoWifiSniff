#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════╗
║          AutoWiFiSniff Pro v2.0 – Network Forensics & Analysis          ║
║          Linux Only | Python 3.10+ | Fully Standalone & Offline         ║
╚══════════════════════════════════════════════════════════════════════════╝

# ─── requirements.txt ────────────────────────────────────────────────────
# scapy>=2.5.0
# pyshark>=0.6
# rich>=13.0
# pandas>=2.0
# scikit-learn>=1.3
# reportlab>=4.0
# matplotlib>=3.7
# netifaces>=0.11
# tqdm>=4.65
# colorama>=0.4.6
# Pillow>=10.0
#
# System deps (apt):
#   sudo apt install tshark aircrack-ng libpcap-dev espeak
# ─────────────────────────────────────────────────────────────────────────
"""

# ══════════════════════════════════════════════════════════════════════════
# SECTION 1: IMPORTS
# ══════════════════════════════════════════════════════════════════════════
import os, sys, time, json, shutil, socket, struct, hashlib, re, threading
import subprocess, platform, signal, textwrap, webbrowser, tempfile, copy
import datetime, warnings, random, math
from pathlib import Path
from collections import defaultdict, Counter
from typing import List, Dict, Optional, Tuple, Any

warnings.filterwarnings("ignore")

# ─── Rich ─────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.live import Live
    from rich.progress import (Progress, SpinnerColumn, BarColumn,
                               TextColumn, TimeElapsedColumn, TaskProgressColumn)
    from rich.text import Text
    from rich.align import Align
    from rich.style import Style
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.markup import escape
except ImportError:
    print("[!] rich not installed. Run: pip install rich"); sys.exit(1)

# ─── Colorama ─────────────────────────────────────────────────────────────
try:
    from colorama import init as colorama_init, Fore, Back, Style as CStyle
    colorama_init(autoreset=True)
except ImportError:
    class Fore:
        CYAN=MAGENTA=YELLOW=RED=GREEN=WHITE=RESET=""
    class CStyle:
        BRIGHT=RESET_ALL=""

# ─── Scapy ────────────────────────────────────────────────────────────────
try:
    from scapy.all import (rdpcap, wrpcap, sniff, Ether, IP, IPv6, TCP, UDP,
                           ARP, DNS, DNSQR, DNSRR, Raw, Dot11, Dot11Beacon,
                           Dot11Deauth, Dot11Disas, Dot11ProbeReq, Dot11ProbeResp,
                           Dot11Auth, Dot11AssoReq, Dot11ReassoReq, EAPOL,
                           DHCP, BOOTP, ICMP, conf as scapy_conf, PacketList)
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    SCAPY_OK = True
except Exception as e:
    SCAPY_OK = False
    print(f"[!] scapy import warning: {e}")

# ─── PyShark ──────────────────────────────────────────────────────────────
try:
    import pyshark
    PYSHARK_OK = True
except ImportError:
    PYSHARK_OK = False

# ─── ML / Data ────────────────────────────────────────────────────────────
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_OK = True
except ImportError:
    ML_OK = False

# ─── ReportLab ────────────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table as RLTable, TableStyle, Image,
                                    PageBreak, HRFlowable, KeepTogether)
    from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Line
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics import renderPDF
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    RL_OK = True
except ImportError:
    RL_OK = False

# ─── Matplotlib ───────────────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch
    MPL_OK = True
except ImportError:
    MPL_OK = False

# ─── Netifaces ────────────────────────────────────────────────────────────
try:
    import netifaces
    NETIFACES_OK = True
except ImportError:
    NETIFACES_OK = False

# ══════════════════════════════════════════════════════════════════════════
# SECTION 2: GLOBAL CONSTANTS & THEME
# ══════════════════════════════════════════════════════════════════════════
VERSION   = "2.2"
TOOL_NAME = "AutoWiFiSniff Pro"
REPORTS_DIR = Path("./reports")
REPORTS_DIR.mkdir(exist_ok=True)

# Neon palette (Rich markup colours)
C_CYAN    = "bold cyan"
C_MAGENTA = "bold magenta"
C_PURPLE  = "bold purple"
C_BLUE    = "bold blue"
C_GREEN   = "bold green"
C_RED     = "bold red"
C_YELLOW  = "bold yellow"
C_WHITE   = "bold white"
C_DIM     = "dim white"

console = Console()

# ══════════════════════════════════════════════════════════════════════════
# SECTION 3: ASCII ART LOGO & STARTUP
# ══════════════════════════════════════════════════════════════════════════
LOGO = r"""
 ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   █     █░ ██▓  █████▒██▓
▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒▓█░ █ ░█░▓██▒▓██   ▒▓██▒
▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▒█░ █ ░█ ▒██▒▒████ ░▒██▒
░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░░█░ █ ░█ ░██░░▓█▒  ░░██░
 ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░░░██▒██▓ ░██░░▒█░   ░██░
 ▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▓░▒ ▒  ░▓   ▒ ░   ░▓
  ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░   ▒ ░ ░   ▒ ░ ░      ▒ ░
  ░   ▒    ░░░ ░ ░   ░      ░ ░ ░ ▒    ░   ░   ▒ ░ ░ ░    ▒ ░
      ░  ░   ░                   ░ ░      ░     ░           ░
  ██████  ███▄    █  ██▓  █████▒███████╗
▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒ ██╔════╝
░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░ █████╗
  ▒   ██▒▓██▒  ▐▌██▒░██░░▓█▒  ░ ██╔══╝
▒██████▒▒▒██░   ▓██░░██░░▒█░    ██║
▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░▓   ▒ ░   ╚═╝
░ ░▒  ░ ░░ ░░   ░ ▒░ ▒ ░ ░
░  ░  ░     ░   ░ ░  ▒ ░ ░ ░          P R O  v2.1
      ░           ░  ░
"""

SUBTITLE = "[ Network Forensics & WiFi Security Analysis Suite ]"
TAGLINE  = "Powered by Scapy · PyShark · Rich · scikit-learn · ReportLab"


def print_logo():
    """Print the animated neon ASCII logo."""
    console.clear()
    colours = [C_CYAN, C_MAGENTA, C_PURPLE, C_BLUE, C_CYAN]
    lines = LOGO.strip("\n").split("\n")
    for i, line in enumerate(lines):
        col = colours[i % len(colours)]
        console.print(f"[{col}]{escape(line)}[/{col}]")
        time.sleep(0.01)
    console.print()
    console.print(Align.center(f"[bold cyan]{SUBTITLE}[/bold cyan]"))
    console.print(Align.center(f"[dim]{TAGLINE}[/dim]"))
    console.print()
    # Animated neon separator
    sep = "─" * 78
    for col in [C_CYAN, C_MAGENTA, C_PURPLE, C_MAGENTA, C_CYAN]:
        console.print(Align.center(f"[{col}]{sep}[/{col}]"), end="\r")
        time.sleep(0.08)
    console.print(Align.center(f"[bold cyan]{sep}[/bold cyan]"))
    console.print()


# ══════════════════════════════════════════════════════════════════════════
# SECTION 4: PERMISSION & ENVIRONMENT CHECKS
# ══════════════════════════════════════════════════════════════════════════

def check_root() -> bool:
    """Return True if running as root/sudo."""
    return os.geteuid() == 0


def require_root(feature: str):
    """Prompt user for sudo if not root."""
    if not check_root():
        console.print(f"\n[bold red][!] {feature} requires root/sudo privileges.[/bold red]")
        console.print("[yellow]    Re-run with: sudo python3 autowifisniff_pro.py[/yellow]\n")
        return False
    return True


def check_tool(name: str) -> bool:
    """Check if a system binary exists."""
    return shutil.which(name) is not None


def check_dependencies():
    """Check Python packages and system tools, warn if missing."""
    issues = []
    if not SCAPY_OK:   issues.append("scapy (pip install scapy)")
    if not PYSHARK_OK: issues.append("pyshark (pip install pyshark)")
    if not ML_OK:      issues.append("pandas / scikit-learn (pip install pandas scikit-learn)")
    if not RL_OK:      issues.append("reportlab (pip install reportlab)")
    if not MPL_OK:     issues.append("matplotlib (pip install matplotlib)")
    if not NETIFACES_OK: issues.append("netifaces (pip install netifaces)")
    sys_tools = ["tshark", "airmon-ng"]
    for t in sys_tools:
        if not check_tool(t):
            issues.append(f"{t} (sudo apt install {'tshark' if 'tshark' in t else 'aircrack-ng'})")
    if issues:
        console.print(Panel(
            "\n".join(f"[yellow]  ⚠  {i}[/yellow]" for i in issues),
            title="[bold red]Missing Dependencies[/bold red]",
            border_style="red"
        ))
        console.print("[dim]The tool will continue with reduced functionality.[/dim]\n")
        time.sleep(1.5)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 5: MAIN MENU
# ══════════════════════════════════════════════════════════════════════════

def animated_spinner(text: str, duration: float = 1.2):
    """Show a quick spinner for UI effect."""
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        console.print(f"\r[cyan]{frames[i % len(frames)]}[/cyan] [white]{text}[/white]",
                      end="", highlight=False)
        time.sleep(0.1)
        i += 1
    console.print(f"\r[green]✔[/green] [white]{text}[/white]")


def show_main_menu() -> int:
    """Display the animated main menu and return user choice."""
    console.print(Panel(
        Align.center(
            Text.assemble(
                ("  ┌──────────────────────────────────────────────┐\n", "bold cyan"),
                ("  │            ", "bold cyan"),
                ("✦  MAIN  MENU  ✦", "bold magenta"),
                ("                   │\n", "bold cyan"),
                ("  ├──────────────────────────────────────────────┤\n", "bold cyan"),
                ("  │  ", "bold cyan"),
                (" 1 ", "bold black on cyan"),
                ("  Insert PCAP File  ", "bold white"),
                ("(Analyse Existing)      │\n", "dim white"),
                ("  │  ", "bold cyan"),
                (" 2 ", "bold black on magenta"),
                ("  Capture Packets Live  ", "bold white"),
                ("(Wireshark-like)   │\n", "dim white"),
                ("  │  ", "bold cyan"),
                (" 3 ", "bold black on blue"),
                ("  Help                  ", "bold white"),
                ("(Usage & Shortcuts)    │\n", "dim white"),
                ("  │  ", "bold cyan"),
                (" 4 ", "bold black on red"),
                ("  Exit                                        │\n", "bold white"),
                ("  └──────────────────────────────────────────────┘\n", "bold cyan"),
            )
        ),
        border_style="cyan",
        padding=(1, 4),
    ))

    while True:
        choice = Prompt.ask(
            "[bold cyan]  ⮞  Select option[/bold cyan]",
            choices=["1", "2", "3", "4"],
            show_choices=True
        )
        return int(choice)


def show_help():
    """Display the Help panel (option 3)."""
    help_text = Text.assemble(
        ("\n  AutoWiFiSniff Pro v2.1 — Help & Usage Guide\n", "bold cyan"),
        ("  " + "─" * 54 + "\n", "dim cyan"),
        ("\n  ► USAGE\n", "bold magenta"),
        ("    sudo python3 autowifisniff_pro.py\n", "bold white"),
        ("    pip install -r requirements.txt\n", "dim white"),
        ("    sudo apt install tshark aircrack-ng espeak\n", "dim white"),
        ("\n  ► MENU OPTIONS\n", "bold magenta"),
        ("    [1]  ", "bold cyan"), ("Insert PCAP  ", "bold white"),
        ("─ Load & analyse an existing .pcap or .pcapng file\n", "dim white"),
        ("    [2]  ", "bold cyan"), ("Live Capture ", "bold white"),
        ("─ Wireshark-style real-time packet capture\n", "dim white"),
        ("    [3]  ", "bold cyan"), ("Help         ", "bold white"),
        ("─ Show this help panel\n", "dim white"),
        ("    [4]  ", "bold cyan"), ("Exit         ", "bold white"),
        ("─ Quit the tool\n", "dim white"),
        ("\n  ► KEYBOARD SHORTCUTS (during live capture)\n", "bold magenta"),
        ("    Ctrl+C  ", "bold yellow"), ("— Stop capture and proceed to analysis\n", "dim white"),
        ("\n  ► ENABLING MONITOR MODE\n", "bold magenta"),
        ("    1. Run:  ", "bold white"), ("sudo airmon-ng check kill\n", "bold cyan"),
        ("    2. Run:  ", "bold white"), ("sudo airmon-ng start wlan0\n", "bold cyan"),
        ("    3. New iface will be e.g. wlan0mon — select it in menu\n", "dim white"),
        ("    4. AutoWiFiSniff Pro can do this automatically — answer Y\n", "dim white"),
        ("\n  ► REPORTS FOLDER\n", "bold magenta"),
        ("    ./reports/<name>/         ", "bold white"),
        ("─ Created automatically per scan\n", "dim white"),
        ("    <name>.pcap               ", "bold white"), ("─ Raw packet capture\n", "dim white"),
        ("    <name>.json               ", "bold white"), ("─ Full structured data + SIEM/CEF\n", "dim white"),
        ("    <name>.txt                ", "bold white"), ("─ Human-readable summary\n", "dim white"),
        ("    <name>.pdf                ", "bold white"), ("─ Full PDF with charts & evidence\n", "dim white"),
        ("    report_<name>.html        ", "bold white"), ("─ Holographic HTML dashboard\n", "dim white"),
        ("\n  ► VIEWING THE HTML DASHBOARD\n", "bold magenta"),
        ("    The HTML path is printed in the terminal after each scan.\n", "dim white"),
        ("    Open it manually in any browser, e.g.:\n", "dim white"),
        ("    firefox ./reports/<name>/report_<name>.html\n", "bold cyan"),
        ("\n  ► DETECTION ENGINE\n", "bold magenta"),
        ("    37+ rules covering: ARP Spoofing, Deauth Flood, Evil Twin,\n", "dim white"),
        ("    KRACK, DHCP Spoofing, SSL Strip, SYN Flood, DNS Tunnel,\n", "dim white"),
        ("    EternalBlue, Heartbleed, SQLi, XSS, C2 Beaconing, and more.\n", "dim white"),
        ("    ML anomaly detection via Isolation Forest (scikit-learn).\n", "dim white"),
        ("    Voice alerts via espeak for critical findings.\n", "dim white"),
        ("\n")
    )
    console.print(Panel(
        help_text,
        title="[bold cyan]❓  AutoWiFiSniff Pro v2.1 — Help[/bold cyan]",
        border_style="cyan",
        padding=(0, 2),
    ))


# ══════════════════════════════════════════════════════════════════════════
# SECTION 6: UTILITY HELPERS
# ══════════════════════════════════════════════════════════════════════════

def ts_to_str(ts) -> str:
    """Convert a float timestamp to readable string."""
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S.%f")[:-3]
    except Exception:
        return str(ts)


def mac_str(mac) -> str:
    try:
        return str(mac).upper()
    except Exception:
        return "??"


def safe_ip(pkt, layer="IP") -> Tuple[str, str]:
    """Return (src, dst) IPs safely."""
    try:
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    except Exception:
        pass
    return ("?.?.?.?", "?.?.?.?")


def hex_snippet(pkt, n: int = 32) -> str:
    """Return first n bytes of packet payload as hex string."""
    try:
        raw = bytes(pkt)
        return raw[:n].hex(" ")
    except Exception:
        return ""


def voice_alert(message: str):
    """Non-blocking voice alert via espeak (optional)."""
    if check_tool("espeak"):
        try:
            subprocess.Popen(
                ["espeak", "-s", "140", f"Alert! {message}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            pass


def create_report_dir(name: str) -> Path:
    """Create ./reports/<name>/ and return path."""
    d = REPORTS_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def risk_colour(score: int) -> str:
    """Return Rich colour tag based on risk score."""
    if score >= 80: return "bold red"
    if score >= 60: return "bold yellow"
    if score >= 40: return "bold magenta"
    if score >= 20: return "cyan"
    return "dim green"


def risk_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "INFO"


# ══════════════════════════════════════════════════════════════════════════
# SECTION 7: DETECTION ENGINE – 30+ ATTACK RULES
# ══════════════════════════════════════════════════════════════════════════

class Detection:
    """Represents one detected attack/anomaly."""
    def __init__(self, name: str, possibility: int, target: str,
                 evidence: str, why: str, fix: str, risk: int,
                 packet_nos: list = None, severity: str = "MEDIUM",
                 attack_type: str = "", pathway: str = "",
                 possible_attacks: list = None):
        self.name        = name
        self.possibility = possibility
        self.target      = target
        self.evidence    = evidence
        self.why         = why
        self.fix         = fix
        self.risk        = risk
        self.packet_nos  = packet_nos or []
        self.severity    = severity
        self.attack_type = attack_type
        self.pathway     = pathway
        self.possible_attacks = possible_attacks or []
        self.timestamp   = datetime.datetime.now().isoformat()

    def to_dict(self) -> dict:
        return self.__dict__


class RuleEngine:
    """
    Main rule engine: runs 30+ detection methods on a packet list.
    Plugin system: add new rules as methods named detect_<rulename>.
    """

    def __init__(self, packets: list, progress_cb=None):
        self.packets    = packets
        self.detections: List[Detection] = []
        self.progress_cb = progress_cb   # callable(step_name)
        self.total_pkts  = len(packets)

    def _cb(self, name: str):
        if self.progress_cb:
            self.progress_cb(name)

    # ── RULE 01: ARP Spoofing ────────────────────────────────────────────
    def detect_arp_spoofing(self):
        self._cb("ARP Spoofing")
        if not SCAPY_OK: return
        ip_mac: Dict[str, set] = defaultdict(set)
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
                ip  = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                ip_mac[ip].add(mac)
                if len(ip_mac[ip]) > 1:
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            spoofed = {ip: macs for ip, macs in ip_mac.items() if len(macs) > 1}
            detail = "; ".join(f"{ip}→{','.join(macs)}" for ip, macs in spoofed.items())
            self.detections.append(Detection(
                name="ARP Spoofing / Poisoning",
                possibility=min(95, 60 + len(evidence_pkts) * 5),
                target="LAN – multiple hosts",
                evidence=f"Pkts {evidence_pkts[:5]}: Multiple MACs per IP: {detail}",
                why="An attacker replies with spoofed ARP packets to redirect traffic through their machine (MitM).",
                fix="Enable dynamic ARP inspection (DAI) on managed switches; use static ARP entries for critical hosts.",
                risk=85,
                packet_nos=evidence_pkts[:10],
                severity="CRITICAL"
            ))
            voice_alert("ARP spoofing detected")

    # ── RULE 02: Deauth / Disassoc Flood ─────────────────────────────────
    def detect_deauth_flood(self):
        self._cb("Deauth/Disassoc Flood")
        if not SCAPY_OK: return
        deauth_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
                deauth_pkts.append(i + 1)
        if len(deauth_pkts) > 10:
            self.detections.append(Detection(
                name="Deauthentication / Disassociation Flood",
                possibility=min(98, 70 + len(deauth_pkts)),
                target="WiFi clients (all)",
                evidence=f"{len(deauth_pkts)} deauth/disassoc frames – pkt nos: {deauth_pkts[:8]}",
                why="802.11 deauth frames are unauthenticated; mass sending forces clients offline (DoS).",
                fix="Enable 802.11w (PMF) to authenticate management frames; use an enterprise IDS/IPS.",
                risk=80,
                packet_nos=deauth_pkts[:10],
                severity="HIGH"
            ))
            voice_alert("Deauth flood detected")

    # ── RULE 03: Evil Twin / Rogue AP ─────────────────────────────────────
    def detect_evil_twin(self):
        self._cb("Evil Twin / Rogue AP")
        if not SCAPY_OK: return
        ssid_bssid: Dict[str, set] = defaultdict(set)
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Dot11Beacon):
                try:
                    ssid  = pkt[Dot11Beacon].network_stats().get("ssid", "")
                    bssid = pkt.addr3
                    if ssid:
                        ssid_bssid[ssid].add(bssid)
                except Exception:
                    pass
        dupes = {ssid: bssids for ssid, bssids in ssid_bssid.items() if len(bssids) > 1}
        if dupes:
            detail = "; ".join(f'"{s}"→{list(b)[:3]}' for s, b in dupes.items())
            self.detections.append(Detection(
                name="Evil Twin / Rogue Access Point",
                possibility=88,
                target=f"SSID(s): {', '.join(dupes.keys())}",
                evidence=f"Same SSID, multiple BSSIDs: {detail}",
                why="Attacker broadcasts a clone of a legitimate AP to lure victims into connecting to a malicious network.",
                fix="Use WIDS/WIPS with rogue AP detection; educate users to verify certificates.",
                risk=90,
                severity="CRITICAL"
            ))

    # ── RULE 04: KRACK (Nonce Reuse in EAPOL) ────────────────────────────
    def detect_krack(self):
        self._cb("KRACK Attack")
        if not SCAPY_OK: return
        nonces = defaultdict(list)
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(EAPOL):
                try:
                    raw = bytes(pkt[EAPOL])
                    if len(raw) >= 17:
                        nonce = raw[17:49].hex()
                        key_info = struct.unpack(">H", raw[1:3])[0]
                        if key_info & 0x0008:  # install bit
                            nonces[nonce].append(i + 1)
                except Exception:
                    pass
        reused = {n: pkts for n, pkts in nonces.items() if len(pkts) > 1}
        if reused:
            self.detections.append(Detection(
                name="KRACK – Key Reinstallation Attack (Nonce Reuse)",
                possibility=82,
                target="WPA2 handshake victims",
                evidence=f"Nonce(s) reused across EAPOL frames: {list(reused.keys())[:2]}",
                why="KRACK forces nonce reuse to break WPA2 encryption and decrypt/replay packets.",
                fix="Patch all WiFi clients and APs; enforce WPA3; use HTTPS/VPN regardless.",
                risk=88,
                severity="CRITICAL"
            ))

    # ── RULE 05: DHCP Spoofing ────────────────────────────────────────────
    def detect_dhcp_spoofing(self):
        self._cb("DHCP Spoofing")
        if not SCAPY_OK: return
        servers = defaultdict(set)
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(DHCP):
                opts = dict(pkt[DHCP].options) if pkt[DHCP].options else {}
                if opts.get("message-type") in [2, 5]:  # OFFER or ACK
                    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "?"
                    servers["dhcp"].add(src_mac)
                    if len(servers["dhcp"]) > 1:
                        evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="DHCP Spoofing / Rogue DHCP Server",
                possibility=85,
                target="All DHCP clients on LAN",
                evidence=f"Multiple DHCP servers: {list(servers['dhcp'])} – pkts: {evidence_pkts[:5]}",
                why="A rogue DHCP server assigns malicious gateway/DNS to hijack all traffic.",
                fix="Enable DHCP snooping on managed switches; use 802.1X port security.",
                risk=80,
                packet_nos=evidence_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 06: MAC Flooding ─────────────────────────────────────────────
    def detect_mac_flooding(self):
        self._cb("MAC Flooding")
        if not SCAPY_OK: return
        mac_set = set()
        for pkt in self.packets:
            if pkt.haslayer(Ether):
                mac_set.add(pkt[Ether].src)
        if len(mac_set) > 500:
            self.detections.append(Detection(
                name="MAC Flooding / CAM Table Overflow",
                possibility=78,
                target="Network switches",
                evidence=f"{len(mac_set)} unique source MACs detected in capture",
                why="Flooding the CAM table forces switch to broadcast all frames, enabling passive sniffing.",
                fix="Enable port security (limit MACs per port); use dynamic ARP inspection.",
                risk=72,
                severity="HIGH"
            ))

    # ── RULE 07: SSL Stripping / MitM ────────────────────────────────────
    def detect_ssl_stripping(self):
        self._cb("SSL Stripping / MitM")
        if not SCAPY_OK: return
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                if ("http://" in payload.lower() and
                        re.search(r"(login|password|passwd|session|token)", payload, re.I)):
                    evidence_pkts.append(i + 1)
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                if b"HTTP/1." in raw and b"Location: http://" in raw:
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="SSL Stripping / HTTPS Downgrade Attack",
                possibility=75,
                target="HTTP credential sessions",
                evidence=f"Cleartext credentials/redirects on port 80 – pkts: {evidence_pkts[:5]}",
                why="Attacker intercepts and strips HTTPS→HTTP, exposing credentials in plaintext.",
                fix="Enforce HSTS headers; use HTTPS-only policies; deploy certificate pinning.",
                risk=78,
                packet_nos=evidence_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 08: SYN Flood ────────────────────────────────────────────────
    def detect_syn_flood(self):
        self._cb("SYN Flood / DoS")
        if not SCAPY_OK: return
        syn_counts: Dict[str, int] = Counter()
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
                src, _ = safe_ip(pkt)
                syn_counts[src] += 1
                if syn_counts[src] == 100:
                    evidence_pkts.append(i + 1)
        heavy = {ip: c for ip, c in syn_counts.items() if c > 100}
        if heavy:
            self.detections.append(Detection(
                name="SYN Flood / TCP DoS Attack",
                possibility=90,
                target=f"Servers: {list(heavy.keys())[:3]}",
                evidence=f"Attackers with >100 half-open SYNs: {heavy}",
                why="Mass SYN packets exhaust server connection tables, causing denial of service.",
                fix="Enable SYN cookies; deploy rate-limiting; use firewall thresholds.",
                risk=85,
                severity="CRITICAL"
            ))

    # ── RULE 09: WEP / WPA1 Usage ─────────────────────────────────────────
    def detect_weak_encryption(self):
        self._cb("WEP/WPA1 Detection")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Dot11Beacon):
                try:
                    stats = pkt[Dot11Beacon].network_stats()
                    crypto = stats.get("crypto", set())
                    if "WEP" in crypto or "WPA" in crypto:
                        self.detections.append(Detection(
                            name="Weak Encryption (WEP/WPA1) Detected",
                            possibility=99,
                            target=f"SSID: {stats.get('ssid','?')}",
                            evidence=f"Pkt {i+1}: Crypto={crypto}",
                            why="WEP is trivially crackable in minutes; WPA1-TKIP is also broken. Both expose traffic.",
                            fix="Upgrade to WPA3 or at minimum WPA2-AES; disable legacy cipher suites.",
                            risk=75,
                            packet_nos=[i + 1],
                            severity="HIGH"
                        ))
                        return
                except Exception:
                    pass

    # ── RULE 10: WPS Enabled ─────────────────────────────────────────────
    def detect_wps(self):
        self._cb("WPS Enabled")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Dot11Beacon):
                try:
                    raw = bytes(pkt)
                    # WPS information element: tag 221 (0xDD), OUI 00:50:f2:04
                    if b"\xdd\x09\x00\x50\xf2\x04" in raw or b"\xdd\x1d\x00\x50\xf2\x04" in raw:
                        stats = pkt[Dot11Beacon].network_stats()
                        self.detections.append(Detection(
                            name="WPS Enabled (Pixie Dust / Brute-force Risk)",
                            possibility=95,
                            target=f"SSID: {stats.get('ssid', '?')}",
                            evidence=f"Pkt {i+1}: WPS IE detected in beacon frame",
                            why="WPS PINs are 8 digits; Pixie Dust attack cracks many routers in seconds.",
                            fix="Disable WPS on all access points immediately.",
                            risk=70,
                            packet_nos=[i + 1],
                            severity="HIGH"
                        ))
                        return
                except Exception:
                    pass

    # ── RULE 11: No PMF (802.11w) ─────────────────────────────────────────
    def detect_no_pmf(self):
        self._cb("PMF/802.11w Check")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Dot11Beacon):
                try:
                    raw = bytes(pkt)
                    # RSN IE without MFPC/MFPR bits set
                    rsn_offset = raw.find(b"\x30")
                    if rsn_offset != -1 and len(raw) > rsn_offset + 8:
                        rsn_cap = raw[rsn_offset + 4:rsn_offset + 6]
                        if rsn_cap and not (rsn_cap[1] & 0x80):  # MFPC not set
                            stats = pkt[Dot11Beacon].network_stats()
                            self.detections.append(Detection(
                                name="No PMF / 802.11w Management Frame Protection Disabled",
                                possibility=80,
                                target=f"SSID: {stats.get('ssid','?')}",
                                evidence=f"Pkt {i+1}: RSN capabilities – MFPC/MFPR bits not set",
                                why="Without PMF, deauth/disassoc frames are unauthenticated; DoS trivial.",
                                fix="Enable 802.11w PMF (required for WPA3); set PMF to mandatory if possible.",
                                risk=55,
                                packet_nos=[i+1],
                                severity="MEDIUM"
                            ))
                            return
                except Exception:
                    pass

    # ── RULE 12: Broadcast / Multicast Flood ─────────────────────────────
    def detect_broadcast_flood(self):
        self._cb("Broadcast/Multicast Flood")
        if not SCAPY_OK: return
        bc_count = sum(1 for p in self.packets
                       if p.haslayer(Ether) and p[Ether].dst == "ff:ff:ff:ff:ff:ff")
        if bc_count > 200:
            self.detections.append(Detection(
                name="Broadcast / Multicast Storm",
                possibility=80,
                target="All LAN hosts",
                evidence=f"{bc_count} broadcast packets in capture",
                why="Broadcast storms consume all available bandwidth and CPU, causing network outage.",
                fix="Enable storm control on switches; segment network with VLANs.",
                risk=60,
                severity="MEDIUM"
            ))

    # ── RULE 13: Old TLS (1.0 / 1.1) ────────────────────────────────────
    def detect_old_tls(self):
        self._cb("Old TLS Version")
        if not SCAPY_OK: return
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                # TLS ClientHello record: 0x16 0x03 0x01 (TLS 1.0) or 0x03 0x02 (TLS 1.1)
                if (raw[:2] == b"\x16\x03" and raw[2] in (0x01, 0x02)):
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="Deprecated TLS 1.0 / TLS 1.1 Usage",
                possibility=97,
                target="TLS endpoints in capture",
                evidence=f"Pkts {evidence_pkts[:5]}: TLS version bytes 0x0301/0x0302 observed",
                why="TLS 1.0/1.1 are broken (POODLE, BEAST, ROBOT) – attackers can decrypt sessions.",
                fix="Enforce TLS 1.2 minimum; migrate to TLS 1.3 for all endpoints.",
                risk=65,
                packet_nos=evidence_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 14: DNS Tunnelling ───────────────────────────────────────────
    def detect_dns_tunnelling(self):
        self._cb("DNS Tunnelling")
        if not SCAPY_OK: return
        long_dns = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                if len(qname) > 60 or qname.count(".") > 6:
                    long_dns.append((i + 1, qname[:80]))
        if len(long_dns) > 5:
            self.detections.append(Detection(
                name="DNS Tunnelling / C2 over DNS",
                possibility=78,
                target="Internal DNS clients",
                evidence=f"{len(long_dns)} abnormally long DNS queries. Example: {long_dns[0][1]}",
                why="Attackers encode data in DNS queries to bypass firewalls and exfiltrate data covertly.",
                fix="Deploy DNS filtering (RPZ); monitor query length anomalies; use DNS-over-HTTPS internally.",
                risk=70,
                severity="HIGH"
            ))

    # ── RULE 15: Beacon Flooding ─────────────────────────────────────────
    def detect_beacon_flood(self):
        self._cb("Beacon Flooding")
        if not SCAPY_OK: return
        ssids = set()
        beacon_count = 0
        for pkt in self.packets:
            if pkt.haslayer(Dot11Beacon):
                beacon_count += 1
                try:
                    ssids.add(pkt[Dot11Beacon].network_stats().get("ssid", ""))
                except Exception:
                    pass
        if beacon_count > 500 and len(ssids) > 50:
            self.detections.append(Detection(
                name="Beacon Flooding (SSID Flood)",
                possibility=92,
                target="WiFi spectrum",
                evidence=f"{beacon_count} beacon frames, {len(ssids)} unique SSIDs",
                why="Tools like mdk4 flood fake SSIDs to overwhelm WiFi scanners and clients.",
                fix="Use WIDS to detect beacon floods; implement spectrum monitoring.",
                risk=55,
                severity="MEDIUM"
            ))

    # ── RULE 16: Probe Request Anomalies ─────────────────────────────────
    def detect_probe_anomalies(self):
        self._cb("Probe Anomalies")
        if not SCAPY_OK: return
        probe_srcs = Counter()
        for pkt in self.packets:
            if pkt.haslayer(Dot11ProbeReq):
                probe_srcs[pkt.addr2] += 1
        aggressive = {m: c for m, c in probe_srcs.items() if c > 50}
        if aggressive:
            self.detections.append(Detection(
                name="Aggressive Probe Request Scanning",
                possibility=70,
                target="WiFi environment",
                evidence=f"High-rate probe senders: {aggressive}",
                why="Mass probe requests reveal preferred network history and can be used for reconnaissance.",
                fix="Enable randomized MAC on clients; ignore unknown probes in WIDS.",
                risk=35,
                severity="LOW"
            ))

    # ── RULE 17: SQL Injection in HTTP ───────────────────────────────────
    def detect_sqli(self):
        self._cb("SQL Injection")
        if not SCAPY_OK: return
        sqli_patterns = re.compile(
            r"(union.*select|select.*from|insert.*into|drop.*table|'.*or.*'.*=.*'|"
            r"--.*$|;.*--|\bexec\b|\bxp_|\bcast\(|benchmark\(|sleep\()",
            re.IGNORECASE
        )
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                if sqli_patterns.search(payload):
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="SQL Injection Attempt in HTTP Traffic",
                possibility=85,
                target="Web servers in capture",
                evidence=f"SQLi-like patterns in HTTP payloads – pkts: {evidence_pkts[:5]}",
                why="SQL injection can expose/destroy databases and lead to full server compromise.",
                fix="Use parameterised queries; deploy WAF; sanitise all user inputs.",
                risk=82,
                packet_nos=evidence_pkts[:5],
                severity="CRITICAL"
            ))

    # ── RULE 18: C2 Beaconing ────────────────────────────────────────────
    def detect_c2_beaconing(self):
        self._cb("C2 Beaconing")
        if not SCAPY_OK: return
        interval_map: Dict[tuple, list] = defaultdict(list)
        for pkt in self.packets:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].dport)
                interval_map[key].append(float(pkt.time))
        beaconing = []
        for key, times in interval_map.items():
            if len(times) < 6: continue
            times.sort()
            intervals = [times[j+1] - times[j] for j in range(len(times)-1)]
            mean_i = sum(intervals) / len(intervals)
            variance = sum((x - mean_i)**2 for x in intervals) / len(intervals)
            jitter = math.sqrt(variance)
            if 10 <= mean_i <= 300 and jitter < mean_i * 0.15:
                beaconing.append((*key, round(mean_i, 1), round(jitter, 2)))
        if beaconing:
            b = beaconing[0]
            self.detections.append(Detection(
                name="C2 Beaconing Pattern Detected",
                possibility=80,
                target=f"{b[0]} → {b[1]}:{b[2]}",
                evidence=f"Regular interval={b[3]}s ± {b[4]}s jitter. {len(beaconing)} flows match.",
                why="Malware beacons home at regular intervals for command-and-control; low jitter is a IoC.",
                fix="Block unknown outbound connections; deploy NDR/EDR; inspect TLS certificates.",
                risk=88,
                severity="CRITICAL"
            ))

    # ── RULE 19: Data Exfiltration ────────────────────────────────────────
    def detect_exfiltration(self):
        self._cb("Data Exfiltration")
        if not SCAPY_OK: return
        volume: Dict[str, int] = defaultdict(int)
        for pkt in self.packets:
            if pkt.haslayer(IP):
                volume[pkt[IP].src] += len(pkt)
        big_senders = {ip: b for ip, b in volume.items() if b > 10_000_000}
        if big_senders:
            detail = "; ".join(f"{ip}: {b//1024}kB" for ip, b in big_senders.items())
            self.detections.append(Detection(
                name="Potential Data Exfiltration (High Outbound Volume)",
                possibility=65,
                target="Internal hosts sending large volumes",
                evidence=f"High senders: {detail}",
                why="Unusually high outbound data may indicate exfiltration of sensitive data.",
                fix="Implement DLP; monitor unusual outbound traffic; restrict upload destinations.",
                risk=75,
                severity="HIGH"
            ))

    # ── RULE 20: ICMP Flood / Smurf ──────────────────────────────────────
    def detect_icmp_flood(self):
        self._cb("ICMP Flood")
        if not SCAPY_OK: return
        icmp_count = Counter()
        for pkt in self.packets:
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                icmp_count[pkt[IP].src] += 1
        heavy = {ip: c for ip, c in icmp_count.items() if c > 200}
        if heavy:
            self.detections.append(Detection(
                name="ICMP Flood / Smurf DoS",
                possibility=88,
                target=f"ICMP targets: {list(heavy.keys())[:3]}",
                evidence=f"ICMP volume by source: {heavy}",
                why="ICMP floods saturate bandwidth and CPU of target hosts (Smurf attack uses broadcast).",
                fix="Rate-limit ICMP at firewall; block broadcast ICMP; deploy anti-spoofing filters.",
                risk=70,
                severity="HIGH"
            ))

    # ── RULE 21: HTTP Basic Auth in Cleartext ────────────────────────────
    def detect_cleartext_auth(self):
        self._cb("Cleartext Credentials")
        import base64
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                if re.search(r"Authorization: Basic\s+([A-Za-z0-9+/=]+)", raw):
                    match = re.search(r"Authorization: Basic\s+([A-Za-z0-9+/=]+)", raw)
                    try:
                        decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="ignore")
                        evidence_pkts.append((i+1, decoded[:40]))
                    except Exception:
                        evidence_pkts.append((i+1, match.group(1)[:40]))
        if evidence_pkts:
            self.detections.append(Detection(
                name="HTTP Basic Authentication in Cleartext",
                possibility=99,
                target="HTTP servers accepting Basic Auth",
                evidence=f"Credentials visible in packets: {evidence_pkts[:3]}",
                why="Credentials transmitted in Base64 over HTTP are trivially intercepted.",
                fix="Use HTTPS; replace Basic Auth with OAuth2/token-based auth.",
                risk=90,
                packet_nos=[p[0] for p in evidence_pkts[:5]],
                severity="CRITICAL"
            ))

    # ── RULE 22: Port Scanning ────────────────────────────────────────────
    def detect_port_scan(self):
        self._cb("Port Scanning")
        if not SCAPY_OK: return
        ports_by_src: Dict[str, set] = defaultdict(set)
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].flags & 0x02:  # SYN
                    ports_by_src[pkt[IP].src].add(pkt[TCP].dport)
        scanners = {ip: ports for ip, ports in ports_by_src.items() if len(ports) > 30}
        if scanners:
            self.detections.append(Detection(
                name="Port Scanning / Reconnaissance",
                possibility=92,
                target=f"Scanned from: {list(scanners.keys())[:2]}",
                evidence=f"IPs scanning >30 ports: {{{k}: {len(v)} ports for k,v in list(scanners.items())[:3]}}",
                why="Port scans enumerate open services; first step in attack kill-chain.",
                fix="Deploy IDS/IPS; block scanner IPs; reduce exposed services.",
                risk=60,
                severity="MEDIUM"
            ))

    # ── RULE 23: FTP / Telnet Cleartext ──────────────────────────────────
    def detect_cleartext_protocols(self):
        self._cb("Cleartext Protocols (FTP/Telnet)")
        if not SCAPY_OK: return
        found = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport in (21, 23):  # FTP, Telnet
                    found.append((i+1, "FTP" if dport == 21 else "Telnet"))
                if pkt.haslayer(Raw):
                    raw = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                    if re.search(r"(USER |PASS |Password:)", raw):
                        found.append((i+1, "Cleartext creds"))
        if found:
            self.detections.append(Detection(
                name="Cleartext Protocols Detected (FTP/Telnet)",
                possibility=99,
                target="Cleartext protocol servers",
                evidence=f"Usage: {found[:5]}",
                why="FTP and Telnet transmit credentials in plaintext; trivially sniffed.",
                fix="Replace FTP with SFTP/FTPS; replace Telnet with SSH.",
                risk=75,
                packet_nos=[f[0] for f in found[:5]],
                severity="HIGH"
            ))

    # ── RULE 24: LLMNR / NBT-NS Poisoning Opportunity ───────────────────
    def detect_llmnr_nbtns(self):
        self._cb("LLMNR/NBT-NS Detection")
        if not SCAPY_OK: return
        llmnr_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(UDP):
                if pkt[UDP].dport in (5355, 137):  # LLMNR, NBT-NS
                    llmnr_pkts.append(i + 1)
        if llmnr_pkts:
            self.detections.append(Detection(
                name="LLMNR / NBT-NS Broadcast Queries (Responder Opportunity)",
                possibility=85,
                target="Windows hosts using LLMNR",
                evidence=f"{len(llmnr_pkts)} LLMNR/NBT-NS queries – pkts {llmnr_pkts[:5]}",
                why="Responder can answer these queries and steal NTLMv2 hashes for offline cracking.",
                fix="Disable LLMNR and NBT-NS via GPO; deploy DNS properly.",
                risk=72,
                packet_nos=llmnr_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 25: IPv6 Rogue RA ────────────────────────────────────────────
    def detect_rogue_ra(self):
        self._cb("Rogue IPv6 RA")
        if not SCAPY_OK: return
        try:
            from scapy.layers.inet6 import ICMPv6ND_RA
            ra_sources = set()
            evidence_pkts = []
            for i, pkt in enumerate(self.packets):
                if pkt.haslayer(ICMPv6ND_RA):
                    ra_sources.add(pkt[IPv6].src if pkt.haslayer(IPv6) else "?")
                    evidence_pkts.append(i + 1)
            if len(ra_sources) > 1:
                self.detections.append(Detection(
                    name="Rogue IPv6 Router Advertisement",
                    possibility=80,
                    target="IPv6 hosts",
                    evidence=f"Multiple RA sources: {ra_sources} – pkts: {evidence_pkts[:5]}",
                    why="Rogue RAs redirect IPv6 traffic through attacker (MitM) or cause DoS.",
                    fix="Deploy RA Guard on switches; use SEND (Secure Neighbor Discovery).",
                    risk=78,
                    severity="HIGH"
                ))
        except ImportError:
            pass

    # ── RULE 26: Heartbleed (TLS Heartbeat Anomaly) ──────────────────────
    def detect_heartbleed(self):
        self._cb("Heartbleed Check")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw) and pkt.haslayer(TCP):
                raw = bytes(pkt[Raw])
                # TLS Heartbeat record type: 0x18, version 0x0301-0x0303
                if len(raw) >= 5 and raw[0] == 0x18 and raw[1] == 0x03:
                    length = struct.unpack(">H", raw[3:5])[0]
                    if length > 16000:
                        self.detections.append(Detection(
                            name="Heartbleed (CVE-2014-0160) Exploit Attempt",
                            possibility=90,
                            target=f"TLS server at pkt {i+1}",
                            evidence=f"Pkt {i+1}: TLS heartbeat with inflated length={length}",
                            why="Heartbleed leaks server memory including private keys and credentials.",
                            fix="Patch OpenSSL to ≥1.0.1g; revoke and reissue all certificates.",
                            risk=95,
                            packet_nos=[i+1],
                            severity="CRITICAL"
                        ))
                        break

    # ── RULE 27: DNS Rebinding ────────────────────────────────────────────
    def detect_dns_rebinding(self):
        self._cb("DNS Rebinding")
        if not SCAPY_OK: return
        low_ttl = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(DNS) and pkt[DNS].qr == 1 and pkt.haslayer(DNSRR):
                ans = pkt[DNSRR]
                if ans.ttl < 10 and ans.type == 1:  # A record with very low TTL
                    low_ttl.append((i+1, ans.rrname, ans.ttl))
        if len(low_ttl) > 3:
            self.detections.append(Detection(
                name="DNS Rebinding Attack (Low TTL)",
                possibility=70,
                target="DNS resolver clients",
                evidence=f"Very short TTL A records: {low_ttl[:3]}",
                why="DNS rebinding allows attackers to bypass same-origin policy and access internal services.",
                fix="Deploy DNS rebinding protection on resolver; validate Host headers on internal services.",
                risk=68,
                severity="MEDIUM"
            ))

    # ── RULE 28: SSTP / HTTP CONNECT Tunnelling ──────────────────────────
    def detect_http_tunnel(self):
        self._cb("HTTP CONNECT Tunnelling")
        if not SCAPY_OK: return
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                if raw.startswith("CONNECT ") and "HTTP/" in raw:
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="HTTP CONNECT Tunnelling / Proxy Abuse",
                possibility=80,
                target="HTTP proxy endpoints",
                evidence=f"CONNECT method in pkts: {evidence_pkts[:5]}",
                why="HTTP CONNECT can be abused to tunnel arbitrary protocols through firewalls.",
                fix="Restrict CONNECT method to authorized destinations; monitor proxy usage.",
                risk=55,
                packet_nos=evidence_pkts[:5],
                severity="MEDIUM"
            ))

    # ── RULE 29: VLAN Hopping ─────────────────────────────────────────────
    def detect_vlan_hopping(self):
        self._cb("VLAN Hopping (802.1Q)")
        if not SCAPY_OK: return
        try:
            from scapy.layers.l2 import Dot1Q
            double_tagged = []
            for i, pkt in enumerate(self.packets):
                if pkt.haslayer(Dot1Q):
                    inner = pkt[Dot1Q].payload
                    if inner and inner.haslayer(Dot1Q):
                        double_tagged.append(i + 1)
            if double_tagged:
                self.detections.append(Detection(
                    name="VLAN Hopping (Double-Tagged 802.1Q Frames)",
                    possibility=88,
                    target="VLAN-segmented network",
                    evidence=f"Double-tagged frames: pkts {double_tagged[:5]}",
                    why="Double-tagging bypasses VLAN isolation to reach otherwise inaccessible segments.",
                    fix="Set native VLAN to unused ID; enable VLAN pruning; use PVLAN.",
                    risk=78,
                    packet_nos=double_tagged[:5],
                    severity="HIGH"
                ))
        except ImportError:
            pass

    # ── RULE 30: SNMP Public Community String ────────────────────────────
    def detect_snmp_public(self):
        self._cb("SNMP Community String")
        if not SCAPY_OK: return
        snmp_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(UDP) and pkt[UDP].dport == 161 and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                if b"public" in raw or b"private" in raw:
                    snmp_pkts.append(i + 1)
        if snmp_pkts:
            self.detections.append(Detection(
                name="SNMP Default Community String (public/private)",
                possibility=95,
                target="SNMP-managed devices",
                evidence=f"Default community strings in SNMP – pkts: {snmp_pkts[:5]}",
                why="Default community strings let attackers enumerate full device configs via SNMP.",
                fix="Use SNMPv3 with authPriv; change community strings; firewall UDP 161.",
                risk=68,
                packet_nos=snmp_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 31: BGP Hijack Signature ──── (CUSTOM) ──────────────────────
    def detect_bgp_anomaly(self):
        self._cb("BGP Anomaly")
        if not SCAPY_OK: return
        bgp_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and pkt[TCP].dport == 179 and pkt.haslayer(Raw):
                bgp_pkts.append(i + 1)
        if len(bgp_pkts) > 50:
            self.detections.append(Detection(
                name="BGP Anomaly / Potential Route Hijack (Custom Rule)",
                possibility=60,
                target="BGP peers (TCP/179)",
                evidence=f"{len(bgp_pkts)} BGP packets – possible route injection",
                why="BGP route hijacking redirects internet traffic to attacker-controlled infrastructure.",
                fix="Implement RPKI; peer authentication (MD5 or TCP-AO); monitor BGP updates.",
                risk=85,
                severity="CRITICAL"
            ))

    # ── RULE 32: RDP Brute Force ───── (CUSTOM) ──────────────────────────
    def detect_rdp_bruteforce(self):
        self._cb("RDP Brute Force")
        if not SCAPY_OK: return
        rdp_conns: Dict[str, int] = Counter()
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].dport == 3389:
                rdp_conns[pkt[IP].src] += 1
        attackers = {ip: c for ip, c in rdp_conns.items() if c > 50}
        if attackers:
            self.detections.append(Detection(
                name="RDP Brute Force Attempt (Custom Rule)",
                possibility=82,
                target="RDP servers (TCP/3389)",
                evidence=f"High RDP connection attempts from: {attackers}",
                why="Automated RDP credential stuffing leads to ransomware deployment.",
                fix="Restrict RDP to VPN; enable NLA; deploy MFA; use account lockout policies.",
                risk=80,
                severity="CRITICAL"
            ))

    # ── RULE 33: SMB EternalBlue Signature ─── (CUSTOM) ─────────────────
    def detect_eternalblue(self):
        self._cb("EternalBlue / MS17-010")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and pkt[TCP].dport == 445 and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                if b"\x00\x00\x00\x85\xff\x53\x4d\x42" in raw or \
                   (len(raw) > 8 and raw[4:8] == b"\xff\x53\x4d\x42"):
                    self.detections.append(Detection(
                        name="EternalBlue (MS17-010) Exploit Signature (Custom Rule)",
                        possibility=87,
                        target=f"SMB server – pkt {i+1}",
                        evidence=f"Pkt {i+1}: SMB transaction with EternalBlue-pattern bytes",
                        why="EternalBlue exploits SMBv1 to achieve unauthenticated RCE (WannaCry / NotPetya).",
                        fix="Disable SMBv1; patch MS17-010; block TCP/445 at perimeter.",
                        risk=98,
                        packet_nos=[i+1],
                        severity="CRITICAL"
                    ))
                    voice_alert("EternalBlue exploit detected")
                    return

    # ── RULE 34: XSS in HTTP ───── (CUSTOM) ──────────────────────────────
    def detect_xss(self):
        self._cb("XSS Detection")
        if not SCAPY_OK: return
        xss_re = re.compile(r"<script|javascript:|onerror=|onload=|alert\(|document\.cookie", re.I)
        evidence_pkts = []
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw]).decode("utf-8", errors="ignore")
                if xss_re.search(payload):
                    evidence_pkts.append(i + 1)
        if evidence_pkts:
            self.detections.append(Detection(
                name="Cross-Site Scripting (XSS) Payload in HTTP (Custom Rule)",
                possibility=80,
                target="Web applications",
                evidence=f"XSS patterns in pkts: {evidence_pkts[:5]}",
                why="XSS enables session hijacking, phishing, defacement via injected scripts.",
                fix="Implement CSP headers; sanitise output; use HTTPOnly/Secure cookie flags.",
                risk=74,
                packet_nos=evidence_pkts[:5],
                severity="HIGH"
            ))

    # ── RULE 35: Zero-Window TCP (Resource Exhaustion) ── (CUSTOM) ──────
    def detect_zero_window(self):
        self._cb("TCP Zero-Window Probe")
        if not SCAPY_OK: return
        zw_count = 0
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].window == 0:
                zw_count += 1
        if zw_count > 100:
            self.detections.append(Detection(
                name="TCP Zero-Window Resource Exhaustion (Custom Rule)",
                possibility=72,
                target="TCP servers",
                evidence=f"{zw_count} TCP packets with window=0 (possible Slowloris/resource exhaustion)",
                why="Sustained zero-window advertisements hold server connections open consuming resources.",
                fix="Lower connection timeout; deploy connection rate limits; use reverse proxy.",
                risk=58,
                severity="MEDIUM"
            ))

    # ── RULE 36: LDAP Null Bind ───── (CUSTOM) ───────────────────────────
    def detect_ldap_null_bind(self):
        self._cb("LDAP Null Bind")
        if not SCAPY_OK: return
        for i, pkt in enumerate(self.packets):
            if pkt.haslayer(TCP) and pkt[TCP].dport == 389 and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                # LDAP BindRequest with empty credentials: 0x30 ... 0x80 0x00
                if b"\x80\x00" in raw and b"\x30" in raw:
                    self.detections.append(Detection(
                        name="LDAP Anonymous / Null Bind Attempt (Custom Rule)",
                        possibility=78,
                        target="LDAP directory server",
                        evidence=f"Pkt {i+1}: LDAP bind with empty credentials",
                        why="Null binds allow unauthenticated LDAP enumeration of users and groups.",
                        fix="Disable anonymous binds in LDAP; require authenticated access only.",
                        risk=65,
                        packet_nos=[i+1],
                        severity="HIGH"
                    ))
                    return

    # ── RULE 37: DHCP Starvation ──────────────────────────────────────────
    def detect_dhcp_starvation(self):
        self._cb("DHCP Starvation")
        if not SCAPY_OK: return
        discover_macs = set()
        for pkt in self.packets:
            if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
                opts = {k: v for k, v in pkt[DHCP].options if isinstance(k, str)}
                if opts.get("message-type") == 1:  # DISCOVER
                    discover_macs.add(pkt[BOOTP].chaddr.hex())
        if len(discover_macs) > 50:
            self.detections.append(Detection(
                name="DHCP Starvation / Pool Exhaustion (Custom Rule)",
                possibility=85,
                target="DHCP server",
                evidence=f"{len(discover_macs)} unique MACs sending DHCP DISCOVER",
                why="Exhausting the DHCP pool denies IP addresses to legitimate clients (DoS).",
                fix="Enable DHCP snooping; limit DHCP requests per port; use static IPs for critical hosts.",
                risk=68,
                severity="HIGH"
            ))

    # ── RUNNER ────────────────────────────────────────────────────────────
    def run_all(self) -> List[Detection]:
        """Execute all detection rules and return collected findings."""
        rules = [
            self.detect_arp_spoofing, self.detect_deauth_flood,
            self.detect_evil_twin, self.detect_krack,
            self.detect_dhcp_spoofing, self.detect_mac_flooding,
            self.detect_ssl_stripping, self.detect_syn_flood,
            self.detect_weak_encryption, self.detect_wps,
            self.detect_no_pmf, self.detect_broadcast_flood,
            self.detect_old_tls, self.detect_dns_tunnelling,
            self.detect_beacon_flood, self.detect_probe_anomalies,
            self.detect_sqli, self.detect_c2_beaconing,
            self.detect_exfiltration, self.detect_icmp_flood,
            self.detect_cleartext_auth, self.detect_port_scan,
            self.detect_cleartext_protocols, self.detect_llmnr_nbtns,
            self.detect_rogue_ra, self.detect_heartbleed,
            self.detect_dns_rebinding, self.detect_http_tunnel,
            self.detect_vlan_hopping, self.detect_snmp_public,
            self.detect_bgp_anomaly, self.detect_rdp_bruteforce,
            self.detect_eternalblue, self.detect_xss,
            self.detect_zero_window, self.detect_ldap_null_bind,
            self.detect_dhcp_starvation,
        ]
        for rule in rules:
            try:
                rule()
            except Exception as e:
                pass  # Graceful – never crash on a single rule failure
        return self.detections


# ══════════════════════════════════════════════════════════════════════════
# SECTION 8: ML ANOMALY DETECTION
# ══════════════════════════════════════════════════════════════════════════

def ml_anomaly_detection(packets: list) -> List[dict]:
    """
    Runs Isolation Forest + statistical z-score on packet features.
    Returns list of anomalous packet records.
    """
    if not ML_OK or not SCAPY_OK or len(packets) < 20:
        return []

    records = []
    for i, pkt in enumerate(packets):
        try:
            src_ip, dst_ip = safe_ip(pkt)
            records.append({
                "pkt_no":  i + 1,
                "length":  len(pkt),
                "sport":   pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
                "dport":   pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
                "proto":   6 if pkt.haslayer(TCP) else (17 if pkt.haslayer(UDP) else 0),
                "flags":   int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0,
                "src_ip":  src_ip,
                "dst_ip":  dst_ip,
                "ttl":     pkt[IP].ttl if pkt.haslayer(IP) else 0,
            })
        except Exception:
            pass

    if len(records) < 20:
        return []

    df = pd.DataFrame(records)
    features = ["length", "sport", "dport", "proto", "flags", "ttl"]
    X = df[features].fillna(0).values

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    preds = iso.fit_predict(X_scaled)
    scores = iso.decision_function(X_scaled)

    anomalies = []
    for idx in range(len(records)):
        if preds[idx] == -1:
            rec  = records[idx]
            rec["anomaly_score"] = round(float(-scores[idx]), 4)
            anomalies.append(rec)

    return anomalies[:50]  # cap at 50 for report


# ══════════════════════════════════════════════════════════════════════════
# SECTION 9: INTERFACE DETECTION (Wireshark-style)
# ══════════════════════════════════════════════════════════════════════════

def get_interfaces() -> List[Dict]:
    """
    Returns list of interface dicts with: name, type, mac, ip, status, monitor.
    Uses netifaces + ip link + iw dev + airmon-ng.
    """
    ifaces = []

    # ── Method 1: netifaces ──────────────────────────────────────────────
    if NETIFACES_OK:
        for name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(name)
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr", "??:??:??:??:??:??")
            ip  = addrs.get(netifaces.AF_INET,  [{}])[0].get("addr", "")
            ifaces.append({"name": name, "mac": mac, "ip": ip or "—",
                           "type": "?", "status": "?", "monitor": False})

    # ── Method 2: ip link (Linux) ─────────────────────────────────────────
    try:
        out = subprocess.check_output(["ip", "link"], stderr=subprocess.DEVNULL, text=True)
        link_status: Dict[str, str] = {}
        for line in out.splitlines():
            m = re.match(r"\d+:\s+(\w+).*<([^>]+)>", line)
            if m:
                iname, flags_str = m.group(1), m.group(2)
                link_status[iname] = "UP" if "UP" in flags_str else "DOWN"
        for iface in ifaces:
            iface["status"] = link_status.get(iface["name"], "?")
    except Exception:
        pass

    # ── Method 3: iw dev (WiFi interfaces) ───────────────────────────────
    try:
        out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL, text=True)
        current = None
        for line in out.splitlines():
            m = re.match(r"\s+Interface\s+(\w+)", line)
            if m:
                current = m.group(1)
            if current and "type monitor" in line:
                for iface in ifaces:
                    if iface["name"] == current:
                        iface["type"]    = "WiFi (monitor)"
                        iface["monitor"] = True
            if current and "type managed" in line:
                for iface in ifaces:
                    if iface["name"] == current:
                        iface["type"] = "WiFi"
    except Exception:
        pass

    # ── Type detection heuristics ─────────────────────────────────────────
    for iface in ifaces:
        n = iface["name"]
        if iface["type"] == "?":
            if n.startswith("wl") or n.startswith("wlan") or n.startswith("ath"):
                iface["type"] = "WiFi"
            elif n.startswith("eth") or n.startswith("en") or n.startswith("ens"):
                iface["type"] = "Ethernet"
            elif n.startswith("lo"):
                iface["type"] = "Loopback"
            elif n.startswith("tun") or n.startswith("tap"):
                iface["type"] = "VPN/Tunnel"
            elif n.startswith("docker") or n.startswith("br-"):
                iface["type"] = "Virtual/Docker"
            elif n.startswith("usb") or n.startswith("enx"):
                iface["type"] = "USB Ethernet"
            else:
                iface["type"] = "Unknown"

    return ifaces


def show_interface_table(ifaces: List[Dict]) -> str:
    """Display colourful interface table and return chosen interface name."""
    table = Table(
        title="[bold cyan]Available Interfaces[/bold cyan]",
        border_style="cyan",
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
    )
    table.add_column("#",       style="bold white",  width=4)
    table.add_column("Name",    style="bold cyan",   width=15)
    table.add_column("Type",    style="bold yellow", width=18)
    table.add_column("MAC",     style="dim white",   width=20)
    table.add_column("IP",      style="green",       width=16)
    table.add_column("Status",  style="bold",        width=8)
    table.add_column("Monitor", style="magenta",     width=9)

    for idx, iface in enumerate(ifaces, 1):
        status_col = "[green]UP[/green]" if iface["status"] == "UP" else "[red]DOWN[/red]"
        monitor    = "[cyan]✔[/cyan]" if iface["monitor"] else "—"
        table.add_row(
            str(idx), iface["name"], iface["type"],
            iface["mac"], iface["ip"], status_col, monitor
        )

    console.print(table)

    while True:
        raw = Prompt.ask("[bold cyan]  ⮞  Select interface number or name[/bold cyan]")
        if raw.isdigit():
            idx = int(raw) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]["name"]
        else:
            for iface in ifaces:
                if iface["name"] == raw:
                    return raw
        console.print("[red]Invalid selection – try again.[/red]")


def enable_monitor_mode(iface: str) -> str:
    """
    Enable monitor mode via airmon-ng if needed.
    Returns the new monitor interface name (e.g. wlan0mon).
    """
    if not check_tool("airmon-ng"):
        console.print("[yellow]airmon-ng not found; skipping monitor mode.[/yellow]")
        return iface
    if not require_root("Monitor mode"):
        return iface
    try:
        console.print(f"[cyan]Enabling monitor mode on {iface}...[/cyan]")
        subprocess.run(["airmon-ng", "check", "kill"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out = subprocess.check_output(["airmon-ng", "start", iface],
                                      stderr=subprocess.DEVNULL, text=True)
        m = re.search(r"monitor mode (?:enabled|vif) (?:on|=) (\w+)", out, re.I)
        new_iface = m.group(1) if m else iface + "mon"
        console.print(f"[green]✔ Monitor interface: {new_iface}[/green]")
        return new_iface
    except Exception as e:
        console.print(f"[red]Monitor mode error: {e}[/red]")
        return iface


# ══════════════════════════════════════════════════════════════════════════
# SECTION 10: LIVE CAPTURE (Option 2)
# ══════════════════════════════════════════════════════════════════════════

# Shared state for live capture display
_live_packets: list = []
_live_lock = threading.Lock()
_capture_active = threading.Event()
_capture_active.set()

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6",
             47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF"}

def _pkt_proto(pkt) -> str:
    if not SCAPY_OK: return "?"
    if pkt.haslayer(DNS):  return "DNS"
    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        if dport in (80, 8080): return "HTTP"
        if dport in (443, 8443): return "TLS"
        if dport == 22: return "SSH"
        if dport == 21: return "FTP"
        if dport == 23: return "Telnet"
        if dport == 25: return "SMTP"
        if dport == 3389: return "RDP"
        return "TCP"
    if pkt.haslayer(UDP): return "UDP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(ARP):  return "ARP"
    if pkt.haslayer(Dot11): return "802.11"
    return "Other"


def _pkt_info(pkt) -> str:
    """Return a short info string like Wireshark."""
    if not SCAPY_OK: return ""
    try:
        if pkt.haslayer(ARP):
            op = "who-has" if pkt[ARP].op == 1 else "is-at"
            return f"ARP {op} {pkt[ARP].pdst}"
        if pkt.haslayer(DNS):
            if pkt[DNS].qr == 0 and pkt[DNS].qd:
                return f"Query {pkt[DNS].qd.qname.decode('utf-8', errors='ignore')}"
            return "DNS Response"
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            f_str = ""
            if flags & 0x02: f_str += "SYN "
            if flags & 0x10: f_str += "ACK "
            if flags & 0x01: f_str += "FIN "
            if flags & 0x04: f_str += "RST "
            return f"TCP {pkt[TCP].sport}→{pkt[TCP].dport} [{f_str.strip()}]"
        if pkt.haslayer(UDP):
            return f"UDP {pkt[UDP].sport}→{pkt[UDP].dport}"
        if pkt.haslayer(Dot11Beacon):
            return f"Beacon: {pkt[Dot11Beacon].network_stats().get('ssid','?')}"
        if pkt.haslayer(Dot11Deauth):
            return "Deauthentication (reason={})".format(pkt[Dot11Deauth].reason)
    except Exception:
        pass
    return ""


def _pkt_row_style(pkt, detections_set: set) -> str:
    """Return Rich style for the packet row."""
    if not SCAPY_OK: return ""
    if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
        return "bold red"
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        return "yellow"
    if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
        return "cyan"
    return ""


def build_live_table(packets: list, max_rows: int = 25) -> Table:
    """Build a Rich Table of recent packets, Wireshark-style."""
    table = Table(
        border_style="cyan", show_header=True,
        header_style="bold magenta", box=box.SIMPLE_HEAVY,
        expand=True
    )
    table.add_column("No.",      style="bold white", width=6)
    table.add_column("Time",     style="cyan",       width=13)
    table.add_column("Source",   style="green",      width=18)
    table.add_column("Dest",     style="yellow",     width=18)
    table.add_column("Protocol", style="bold cyan",  width=9)
    table.add_column("Length",   style="white",      width=8)
    table.add_column("Info",     style="dim white",  min_width=20)

    display = packets[-max_rows:]
    for i, pkt in enumerate(display):
        pkt_no   = len(packets) - len(display) + i + 1
        ts       = ts_to_str(getattr(pkt, "time", 0))
        src, dst = safe_ip(pkt)
        proto    = _pkt_proto(pkt)
        length   = str(len(pkt))
        info     = _pkt_info(pkt)
        style    = _pkt_row_style(pkt, set())
        table.add_row(str(pkt_no), ts, src, dst, proto, length, info, style=style)

    return table


def live_capture_loop(iface: str, duration: Optional[int], pcap_path: Path):
    """
    Capture packets live; update _live_packets.
    Duration=None means unlimited (stops on Ctrl+C).
    """
    global _live_packets
    _live_packets = []

    def pkt_handler(pkt):
        if not _capture_active.is_set():
            return
        with _live_lock:
            _live_packets.append(pkt)

    console.print(f"\n[bold cyan]Starting capture on [magenta]{iface}[/magenta]...[/bold cyan]")
    try:
        sniff(iface=iface, prn=pkt_handler, store=False,
              timeout=duration, stop_filter=lambda _: not _capture_active.is_set())
    except Exception as e:
        console.print(f"[red]Capture error: {e}[/red]")


def run_live_capture():
    """Option 2: Full live capture flow with Wireshark-like real-time table."""
    if not require_root("Live packet capture"):
        return

    console.print(Rule("[bold cyan]LIVE CAPTURE MODE[/bold cyan]", style="cyan"))

    # ── Interface selection ───────────────────────────────────────────────
    with console.status("[cyan]Scanning interfaces...[/cyan]"):
        ifaces = get_interfaces()
    if not ifaces:
        console.print("[red]No interfaces found.[/red]")
        return

    iface = show_interface_table(ifaces)

    # ── Monitor mode? ─────────────────────────────────────────────────────
    is_wifi = any(i["name"] == iface and "WiFi" in i["type"] for i in ifaces)
    if is_wifi:
        if Confirm.ask("[cyan]Enable monitor mode (airmon-ng)?[/cyan]", default=True):
            iface = enable_monitor_mode(iface)

    # ── Duration ──────────────────────────────────────────────────────────
    dur_raw = Prompt.ask(
        "[bold cyan]Capture duration in seconds[/bold cyan] (or 0 for unlimited)",
        default="60"
    )
    duration = int(dur_raw) if dur_raw.isdigit() and int(dur_raw) > 0 else None

    # ── Start capture thread ──────────────────────────────────────────────
    _capture_active.set()
    cap_thread = threading.Thread(
        target=live_capture_loop, args=(iface, duration, Path("/tmp/cap.pcap")),
        daemon=True
    )
    cap_thread.start()

    # ── Live display ──────────────────────────────────────────────────────
    start_time = time.time()
    try:
        with Live(refresh_per_second=4, screen=False) as live:
            while cap_thread.is_alive():
                elapsed = time.time() - start_time
                with _live_lock:
                    pkts_copy = list(_live_packets)

                # Header
                elapsed_str = f"{int(elapsed)}s" if duration is None else \
                              f"{int(elapsed)}s / {duration}s"
                prog_pct    = min(int(elapsed / duration * 100), 100) if duration else 0

                header = Panel(
                    Text.assemble(
                        ("  ● LIVE CAPTURE  ", "bold red on black"),
                        (f"  Interface: ", "white"),
                        (iface, "bold cyan"),
                        (f"  │  Packets: ", "white"),
                        (str(len(pkts_copy)), "bold green"),
                        (f"  │  Time: ", "white"),
                        (elapsed_str, "bold yellow"),
                    ),
                    border_style="cyan", padding=(0, 2)
                )
                table = build_live_table(pkts_copy)
                live.update(header)
                time.sleep(0.25)
                live.update(table)
                time.sleep(0.0)
    except KeyboardInterrupt:
        _capture_active.clear()
        console.print("\n[yellow]Capture stopped by user.[/yellow]")

    _capture_active.clear()
    cap_thread.join(timeout=2)

    with _live_lock:
        final_pkts = list(_live_packets)

    if not final_pkts:
        console.print("[red]No packets captured.[/red]")
        return

    # ── Save PCAP ─────────────────────────────────────────────────────────
    pcap_name = Prompt.ask("[bold cyan]Enter name to save capture[/bold cyan]",
                           default=f"capture_{int(time.time())}")
    safe_name = re.sub(r"[^A-Za-z0-9_\-]", "_", pcap_name)
    report_dir = create_report_dir(safe_name)
    pcap_path  = report_dir / f"{safe_name}.pcap"
    wrpcap(str(pcap_path), final_pkts)
    console.print(f"[green]✔ PCAP saved: {pcap_path}[/green]")

    # ── Offer analysis ────────────────────────────────────────────────────
    if Confirm.ask("[bold cyan]Start scanning the captured packets?[/bold cyan]", default=True):
        run_analysis(final_pkts, safe_name, report_dir, pcap_path)


# ══════════════════════════════════════════════════════════════════════════
# SECTION 11: PCAP FILE ANALYSIS ORCHESTRATOR (Options 1 & 2 shared)
# ══════════════════════════════════════════════════════════════════════════

def run_pcap_option():
    """Option 1: Ask for PCAP file, load it, run analysis."""
    console.print(Rule("[bold cyan]PCAP FILE ANALYSIS[/bold cyan]", style="cyan"))
    pcap_input = Prompt.ask("[bold cyan]  ⮞  Enter path to PCAP/PCAPng file[/bold cyan]")
    pcap_input = pcap_input.strip().strip("'\"")

    if not Path(pcap_input).exists():
        console.print(f"[red]File not found: {pcap_input}[/red]")
        return

    report_name = Prompt.ask(
        "[bold cyan]  ⮞  Report name[/bold cyan]",
        default=Path(pcap_input).stem
    )
    safe_name  = re.sub(r"[^A-Za-z0-9_\-]", "_", report_name)
    report_dir = create_report_dir(safe_name)

    # Copy PCAP
    dst_pcap = report_dir / f"{safe_name}.pcap"
    shutil.copy2(pcap_input, dst_pcap)

    # Load packets
    with console.status("[cyan]Loading PCAP...[/cyan]"):
        try:
            packets = rdpcap(pcap_input)
        except Exception as e:
            console.print(f"[red]Error reading PCAP: {e}[/red]")
            return

    console.print(f"[green]✔ Loaded {len(packets)} packets from {Path(pcap_input).name}[/green]\n")
    run_analysis(list(packets), safe_name, report_dir, dst_pcap)


def run_analysis(packets: list, name: str, report_dir: Path, pcap_path: Path):
    """
    Full analysis pipeline with animated terminal dashboard:
    1. Rule-based detection
    2. ML anomaly detection
    3. Risk scoring
    4. Generate reports (JSON, TXT, PDF, HTML)
    5. Open HTML in browser
    """
    steps = [
        "Analysing ARP & Layer-2 …",
        "Checking WiFi Management Frames …",
        "Running DHCP/DNS Inspection …",
        "Scanning TCP/IP Anomalies …",
        "Detecting SSL/TLS Issues …",
        "Checking for Cleartext Credentials …",
        "Running Behavioural Analysis …",
        "Training Isolation Forest (ML) …",
        "Scoring Risk Levels …",
        "Generating JSON Report …",
        "Building TXT Summary …",
        "Rendering PDF …",
        "Compiling HTML Dashboard …",
    ]

    detections: List[Detection] = []
    anomalies:  List[dict]      = []
    current_step = ["Initialising …"]

    def progress_cb(step_name: str):
        current_step[0] = step_name

    # ── Progress display (Rich Live) ──────────────────────────────────────
    with Progress(
        SpinnerColumn(spinner_name="aesthetic", style="bold cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="bold cyan", complete_style="bold green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as prog:
        overall = prog.add_task("[bold white]Overall Analysis", total=len(steps))
        detail  = prog.add_task("[dim cyan]Starting …", total=1, start=False)

        for i, step in enumerate(steps):
            prog.update(detail, description=f"[cyan]{step}[/cyan]")
            prog.start_task(detail)

            if i < 7:
                # Run rule engine (split conceptually – all happen in one call)
                if i == 0:
                    engine = RuleEngine(packets, progress_cb=progress_cb)
                    detections = engine.run_all()
            elif i == 7:
                anomalies = ml_anomaly_detection(packets)
            elif i == 8:
                pass   # Risk scoring embedded in Detection objects
            elif i == 9:
                _save_json(name, report_dir, packets, detections, anomalies)
            elif i == 10:
                _save_txt(name, report_dir, packets, detections, anomalies)
            elif i == 11:
                _save_pdf(name, report_dir, packets, detections, anomalies)
            elif i == 12:
                html_path = _save_html(name, report_dir, packets, detections, anomalies)

            time.sleep(0.3)  # Animate
            prog.update(overall, advance=1)
            prog.reset(detail, start=False)

    # ── Terminal summary dashboard ─────────────────────────────────────────
    _show_terminal_dashboard(packets, detections, anomalies, name)

    # ── Print HTML path (do NOT auto-open browser) ───────────────────────
    if html_path and html_path.exists():
        console.print(Panel(
            Text.assemble(
                ("  HTML Dashboard saved:\n", "bold white"),
                (f"  {html_path.resolve()}\n", "bold cyan"),
                ("\n  Open manually in browser, e.g.:\n", "dim white"),
                (f"  firefox '{html_path.resolve()}'\n", "dim cyan"),
            ),
            title="[bold green]✔ HTML Report Ready[/bold green]",
            border_style="green",
            padding=(0, 2),
        ))

    console.print(f"\n[bold green]✔ All reports saved in: {report_dir}[/bold green]\n")


# ══════════════════════════════════════════════════════════════════════════
# SECTION 12: TERMINAL DASHBOARD (Rich)
# ══════════════════════════════════════════════════════════════════════════

def _show_terminal_dashboard(packets: list, detections: List[Detection],
                             anomalies: List[dict], name: str):
    """Display final animated Rich summary dashboard in terminal."""
    overall_risk = min(100, sum(d.risk for d in detections) // max(len(detections), 1)) \
                   if detections else 0

    # ── Risk gauge ────────────────────────────────────────────────────────
    bar_len  = 40
    filled   = int(bar_len * overall_risk / 100)
    risk_col = risk_colour(overall_risk)
    bar      = ("█" * filled).ljust(bar_len, "░")
    gauge    = f"[{risk_col}]{bar}[/{risk_col}] [{risk_col}]{overall_risk}/100[/{risk_col}] [{risk_col}]{risk_label(overall_risk)}[/{risk_col}]"

    # ── Stats panel ───────────────────────────────────────────────────────
    stats = Panel(
        Text.assemble(
            ("  Packets analysed:   ", "dim white"), (str(len(packets)), "bold cyan"), ("\n", ""),
            ("  Threats detected:   ", "dim white"), (str(len(detections)), "bold red"), ("\n", ""),
            ("  ML anomalies:       ", "dim white"), (str(len(anomalies)), "bold yellow"), ("\n", ""),
            ("  Overall risk score: ", "dim white"),
        ),
        title="[bold cyan]Analysis Summary[/bold cyan]",
        border_style="cyan", padding=(1, 2)
    )
    console.print("\n")
    console.print(stats)
    console.print(f"  {gauge}\n")

    # ── Detections table ──────────────────────────────────────────────────
    if detections:
        t = Table(
            title="[bold red]── Detected Threats ──[/bold red]",
            border_style="red", show_header=True,
            header_style="bold magenta", box=box.ROUNDED, expand=True
        )
        t.add_column("Threat",      style="bold white",  min_width=30)
        t.add_column("Severity",    style="bold",        width=10)
        t.add_column("Probability", style="bold cyan",   width=12)
        t.add_column("Risk",        style="bold",        width=6)
        t.add_column("Pkt Evidence",style="dim white",   min_width=12)

        for d in sorted(detections, key=lambda x: x.risk, reverse=True):
            sev_col = {"CRITICAL": "red", "HIGH": "yellow",
                       "MEDIUM": "magenta", "LOW": "cyan", "INFO": "white"}.get(d.severity, "white")
            t.add_row(
                d.name,
                f"[{sev_col}]{d.severity}[/{sev_col}]",
                f"{d.possibility}%",
                f"[{risk_colour(d.risk)}]{d.risk}[/{risk_colour(d.risk)}]",
                str(d.packet_nos[:3]) if d.packet_nos else "—"
            )
        console.print(t)

    # ── ML anomalies panel ────────────────────────────────────────────────
    if anomalies:
        console.print(Panel(
            f"[yellow]{len(anomalies)} ML-flagged anomalous packets (Isolation Forest 5% contamination)[/yellow]\n"
            + "\n".join(
                f"  Pkt {a['pkt_no']:>5} | {a['src_ip']:<16} → {a['dst_ip']:<16} | score={a['anomaly_score']}"
                for a in anomalies[:8]
            ),
            title="[bold yellow]ML Anomaly Detection[/bold yellow]",
            border_style="yellow", padding=(0, 1)
        ))


# ══════════════════════════════════════════════════════════════════════════
# SECTION 13: JSON REPORT (+ SIEM/ELK/CEF FORMAT)
# ══════════════════════════════════════════════════════════════════════════

def _save_json(name: str, report_dir: Path, packets: list,
               detections: List[Detection], anomalies: List[dict]) -> Path:
    overall_risk = min(100, sum(d.risk for d in detections) // max(len(detections), 1)) \
                   if detections else 0

    # Protocol distribution
    proto_counts: Dict[str, int] = defaultdict(int)
    for p in packets:
        proto_counts[_pkt_proto(p)] += 1

    report = {
        "tool":        TOOL_NAME,
        "version":     VERSION,
        "report_name": name,
        "generated":   datetime.datetime.now().isoformat(),
        "summary": {
            "total_packets":    len(packets),
            "threats_detected": len(detections),
            "ml_anomalies":     len(anomalies),
            "overall_risk":     overall_risk,
            "risk_label":       risk_label(overall_risk),
            "protocol_dist":    dict(proto_counts),
        },
        "detections": [d.to_dict() for d in detections],
        "ml_anomalies": anomalies,
        # SIEM/CEF export entries
        "siem_events": [
            {
                "cef_version": "0",
                "device_vendor": "AutoWiFiSniff",
                "device_product": "ProV2",
                "device_version": VERSION,
                "signature_id":   re.sub(r"\W+", "_", d.name)[:40],
                "name":           d.name,
                "severity":       d.risk,
                "extensions": {
                    "msg":    d.why[:128],
                    "reason": d.fix[:128],
                    "cs1":    d.evidence[:128],
                    "cs1Label": "Evidence",
                    "outcome": d.severity,
                }
            }
            for d in detections
        ],
    }

    path = report_dir / f"{name}.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


# ══════════════════════════════════════════════════════════════════════════
# SECTION 14: TXT REPORT
# ══════════════════════════════════════════════════════════════════════════

def _save_txt(name: str, report_dir: Path, packets: list,
              detections: List[Detection], anomalies: List[dict]) -> Path:
    overall_risk = min(100, sum(d.risk for d in detections) // max(len(detections), 1)) \
                   if detections else 0
    lines = [
        "=" * 78,
        f"  {TOOL_NAME} v{VERSION} — Security Analysis Report",
        f"  Report: {name}",
        f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 78,
        "",
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"  Total Packets Analysed : {len(packets)}",
        f"  Threats Detected       : {len(detections)}",
        f"  ML Anomalies           : {len(anomalies)}",
        f"  Overall Risk Score     : {overall_risk}/100 ({risk_label(overall_risk)})",
        "",
        "DETECTED THREATS",
        "=" * 78,
    ]

    for idx, d in enumerate(sorted(detections, key=lambda x: x.risk, reverse=True), 1):
        lines += [
            "",
            f"[{idx}] {d.name}",
            f"    Severity    : {d.severity}",
            f"    Probability : {d.possibility}%",
            f"    Risk Score  : {d.risk}/100",
            f"    Target      : {d.target}",
            f"    Evidence    : {d.evidence}",
            f"    Why Malicious: {textwrap.fill(d.why, width=70, subsequent_indent=' '*18)}",
            f"    Recommended Fix: {textwrap.fill(d.fix, width=70, subsequent_indent=' '*18)}",
            f"    Packet Nos  : {d.packet_nos[:10] if d.packet_nos else 'N/A'}",
            "-" * 78,
        ]

    if anomalies:
        lines += ["", "ML ANOMALY DETECTION (Isolation Forest)", "=" * 78]
        for a in anomalies[:20]:
            lines.append(
                f"  Pkt {a['pkt_no']:>5} | {a['src_ip']:<16} → {a['dst_ip']:<16}"
                f" | proto={a['proto']} dport={a['dport']} score={a['anomaly_score']}"
            )

    lines += [
        "",
        "=" * 78,
        f"  End of Report — {TOOL_NAME} v{VERSION}",
        "=" * 78,
    ]

    path = report_dir / f"{name}.txt"
    path.write_text("\n".join(lines))
    return path


# ══════════════════════════════════════════════════════════════════════════
# SECTION 15: PDF REPORT (ReportLab + Matplotlib)
# ══════════════════════════════════════════════════════════════════════════

def _make_risk_chart(detections: List[Detection], out_path: str):
    """Generate a matplotlib risk distribution pie chart."""
    if not MPL_OK or not detections:
        return

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for d in detections:
        counts[d.severity] = counts.get(d.severity, 0) + 1

    labels  = [k for k, v in counts.items() if v > 0]
    values  = [v for v in counts.values() if v > 0]
    colours = {"CRITICAL": "#ff2255", "HIGH": "#ff9900",
               "MEDIUM": "#cc44ff", "LOW": "#00ccff", "INFO": "#44ff88"}
    clrs    = [colours[l] for l in labels]

    fig, ax = plt.subplots(figsize=(5, 4), facecolor="#0a0a1a")
    ax.set_facecolor("#0a0a1a")
    wedges, texts, autotexts = ax.pie(
        values, labels=labels, colors=clrs, autopct="%1.0f%%",
        startangle=90, pctdistance=0.8,
        wedgeprops=dict(linewidth=1.5, edgecolor="#1a1a3a")
    )
    for t in texts + autotexts:
        t.set_color("white")
        t.set_fontsize(9)
    ax.set_title("Threat Severity Distribution", color="white", fontsize=11, pad=12)
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#0a0a1a")
    plt.close()


def _make_timeline_chart(packets: list, detections: List[Detection], out_path: str):
    """Create a packet-count timeline showing detected events."""
    if not MPL_OK or len(packets) < 5:
        return

    times = []
    for p in packets[:5000]:
        try:
            times.append(float(p.time))
        except Exception:
            pass

    if not times:
        return

    start = min(times)
    rel   = [t - start for t in times]
    bins  = max(1, int(max(rel) / 2)) if max(rel) > 0 else 1
    bins  = min(bins, 60)

    fig, ax = plt.subplots(figsize=(7, 3), facecolor="#0a0a1a")
    ax.set_facecolor("#0a0a1a")
    n, bin_edges, patches = ax.hist(rel, bins=bins, color="#00ccff", edgecolor="#004466", alpha=0.8)
    ax.set_xlabel("Time (s)", color="#aaaacc", fontsize=8)
    ax.set_ylabel("Packets/bin", color="#aaaacc", fontsize=8)
    ax.set_title("Packet Traffic Timeline", color="white", fontsize=11)
    ax.tick_params(colors="#aaaacc", labelsize=7)
    for spine in ax.spines.values():
        spine.set_edgecolor("#223355")
    plt.tight_layout()
    plt.savefig(out_path, dpi=120, bbox_inches="tight", facecolor="#0a0a1a")
    plt.close()


def _save_pdf(name: str, report_dir: Path, packets: list,
              detections: List[Detection], anomalies: List[dict]) -> Path:
    path = report_dir / f"{name}.pdf"
    if not RL_OK:
        # Fallback: plain text saved as .pdf name
        path.write_text("ReportLab not installed. Install: pip install reportlab")
        return path

    overall_risk = min(100, sum(d.risk for d in detections) // max(len(detections), 1)) \
                   if detections else 0

    # Generate charts
    pie_path      = str(report_dir / "_chart_pie.png")
    timeline_path = str(report_dir / "_chart_timeline.png")
    _make_risk_chart(detections, pie_path)
    _make_timeline_chart(packets, detections, timeline_path)

    doc    = SimpleDocTemplate(str(path), pagesize=A4, topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Colour palette ────────────────────────────────────────────────────
    DARK   = colors.HexColor("#0a0a1a")
    NEON_C = colors.HexColor("#00ccff")
    NEON_M = colors.HexColor("#cc44ff")
    NEON_G = colors.HexColor("#44ff88")
    RED    = colors.HexColor("#ff2255")
    ORANGE = colors.HexColor("#ff9900")
    WHITE  = colors.white
    LGRAY  = colors.HexColor("#aaaacc")

    # ── Cover page ────────────────────────────────────────────────────────
    cover_style = ParagraphStyle("cover", fontName="Helvetica-Bold",
                                 fontSize=26, textColor=NEON_C,
                                 alignment=TA_CENTER, spaceAfter=10)
    sub_style   = ParagraphStyle("sub", fontName="Helvetica",
                                 fontSize=11, textColor=LGRAY,
                                 alignment=TA_CENTER, spaceAfter=6)
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph(TOOL_NAME, cover_style))
    story.append(Paragraph(f"Security Analysis Report — v{VERSION}", sub_style))
    story.append(Paragraph(f"Report: <b>{name}</b>", sub_style))
    story.append(Paragraph(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), sub_style))
    story.append(Spacer(1, 1*cm))

    # Risk meter
    risk_col_rl = RED if overall_risk >= 70 else ORANGE if overall_risk >= 40 else NEON_G
    risk_str    = f"Overall Risk: {overall_risk}/100 — {risk_label(overall_risk)}"
    story.append(Paragraph(risk_str, ParagraphStyle(
        "risk", fontName="Helvetica-Bold", fontSize=16,
        textColor=risk_col_rl, alignment=TA_CENTER, spaceAfter=20
    )))

    # Summary table
    sum_data = [
        ["Metric", "Value"],
        ["Total Packets", str(len(packets))],
        ["Threats Detected", str(len(detections))],
        ["ML Anomalies", str(len(anomalies))],
        ["Overall Risk", f"{overall_risk}/100 ({risk_label(overall_risk)})"],
    ]
    sum_table = RLTable(sum_data, colWidths=[8*cm, 8*cm])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), NEON_C),
        ("TEXTCOLOR",  (0,0), (-1,0), DARK),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#12122a"), colors.HexColor("#1a1a38")]),
        ("TEXTCOLOR",  (0,1), (-1,-1), WHITE),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#334466")),
        ("ROUNDEDCORNERS", [3]),
    ]))
    story.append(sum_table)
    story.append(PageBreak())

    # ── Charts ────────────────────────────────────────────────────────────
    if MPL_OK and detections and Path(pie_path).exists():
        story.append(Paragraph("Threat Analysis Charts", ParagraphStyle(
            "h2", fontName="Helvetica-Bold", fontSize=14, textColor=NEON_C, spaceAfter=10
        )))
        row = [Image(pie_path, width=8*cm, height=6.5*cm)]
        if Path(timeline_path).exists():
            row.append(Image(timeline_path, width=9*cm, height=6.5*cm))
        chart_table = RLTable([row])
        story.append(chart_table)
        story.append(Spacer(1, 0.5*cm))

    # ── Detections ────────────────────────────────────────────────────────
    story.append(Paragraph("Detected Threats", ParagraphStyle(
        "h2", fontName="Helvetica-Bold", fontSize=14, textColor=RED, spaceAfter=8
    )))

    sev_colours_rl = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": NEON_M,
                      "LOW": NEON_C, "INFO": NEON_G}

    for idx, d in enumerate(sorted(detections, key=lambda x: x.risk, reverse=True), 1):
        sev_col_rl = sev_colours_rl.get(d.severity, WHITE)
        story.append(KeepTogether([
            Paragraph(f"{idx}. {d.name}", ParagraphStyle(
                "th", fontName="Helvetica-Bold", fontSize=11,
                textColor=NEON_C, spaceAfter=3
            )),
            RLTable([
                [Paragraph("Severity", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(d.severity, ParagraphStyle("v", fontName="Helvetica-Bold", fontSize=8, textColor=sev_col_rl))],
                [Paragraph("Probability", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(f"{d.possibility}%", ParagraphStyle("v", fontSize=8, textColor=WHITE))],
                [Paragraph("Risk Score", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(f"{d.risk}/100", ParagraphStyle("v", fontSize=8, textColor=sev_col_rl))],
                [Paragraph("Target", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(d.target[:80], ParagraphStyle("v", fontSize=8, textColor=WHITE))],
                [Paragraph("Evidence", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(d.evidence[:120], ParagraphStyle("v", fontSize=8, textColor=ORANGE))],
                [Paragraph("Why", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(d.why[:180], ParagraphStyle("v", fontSize=8, textColor=WHITE))],
                [Paragraph("Fix", ParagraphStyle("l", fontName="Helvetica-Bold", fontSize=8, textColor=LGRAY)),
                 Paragraph(d.fix[:180], ParagraphStyle("v", fontSize=8, textColor=NEON_G))],
            ], colWidths=[3*cm, 13*cm], style=TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#12122a")),
                ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#223355")),
                ("VALIGN", (0,0), (-1,-1), "TOP"),
            ])),
            Spacer(1, 0.3*cm),
        ]))

    story.append(PageBreak())

    # ── ML Anomalies ─────────────────────────────────────────────────────
    if anomalies:
        story.append(Paragraph("Machine Learning Anomalies (Isolation Forest)", ParagraphStyle(
            "h2", fontName="Helvetica-Bold", fontSize=14, textColor=NEON_M, spaceAfter=8
        )))
        ml_data = [["Pkt No", "Src IP", "Dst IP", "Proto", "DPort", "Len", "Score"]]
        for a in anomalies[:30]:
            ml_data.append([
                str(a.get("pkt_no", "")), a.get("src_ip", ""), a.get("dst_ip", ""),
                str(a.get("proto", "")), str(a.get("dport", "")),
                str(a.get("length", "")), str(a.get("anomaly_score", "")),
            ])
        ml_table = RLTable(ml_data, colWidths=[1.5*cm,3.5*cm,3.5*cm,1.5*cm,1.5*cm,1.5*cm,2.5*cm])
        ml_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), NEON_M),
            ("TEXTCOLOR",  (0,0), (-1,0), DARK),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#12122a"), colors.HexColor("#1a1a38")]),
            ("TEXTCOLOR",  (0,1), (-1,-1), WHITE),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#334466")),
        ]))
        story.append(ml_table)

    # ── Footer ─────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(color=NEON_C, thickness=1, width="100%"))
    story.append(Paragraph(
        f"{TOOL_NAME} v{VERSION} — Confidential Security Report — {datetime.date.today()}",
        ParagraphStyle("foot", fontSize=7, textColor=LGRAY, alignment=TA_CENTER)
    ))

    doc.build(story)

    # Cleanup temp chart PNGs
    for p in [pie_path, timeline_path]:
        try:
            Path(p).unlink()
        except Exception:
            pass

    return path


# ══════════════════════════════════════════════════════════════════════════
# SECTION 16: HTML DASHBOARD v2.2 — Token-based (no .format() = no CSS clash)
# Tokens: __RPT__, __GEN__, __PKTS__, __THREATS__, __ML__, __RISK__,
#         __RLABEL__, __RCOL1__, __RCOL2__, __RNUMSTYLE__, __TROWS__,
#         __MLSECT__, __PROTOSECT__, __VULNSECT__, __PIELABELS__,
#         __PIEVALS__, __PIECOLS__, __BARLABELS__, __BARVALS__,
#         __BARCOLS__, __JSONDATA__
# ══════════════════════════════════════════════════════════════════════════

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AutoWiFiSniff Pro v2.2 &mdash; __RPT__</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;600&family=Fira+Mono&display=swap" rel="stylesheet">
<style>
/* AutoWiFiSniff Pro v2.2 – Holographic Theme */
* { margin:0; padding:0; box-sizing:border-box; }
html { scroll-behavior:smooth; }
body { background:#02020e; color:#d8e8ff; font-family:'Inter',sans-serif; min-height:100vh; overflow-x:hidden; }
body::before { content:''; position:fixed; top:0; left:0; width:100%; height:100%;
  background-image: linear-gradient(rgba(0,220,255,0.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,220,255,0.03) 1px,transparent 1px);
  background-size:40px 40px; z-index:0; pointer-events:none; }
body::after { content:''; position:fixed; top:-2px; left:0; width:100%; height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,220,255,0.7),rgba(180,0,255,0.5),transparent);
  animation:scanline 8s linear infinite; z-index:1; pointer-events:none; }
@keyframes scanline { 0% { top:-2px; } 100% { top:100vh; } }
#particles-js { position:fixed; top:0; left:0; width:100%; height:100%; z-index:0; pointer-events:none; }
.wrap { position:relative; z-index:2; max-width:1450px; margin:0 auto; padding:1.5rem 2rem; }
.card { background:rgba(8,8,30,0.72); backdrop-filter:blur(24px) saturate(2);
  border:1px solid rgba(0,220,255,0.22); border-radius:20px; padding:1.6rem;
  box-shadow:0 0 50px rgba(0,220,255,0.05), 0 12px 40px rgba(0,0,0,0.55);
  transition:box-shadow .35s,transform .35s,border-color .35s; animation:fadeUp .55s ease both; }
.card:hover { box-shadow:0 0 80px rgba(0,220,255,0.14), 0 12px 40px rgba(0,0,0,0.65); transform:translateY(-3px); border-color:rgba(0,220,255,0.4); }
.card.mc { border-color:rgba(180,0,255,0.25); }
.card.mc:hover { border-color:rgba(180,0,255,0.55); box-shadow:0 0 80px rgba(180,0,255,0.14), 0 12px 40px rgba(0,0,0,0.65); }
@keyframes fadeUp { from { opacity:0; transform:translateY(28px); } to { opacity:1; transform:none; } }
.card:nth-child(1){animation-delay:.05s} .card:nth-child(2){animation-delay:.1s}
.card:nth-child(3){animation-delay:.15s} .card:nth-child(4){animation-delay:.2s}
header { text-align:center; padding:2.5rem 0 1.5rem; position:relative; }
header::after { content:''; position:absolute; bottom:0; left:50%; transform:translateX(-50%);
  width:60%; height:1px; background:linear-gradient(90deg,transparent,rgba(0,220,255,0.5),rgba(180,0,255,0.5),transparent); }
header h1 { font-family:'Orbitron',monospace; font-size:2.8rem; font-weight:900;
  background:linear-gradient(120deg,#00dcff 0%,#b400ff 40%,#00ff8c 80%,#00dcff 100%);
  background-size:200% auto; -webkit-background-clip:text; -webkit-text-fill-color:transparent;
  background-clip:text; letter-spacing:5px;
  animation:shimmer 4s linear infinite, pulseGlow 3s ease-in-out infinite alternate; }
@keyframes shimmer { 0%{background-position:0% center} 100%{background-position:200% center} }
@keyframes pulseGlow { from{filter:brightness(1)} to{filter:brightness(1.12) drop-shadow(0 0 18px rgba(0,220,255,0.6))} }
.verBadge { display:inline-block; margin-top:.6rem; padding:.2rem .9rem;
  border:1px solid rgba(180,0,255,0.4); border-radius:20px; font-family:'Orbitron',monospace;
  font-size:.62rem; color:#b400ff; letter-spacing:3px; background:rgba(180,0,255,0.07); }
.hsub { color:rgba(100,140,200,0.8); font-size:.82rem; margin-top:.6rem; letter-spacing:3px; font-family:'Fira Mono',monospace; }
.hdate { color:rgba(60,80,130,0.6); font-size:.68rem; margin-top:.3rem; }
.grid-4 { display:grid; grid-template-columns:repeat(4,1fr); gap:1.1rem; margin:1.2rem 0; }
.grid-2 { display:grid; grid-template-columns:repeat(2,1fr); gap:1.3rem; margin:1.1rem 0; }
.stat-card { text-align:center; padding:1.4rem 1rem; position:relative; overflow:hidden; }
.stat-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background:linear-gradient(90deg,transparent,rgba(0,220,255,0.6),transparent); }
.stat-num { font-family:'Orbitron',monospace; font-size:2.6rem; font-weight:900;
  background:linear-gradient(135deg,#00dcff,#b400ff); -webkit-background-clip:text;
  -webkit-text-fill-color:transparent; background-clip:text; }
.stat-label { font-size:.72rem; color:rgba(90,120,180,0.8); letter-spacing:2.5px;
  margin-top:.4rem; text-transform:uppercase; font-family:'Orbitron',monospace; }
h2 { font-family:'Orbitron',monospace; font-size:.95rem; font-weight:700;
  color:#00dcff; letter-spacing:3px; text-transform:uppercase; margin-bottom:1.1rem;
  text-shadow:0 0 20px rgba(0,220,255,0.7); display:inline-block; padding-bottom:.4rem;
  position:relative; }
h2::after { content:''; position:absolute; bottom:0; left:0; width:100%; height:1px;
  background:linear-gradient(90deg,rgba(0,220,255,0.6),rgba(180,0,255,0.4),transparent); }
h2.mg { color:#b400ff; text-shadow:0 0 20px rgba(180,0,255,0.7); }
h2.mg::after { background:linear-gradient(90deg,rgba(180,0,255,0.6),rgba(0,220,255,0.3),transparent); }
.risk-meter { display:flex; align-items:center; gap:1.4rem; padding:.8rem 0; }
.risk-bar-wrap { flex:1; height:24px; background:rgba(0,0,0,0.4); border-radius:12px;
  border:1px solid rgba(0,220,255,0.15); overflow:hidden; position:relative; }
.risk-bar { height:100%; border-radius:12px; transition:width 2s cubic-bezier(.4,0,.2,1); position:relative; overflow:hidden; }
.risk-bar::after { content:''; position:absolute; top:0; left:-100%; width:100%; height:100%;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,0.22),transparent);
  animation:barShine 2.5s ease-in-out infinite; }
@keyframes barShine { 0%,100%{left:-100%} 60%{left:100%} }
.risk-num { font-family:'Orbitron',monospace; font-size:2.2rem; font-weight:900; min-width:70px; text-align:right; }
.risk-desc { font-size:.8rem; color:rgba(100,140,200,0.7); margin-top:.5rem; font-family:'Fira Mono',monospace; letter-spacing:1px; }
.tbl { width:100%; border-collapse:collapse; font-size:.78rem; }
.tbl th { background:rgba(0,220,255,0.08); color:rgba(0,220,255,0.9); padding:.65rem .85rem;
  text-align:left; letter-spacing:1.5px; font-size:.65rem; text-transform:uppercase;
  border-bottom:1px solid rgba(0,220,255,0.18); font-family:'Orbitron',monospace; }
.tbl td { padding:.55rem .85rem; border-bottom:1px solid rgba(255,255,255,0.04);
  font-family:'Fira Mono',monospace; font-size:.73rem; color:rgba(180,200,240,0.9); }
.tbl tr.mrow:hover td { background:rgba(0,220,255,0.04); }
.badge { display:inline-block; border-radius:6px; padding:.15rem .65rem; font-size:.65rem;
  font-weight:700; letter-spacing:1.5px; font-family:'Orbitron',monospace; }
.CRITICAL { background:rgba(255,30,80,.2); color:#ff1e50; border:1px solid rgba(255,30,80,.45); box-shadow:0 0 12px rgba(255,30,80,.3); }
.HIGH     { background:rgba(255,160,0,.18); color:#ffa000; border:1px solid rgba(255,160,0,.4); }
.MEDIUM   { background:rgba(255,220,0,.14); color:#ffdc00; border:1px solid rgba(255,220,0,.35); }
.LOW      { background:rgba(0,255,100,.12); color:#00ff64; border:1px solid rgba(0,255,100,.3); }
.INFO     { background:rgba(0,220,255,.14); color:#00dcff; border:1px solid rgba(0,220,255,.3); }
.drow { display:none; background:rgba(2,2,18,0.85); }
.drow td { padding:1.1rem 1.2rem; font-size:.73rem; line-height:1.7; font-family:'Inter',sans-serif; color:rgba(160,180,220,0.85); }
.exbtn { cursor:pointer; color:#00dcff; font-size:.72rem; background:rgba(0,220,255,0.07);
  border:1px solid rgba(0,220,255,0.25); border-radius:6px; padding:.2rem .6rem;
  font-family:'Fira Mono',monospace; transition:all .2s; }
.exbtn:hover { background:rgba(0,220,255,0.18); box-shadow:0 0 12px rgba(0,220,255,0.2); }
.rbar { display:inline-block; width:55px; height:6px; background:rgba(255,255,255,0.07);
  border-radius:3px; overflow:hidden; vertical-align:middle; margin-right:5px; }
.rbarfill { height:100%; border-radius:3px; }
.filter-wrap { display:flex; align-items:center; gap:.8rem; margin-bottom:1rem; flex-wrap:wrap; }
.finput { background:rgba(0,220,255,.07); border:1px solid rgba(0,220,255,.22);
  border-radius:10px; color:#d0e8ff; padding:.45rem .9rem; font-size:.75rem;
  font-family:'Fira Mono',monospace; outline:none; width:100%; max-width:340px; }
.finput:focus { border-color:rgba(0,220,255,.55); box-shadow:0 0 14px rgba(0,220,255,.18); }
.rcount { font-size:.7rem; color:rgba(80,120,180,.8); font-family:'Fira Mono',monospace; }
.brow { display:flex; gap:.8rem; flex-wrap:wrap; margin-top:1rem; }
.btn { padding:.52rem 1.3rem; border:1px solid rgba(0,220,255,.35); border-radius:10px;
  background:rgba(0,220,255,.08); color:#00dcff; font-size:.72rem; cursor:pointer;
  font-family:'Orbitron',monospace; letter-spacing:1.5px; transition:all .25s; display:inline-block; }
.btn:hover { background:rgba(0,220,255,.22); box-shadow:0 0 25px rgba(0,220,255,.3); transform:scale(1.04); }
.btn.m { border-color:rgba(180,0,255,.35); color:#b400ff; background:rgba(180,0,255,.07); }
.btn.m:hover { background:rgba(180,0,255,.22); box-shadow:0 0 25px rgba(180,0,255,.3); }
.btn.g { border-color:rgba(0,255,100,.3); color:#00ff64; background:rgba(0,255,100,.06); }
.btn.g:hover { background:rgba(0,255,100,.18); box-shadow:0 0 22px rgba(0,255,100,.25); }
.as { color:#b400ff; font-weight:700; font-family:'Orbitron',monospace; font-size:.7rem; }
.pbadge { display:inline-block; padding:.1rem .5rem; border-radius:4px; font-size:.62rem;
  font-family:'Orbitron',monospace; letter-spacing:1px; margin:.2rem .1rem; }
.vcard { border-radius:14px; padding:1.1rem 1.3rem; margin:.6rem 0;
  background:rgba(5,5,22,0.65); border:1px solid rgba(0,220,255,0.1);
  transition:all .3s; position:relative; overflow:hidden; }
.vcard::before { content:''; position:absolute; top:0; left:0; width:3px; height:100%;
  background:linear-gradient(180deg,#00dcff,#b400ff); }
.vcard:hover { border-color:rgba(0,220,255,0.3); transform:translateX(4px); }
.vcard h3 { font-family:'Orbitron',monospace; font-size:.82rem; color:#00dcff; margin-bottom:.6rem; letter-spacing:2px; }
.vatk { display:inline-block; margin:.15rem .2rem; padding:.1rem .5rem; border-radius:5px;
  font-size:.62rem; font-family:'Fira Mono',monospace; background:rgba(255,30,80,0.12);
  color:#ff6080; border:1px solid rgba(255,30,80,0.25); }
::-webkit-scrollbar { width:5px; } ::-webkit-scrollbar-track { background:rgba(0,0,0,0.3); }
::-webkit-scrollbar-thumb { background:rgba(0,220,255,.35); border-radius:3px; }
footer { text-align:center; color:rgba(40,60,100,0.6); font-size:.65rem;
  padding:2.5rem 0; letter-spacing:2px; font-family:'Fira Mono',monospace;
  border-top:1px solid rgba(0,220,255,0.06); margin-top:2rem; }
.hdiv { height:1px; background:linear-gradient(90deg,transparent,rgba(0,220,255,0.4),rgba(180,0,255,0.4),transparent); margin:1.5rem 0; }
.ttoggle { position:fixed; top:1.2rem; right:1.5rem; z-index:100; }
@media(max-width:900px) { .grid-4{grid-template-columns:repeat(2,1fr)} .grid-2{grid-template-columns:1fr} header h1{font-size:1.8rem} }
</style>
</head>
<body>
<div id="particles-js"></div>
<button class="ttoggle btn" onclick="toggleTheme()" title="Toggle theme">&#9681; THEME</button>
<div class="wrap">

<header>
  <h1>AutoWiFiSniff Pro</h1>
  <div class="verBadge">v2.2 &mdash; HOLOGRAPHIC EDITION</div>
  <div class="hsub">NETWORK FORENSICS &amp; WIFI SECURITY ANALYSIS &nbsp;|&nbsp; __RPT__</div>
  <div class="hdate">Generated: __GEN__ &nbsp;&middot;&nbsp; Linux Only &nbsp;&middot;&nbsp; Fully Offline</div>
</header>

<div class="grid-4">
  <div class="card stat-card">
    <div class="stat-num">__PKTS__</div><div class="stat-label">Packets</div>
  </div>
  <div class="card stat-card">
    <div class="stat-num" style="background:linear-gradient(135deg,#ff1e50,#ff6a00);-webkit-background-clip:text;background-clip:text">__THREATS__</div>
    <div class="stat-label">Threats</div>
  </div>
  <div class="card stat-card">
    <div class="stat-num" style="background:linear-gradient(135deg,#b400ff,#7800cc);-webkit-background-clip:text;background-clip:text">__ML__</div>
    <div class="stat-label">ML Anomalies</div>
  </div>
  <div class="card stat-card">
    <div class="stat-num" style="__RNUMSTYLE__">__RISK__</div>
    <div class="stat-label">Risk Score</div>
  </div>
</div>

<div class="card" style="margin:1rem 0">
  <h2>Overall Risk Assessment</h2>
  <div class="risk-meter">
    <div class="risk-bar-wrap">
      <div class="risk-bar" id="riskBar" style="width:0%;background:linear-gradient(90deg,__RCOL1__,__RCOL2__);box-shadow:0 0 20px __RCOL1__88"></div>
    </div>
    <div class="risk-num" style="color:__RCOL1__">__RISK__</div>
    <span class="badge __RLABEL__" style="font-size:.85rem;padding:.35rem 1rem">__RLABEL__</span>
  </div>
  <div class="risk-desc">Composite risk from __THREATS__ detected threats &nbsp;&middot;&nbsp; Isolation Forest ML active &nbsp;&middot;&nbsp; 37+ detection rules</div>
</div>

<div class="grid-2">
  <div class="card">
    <h2>Threat Severity Distribution</h2>
    <canvas id="pieChart" height="225"></canvas>
  </div>
  <div class="card mc">
    <h2 class="mg">Top Attack Risk Scores</h2>
    <canvas id="barChart" height="225"></canvas>
  </div>
</div>

<div class="card" style="margin-top:1.3rem">
  <h2>Detected Threats</h2>
  <div class="filter-wrap">
    <input class="finput" type="text" id="fi" placeholder="&#128269; Filter threats..." oninput="filterTable()">
    <span class="rcount" id="rc"></span>
  </div>
  <div style="overflow-x:auto">
  <table class="tbl" id="tt">
    <thead><tr><th>#</th><th>Threat Name</th><th>Severity</th><th>Prob.</th><th>Risk</th><th>Target</th><th>Expand</th></tr></thead>
    <tbody>__TROWS__</tbody>
  </table></div>
</div>

__VULNSECT__
__MLSECT__
__PROTOSECT__

<div class="card" style="margin-top:1.3rem">
  <h2>Export &amp; Actions</h2>
  <div class="brow">
    <button class="btn" onclick="exportJSON()">&#8595; JSON Export</button>
    <button class="btn m" onclick="exportSIEM()">&#128225; SIEM / ELK</button>
    <button class="btn g" onclick="exportCSV()">&#128202; CSV Export</button>
    <button class="btn" onclick="window.print()">&#128424; Print</button>
    <button class="btn m" onclick="copyEmail()">&#9993; Email Template</button>
  </div>
</div>

<div class="hdiv"></div>
<footer>AutoWiFiSniff Pro v2.2 &nbsp;&middot;&nbsp; Standalone Network Forensics &nbsp;&middot;&nbsp; Python 3 &nbsp;&middot;&nbsp; Linux Only<br>
Powered by Scapy &middot; Rich &middot; scikit-learn &middot; ReportLab &middot; Matplotlib</footer>
</div>

<script>
particlesJS('particles-js',{particles:{number:{value:65},color:{value:'#00dcff'},shape:{type:'circle'},
opacity:{value:0.12,random:true},size:{value:1.8,random:true},
line_linked:{enable:true,distance:120,color:'#00dcff',opacity:0.07,width:1},
move:{enable:true,speed:0.5,random:true}},
interactivity:{detect_on:'canvas',events:{onhover:{enable:true,mode:'repulse'},onclick:{enable:true,mode:'bubble'}},
modes:{repulse:{distance:90},bubble:{distance:120,size:4,opacity:0.25}}},retina_detect:true});

window.addEventListener('load',function(){
  setTimeout(function(){ document.getElementById('riskBar').style.width='__RISK__%'; },400);
  updateRC();
});

var pie=new Chart(document.getElementById('pieChart'),{type:'doughnut',
  data:{labels:__PIELABELS__,datasets:[{data:__PIEVALS__,backgroundColor:__PIECOLS__,
    borderColor:'rgba(0,0,0,0.4)',borderWidth:2,hoverOffset:12}]},
  options:{plugins:{legend:{labels:{color:'rgba(160,200,240,0.8)',font:{family:'Fira Mono',size:11},padding:14}}},
    cutout:'62%',animation:{animateRotate:true,duration:1500}}});

var bar=new Chart(document.getElementById('barChart'),{type:'bar',
  data:{labels:__BARLABELS__,datasets:[{label:'Risk',data:__BARVALS__,
    backgroundColor:__BARCOLS__,borderRadius:7,borderSkipped:false}]},
  options:{indexAxis:'y',plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'rgba(100,140,200,0.7)',font:{family:'Fira Mono',size:9}},
      grid:{color:'rgba(255,255,255,0.04)'},max:100},
    y:{ticks:{color:'rgba(160,200,240,0.85)',font:{family:'Fira Mono',size:8.5}},
      grid:{color:'rgba(0,0,0,0)'}}}},animation:{duration:1200}});

function filterTable(){
  var q=document.getElementById('fi').value.toLowerCase();
  var rows=document.querySelectorAll('#tt tbody tr.mrow');
  var vis=0;
  rows.forEach(function(r){
    var ok=r.textContent.toLowerCase().indexOf(q)>=0;
    r.style.display=ok?'':'none';
    var d=document.getElementById('dr-'+r.dataset.idx);
    if(d) d.style.display='none';
    if(ok) vis++;
  });
  var el=document.getElementById('rc');
  if(el) el.textContent='Showing '+vis+' of '+rows.length+' threats';
}
function updateRC(){
  var rows=document.querySelectorAll('#tt tbody tr.mrow');
  var el=document.getElementById('rc');
  if(el) el.textContent='Showing '+rows.length+' of '+rows.length+' threats';
}
function toggleDetail(n){
  var r=document.getElementById('dr-'+n);
  var b=document.getElementById('eb-'+n);
  if(!r) return;
  var open=r.style.display==='table-row';
  r.style.display=open?'none':'table-row';
  if(b) b.textContent=open?'&#9660; Expand':'&#9650; Close';
}
var reportData=__JSONDATA__;
function exportJSON(){
  var b=new Blob([JSON.stringify(reportData,null,2)],{type:'application/json'});
  var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='autowifisniff_report.json';a.click();
}
function exportSIEM(){
  var s=reportData.siem_events||[];
  var b=new Blob([JSON.stringify(s,null,2)],{type:'application/json'});
  var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='siem_events.json';a.click();
}
function exportCSV(){
  var d=reportData.detections||[];
  var csv='Name,Severity,Risk,Probability,Target\\n';
  d.forEach(function(x){ csv+='"'+(x.name||'').replace(/"/g,'""')+'","'+x.severity+'",'+x.risk+','+x.possibility+'%,"'+(x.target||'').replace(/"/g,'""')+'"\\n'; });
  var b=new Blob([csv],{type:'text/csv'});
  var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='threats.csv';a.click();
}
function copyEmail(){
  var t='Security Alert - AutoWiFiSniff Pro v2.2\\nReport: __RPT__\\nThreats: __THREATS__\\nML Anomalies: __ML__\\nRisk: __RISK__/100 (__RLABEL__)\\nGenerated: __GEN__\\n\\nPlease review the full HTML report.';
  navigator.clipboard.writeText(t).then(function(){ alert('Email template copied!'); });
}
function toggleTheme(){document.body.classList.toggle('light');}
</script>
</body></html>"""


def _html_sub(html: str, token: str, value: str) -> str:
    """Safe single-token replacement. Never raises, always returns str."""
    try:
        return html.replace(token, str(value))
    except Exception:
        return html


def _build_threat_rows(detections: List[Detection]) -> str:
    rows = ""
    for idx, det in enumerate(sorted(detections, key=lambda x: x.risk, reverse=True), 1):
        sev = det.severity
        rc = ('#ff1e50' if det.risk >= 80 else '#ffa000' if det.risk >= 60
              else '#ffdc00' if det.risk >= 40 else '#00ff64')
        rows += (
            f'<tr class="mrow" data-idx="{idx}">'
            f'<td>{idx}</td>'
            f'<td><b>{det.name}</b></td>'
            f'<td><span class="badge {sev}">{sev}</span></td>'
            f'<td>{det.possibility}%</td>'
            f'<td><span class="rbar"><span class="rbarfill" style="width:{det.risk}%;background:{rc}"></span></span>'
            f'<b style="color:{rc}">{det.risk}</b></td>'
            f'<td style="max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{det.target[:55]}</td>'
            f'<td><button id="eb-{idx}" class="exbtn" onclick="toggleDetail({idx})">&#9660; Expand</button></td>'
            f'</tr>'
            f'<tr class="drow" id="dr-{idx}"><td colspan="7">'
            f'<b style="color:#00dcff">&#9654; Evidence:</b> {det.evidence}<br><br>'
            f'<b style="color:#ffa000">&#9654; Why Malicious:</b> {det.why}<br><br>'
            f'<b style="color:#00ff64">&#9654; Recommended Fix:</b> {det.fix}<br><br>'
            f'<b style="color:#b400ff">&#9654; Packet Numbers:</b> {det.packet_nos[:10] if det.packet_nos else "N/A"}'
        )
        if det.possible_attacks:
            atks = " &nbsp; ".join(f'<span class="vatk">{a}</span>' for a in det.possible_attacks)
            rows += f'<br><br><b style="color:#ff6080">&#9654; Possible Attacks:</b> {atks}'
        rows += '</td></tr>'
    return rows


def _build_vuln_section(detections: List[Detection]) -> str:
    """Build the Vulnerabilities Detected card."""
    dets = [d for d in detections if d.risk >= 40]
    if not dets:
        return ""
    cards = ""
    for det in sorted(dets, key=lambda x: x.risk, reverse=True)[:15]:
        sev = det.severity
        rc = ('#ff1e50' if det.risk >= 80 else '#ffa000' if det.risk >= 60
              else '#ffdc00' if det.risk >= 40 else '#00ff64')
        atks_html = ""
        if det.possible_attacks:
            atks_html = "".join(f'<span class="vatk">{a}</span> ' for a in det.possible_attacks)
        pathway_html = f'<div style="font-size:.72rem;color:rgba(100,150,200,0.7);margin:.4rem 0">Pathway: {det.pathway}</div>' if det.pathway else ""
        cards += f"""<div class="vcard">
  <h3>{det.name} &nbsp;<span class="badge {sev}">{sev}</span> &nbsp;<b style="color:{rc};font-size:.8rem">Risk: {det.risk}/100</b></h3>
  {pathway_html}
  <div style="font-size:.72rem;color:rgba(160,200,240,0.8);margin:.4rem 0"><b style="color:#00dcff">Evidence:</b> {det.evidence[:200]}</div>
  <div style="font-size:.72rem;color:rgba(160,200,240,0.8);margin:.4rem 0"><b style="color:#00ff64">Fix:</b> {det.fix[:200]}</div>
  {'<div style="margin-top:.5rem"><b style="font-size:.68rem;color:#ff6080;font-family:Orbitron,monospace">POSSIBLE ATTACKS:</b><br>' + atks_html + '</div>' if atks_html else ''}
</div>"""
    return f"""<div class="card" style="margin-top:1.3rem">
  <h2 class="mg">Vulnerabilities Detected</h2>
  <p style="font-size:.75rem;color:rgba(100,140,200,0.7);margin-bottom:.8rem;font-family:Fira Mono,monospace">
    Medium-to-Critical risk findings with attack pathways and remediation guidance.</p>
  {cards}
</div>"""


def _build_proto_section(packets: list) -> str:
    proto_counts: Dict[str, int] = defaultdict(int)
    for p in packets:
        proto_counts[_pkt_proto(p)] += 1
    if not proto_counts:
        return ""
    total = max(sum(proto_counts.values()), 1)
    cols = {'TCP':'#00dcff','UDP':'#b400ff','DNS':'#00ff8c','HTTP':'#ffa000',
             'TLS':'#ff1e50','ARP':'#ffee00','ICMP':'#ff6080','SSH':'#44ffcc',
             'FTP':'#ff8800','RDP':'#cc0055','802.11':'#8844ff','Other':'#557799'}
    rows = ""
    for proto, cnt in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:12]:
        pct = int(cnt / total * 100)
        col = cols.get(proto, '#557799')
        rows += (f'<tr><td><span class="pbadge" style="border:1px solid {col};color:{col}">{proto}</span></td>'
                 f'<td>{cnt}</td>'
                 f'<td style="width:55%"><div style="width:100%;height:6px;background:rgba(255,255,255,0.07);border-radius:3px;overflow:hidden">'
                 f'<div style="width:{pct}%;height:6px;background:{col};border-radius:3px"></div></div></td>'
                 f'<td style="text-align:right">{pct}%</td></tr>')
    return f"""<div class="card" style="margin-top:1.3rem">
  <h2>Protocol Distribution</h2>
  <div style="overflow-x:auto">
  <table class="tbl"><thead><tr><th>Protocol</th><th>Count</th><th>Distribution</th><th>%</th></tr></thead>
  <tbody>{rows}</tbody></table></div>
</div>"""


def _build_ml_section(anomalies: List[dict]) -> str:
    if not anomalies:
        return ""
    rows = ""
    for a in anomalies[:20]:
        rows += (f'<tr><td>{a.get("pkt_no","")}</td>'
                 f'<td>{a.get("src_ip","")}</td><td>{a.get("dst_ip","")}</td>'
                 f'<td>{a.get("proto","")}</td><td>{a.get("dport","")}</td>'
                 f'<td>{a.get("length","")}</td>'
                 f'<td class="as">{a.get("anomaly_score","")}</td></tr>')
    return f"""<div class="card mc" style="margin-top:1.2rem">
  <h2 class="mg">ML Anomaly Detection <small style="font-size:.62rem;color:#779">(Isolation Forest)</small></h2>
  <div style="overflow-x:auto">
  <table class="tbl"><thead><tr><th>Pkt</th><th>Src IP</th><th>Dst IP</th><th>Proto</th><th>DPort</th><th>Len</th><th>Score</th></tr></thead>
  <tbody>{rows}</tbody></table></div>
</div>"""


def _save_html(name: str, report_dir: Path, packets: list,
               detections: List[Detection], anomalies: List[dict]) -> Path:
    """Generate HTML dashboard using safe token replacement (no .format() = no CSS clash)."""
    path = report_dir / f"report_{name}.html"
    try:
        overall_risk = (min(100, sum(d.risk for d in detections) // max(len(detections), 1))
                        if detections else 0)
        rl = risk_label(overall_risk)

        sev_counts = Counter(d.severity for d in detections)
        sev_order  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        active_sevs = [s for s in sev_order if sev_counts.get(s, 0) > 0]
        pie_labels = json.dumps(active_sevs)
        pie_values = json.dumps([sev_counts[s] for s in active_sevs])
        pie_colors_map = {"CRITICAL":"#ff1e50","HIGH":"#ffa000","MEDIUM":"#ffdc00","LOW":"#00ff64","INFO":"#00dcff"}
        pie_colors = json.dumps([pie_colors_map[s] for s in active_sevs])

        top_n = sorted(detections, key=lambda d: d.risk, reverse=True)[:10]
        bar_labels = json.dumps([d.name[:26] for d in top_n])
        bar_values = json.dumps([d.risk for d in top_n])
        bar_cols_map = {"CRITICAL":"#ff1e50","HIGH":"#ffa000","MEDIUM":"#ffdc00","LOW":"#00ff64","INFO":"#00dcff"}
        bar_colors  = json.dumps([bar_cols_map.get(d.severity, "#00dcff") for d in top_n])

        rc1, rc2 = (("#ff1e50","#cc0044") if overall_risk >= 80 else
                    ("#ffa000","#cc6600") if overall_risk >= 60 else
                    ("#ffdc00","#cc9900") if overall_risk >= 40 else
                    ("#00ff64","#00cc44"))

        rnum_style = (f"background:linear-gradient(135deg,{rc1},{rc2});"
                      f"-webkit-background-clip:text;background-clip:text;"
                      f"-webkit-text-fill-color:transparent")

        j = json.dumps({
            "report_name": name, "total_packets": len(packets),
            "threats": len(detections), "overall_risk": overall_risk,
            "detections": [d.to_dict() for d in detections],
            "siem_events": [{"name": d.name, "severity": d.severity,
                             "risk": d.risk, "evidence": d.evidence, "fix": d.fix}
                            for d in detections],
        }, default=str)

        html = _HTML_TEMPLATE
        html = _html_sub(html, "__RPT__",        name)
        html = _html_sub(html, "__GEN__",        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        html = _html_sub(html, "__PKTS__",       str(len(packets)))
        html = _html_sub(html, "__THREATS__",    str(len(detections)))
        html = _html_sub(html, "__ML__",         str(len(anomalies)))
        html = _html_sub(html, "__RISK__%",      f"{overall_risk}%")
        html = _html_sub(html, "__RISK__",       str(overall_risk))
        html = _html_sub(html, "__RLABEL__",     rl)
        html = _html_sub(html, "__RCOL1__",      rc1)
        html = _html_sub(html, "__RCOL2__",      rc2)
        html = _html_sub(html, "__RNUMSTYLE__",  rnum_style)
        html = _html_sub(html, "__TROWS__",      _build_threat_rows(detections))
        html = _html_sub(html, "__MLSECT__",     _build_ml_section(anomalies))
        html = _html_sub(html, "__PROTOSECT__",  _build_proto_section(packets))
        html = _html_sub(html, "__VULNSECT__",   _build_vuln_section(detections))
        html = _html_sub(html, "__PIELABELS__",  pie_labels)
        html = _html_sub(html, "__PIEVALS__",    pie_values)
        html = _html_sub(html, "__PIECOLS__",    pie_colors)
        html = _html_sub(html, "__BARLABELS__",  bar_labels)
        html = _html_sub(html, "__BARVALS__",    bar_values)
        html = _html_sub(html, "__BARCOLS__",    bar_colors)
        html = _html_sub(html, "__JSONDATA__",   j)

        path.write_text(html, encoding="utf-8")
    except Exception as e:
        # Absolute last-resort fallback — always write a valid file
        path.write_text(
            f"<!DOCTYPE html><html><head><title>AutoWiFiSniff Pro v2.2</title></head>"
            f"<body style='background:#02020e;color:#00dcff;font-family:monospace;padding:2rem'>"
            f"<h1>AutoWiFiSniff Pro v2.2 &mdash; {name}</h1>"
            f"<p style='color:#ff1e50'>Render note: {e}</p>"
            f"<pre style='color:#aaa'>{json.dumps({'threats':len(detections),'risk':0},indent=2)}</pre>"
            f"</body></html>",
            encoding="utf-8",
        )
    return path

# SECTION 17: MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def graceful_exit(sig=None, frame=None):
    console.print("\n\n[bold cyan][ AutoWiFiSniff Pro ] Goodbye! Stay safe.[/bold cyan]\n")
    sys.exit(0)


def main():
    """Main application loop."""
    # Register SIGINT
    signal.signal(signal.SIGINT, graceful_exit)

    # Startup
    print_logo()
    check_dependencies()

    while True:
        choice = show_main_menu()

        if choice == 1:
            try:
                run_pcap_option()
            except Exception as e:
                console.print(f"\n[red][!] Error: {e}[/red]\n")
            finally:
                Prompt.ask("\n[dim]Press Enter to return to menu…[/dim]", default="")

        elif choice == 2:
            try:
                run_live_capture()
            except Exception as e:
                console.print(f"\n[red][!] Error: {e}[/red]\n")
            finally:
                Prompt.ask("\n[dim]Press Enter to return to menu…[/dim]", default="")

        elif choice == 3:
            show_help()
            Prompt.ask("\n[dim]Press Enter to return to menu…[/dim]", default="")

        elif choice == 4:
            graceful_exit()


if __name__ == "__main__":
    main()
