#!/usr/bin/env python3

import os
import platform
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional, List

try:
    from scapy.all import (
        sniff,
        get_if_list,
        conf,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        Raw,
        wrpcap,
    )
except Exception as e:
    print("Error: scapy is required. Install with: pip install scapy")
    print("Import error:", e)
    sys.exit(1)


def is_admin() -> bool:
    if platform.system() == "Windows":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def check_wifi_connection() -> Optional[str]:
    """Best-effort: return SSID or None."""
    system = platform.system()
    try:
        if system == "Windows":
            # netsh output parsing
            proc = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                  capture_output=True, text=True)
            out = proc.stdout
            if not out:
                return None
            state = None
            ssid = None
            for line in out.splitlines():
                if ":" in line:
                    k, v = [s.strip() for s in line.split(":", 1)]
                    if k.lower() == "state":
                        state = v.lower()
                    if k.lower() == "ssid":
                        ssid = v
            if state == "connected":
                return ssid or "CONNECTED"
        elif system == "Linux":
            proc = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            ssid = proc.stdout.strip()
            if ssid:
                return ssid
            if os.path.exists("/proc/net/wireless"):
                with open("/proc/net/wireless", "r") as f:
                    lines = f.readlines()
                if len(lines) > 2:
                    return "WIRELESS_INTERFACE_PRESENT"
        elif system == "Darwin":
            # macOS: try networksetup
            proc = subprocess.run(["/usr/sbin/networksetup", "-getairportnetwork", "en0"],
                                  capture_output=True, text=True)
            out = proc.stdout.strip()
            if "Current Wi-Fi Network" in out:
                parts = out.split(": ", 1)
                if len(parts) == 2:
                    return parts[1].strip()
    except Exception:
        pass
    return None


def detect_iface_guess() -> Optional[str]:
    """Try to guess a wireless interface name (best-effort)."""
    system = platform.system()
    try:
        if system == "Linux":
            if os.path.exists("/proc/net/wireless"):
                with open("/proc/net/wireless", "r") as f:
                    lines = f.readlines()
                for ln in lines[2:]:
                    if ln.strip():
                        iface = ln.split()[0].strip(":")
                        return iface
            proc = subprocess.run(["iw", "dev"], capture_output=True, text=True)
            for line in proc.stdout.splitlines():
                if line.strip().startswith("Interface"):
                    return line.split()[1].strip()
        elif system == "Darwin":
            proc = subprocess.run(["/usr/sbin/networksetup", "-listallhardwareports"],
                                  capture_output=True, text=True)
            lines = proc.stdout.splitlines()
            for i, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    for j in range(i, min(i + 4, len(lines))):
                        if "Device" in lines[j]:
                            return lines[j].split(":")[1].strip()
        elif system == "Windows":
            # Use netsh to find interface name
            proc = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            out = proc.stdout
            for line in out.splitlines():
                if line.strip().startswith("Name"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except Exception:
        pass
    # fallback to scapy default interface
    try:
        return conf.iface
    except Exception:
        return None


def fmt_payload(payload_bytes: bytes, max_len: int = 120) -> str:
    if not payload_bytes:
        return ""
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = repr(payload_bytes)
    text_preview = text if len(text) <= max_len else text[:max_len] + "..."
    hex_preview = payload_bytes.hex()[: max_len * 2]
    return f"{text_preview} | {hex_preview}"


# Global collectors
captured_packets: List = []
proto_counter = Counter()
talkers = Counter()


def packet_printer(pkt):
    """Pretty-print important fields and record stats."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    src = dst = proto = "-"
    sport = dport = "-"
    payload_info = ""

    try:
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = ip.proto
            if TCP in pkt:
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
                if Raw in pkt:
                    payload_info = fmt_payload(bytes(pkt[Raw].load))
                proto_name = "TCP"
            elif UDP in pkt:
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport
                if Raw in pkt:
                    payload_info = fmt_payload(bytes(pkt[Raw].load))
                proto_name = "UDP"
            else:
                proto_name = f"IP(proto={proto})"
                if Raw in pkt:
                    payload_info = fmt_payload(bytes(pkt[Raw].load))
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            src = ip6.src
            dst = ip6.dst
            proto_name = "IPv6"
            if Raw in pkt:
                payload_info = fmt_payload(bytes(pkt[Raw].load))
        else:
            # non-IP (ethernet) frames
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                src = eth.src
                dst = eth.dst
                proto_name = f"ETH-{hex(eth.type)}"
            else:
                proto_name = pkt.summary()
            if Raw in pkt:
                payload_info = fmt_payload(bytes(pkt[Raw].load))
    except Exception as e:
        proto_name = f"PARSE_ERR"
        payload_info = f"ERR:{e}"

    line = f"[{ts}] {src}:{sport} -> {dst}:{dport} | {proto_name} | payload: {payload_info}"
    print(line)

    # record
    captured_packets.append(pkt)
    proto_counter.update([proto_name])
    talkers.update([f"{src} -> {dst}"])


def start_sniffing(iface: str, bpf: Optional[str], count: int, timeout: Optional[int]):
    """Attempt layer-2 sniff (pcap) first; if it fails, fall back to L3 IP sniffing."""
    # Try layer-2 sniffing using scapy's sniff (which uses pcap if available)
    try:
        print("Trying Layer-2 sniffing (requires pcap provider like Npcap/WinPcap)...")
        sniff(iface=iface, prn=packet_printer, filter=bpf if bpf else None,
              store=False, count=count if count > 0 else 0, timeout=timeout if timeout else None)
        return
    except Exception as e:
        err = str(e).lower()
        if any(k in err for k in ("no libpcap provider", "winpcap", "npcap", "layer 2")):
            print("Layer-2 sniff failed (pcap missing). Falling back to Layer-3 (IP-only) sniffing.")
            conf.use_pcap = False
            try:
                sniff(iface=iface, prn=packet_printer, store=False,
                      count=count if count > 0 else 0, timeout=timeout if timeout else None,
                      lfilter=lambda p: IP in p or IPv6 in p)
                return
            except Exception as e2:
                print("Layer-3 sniffing also failed:", e2)
                sys.exit(1)
        else:
            print("Unexpected sniff error:", e)
            sys.exit(1)


def print_summary(save_pcap: Optional[str]):
    print("\n--- Capture Summary ---")
    print(f"Total packets captured: {len(captured_packets)}")
    if proto_counter:
        print("\nProtocol counts:")
        for proto, cnt in proto_counter.most_common(10):
            print(f"  {proto}: {cnt}")
    if talkers:
        print("\nTop talkers:")
        for t, cnt in talkers.most_common(10):
            print(f"  {t}: {cnt}")
    if save_pcap and captured_packets:
        try:
            wrpcap(save_pcap, captured_packets)
            print(f"\nSaved capture to: {save_pcap}")
        except Exception as e:
            print("Failed to save pcap:", e)


def main():
    if not is_admin():
        print("ERROR: Run this script as Administrator/root to capture packets.")
        print("On Windows: run the terminal or IDE as Administrator. On Linux/macOS: use sudo.")
        sys.exit(1)

    print("=== Educational Packet Sniffer ===")
    print("⚠️  Ethical reminder: Use only on networks you own or with explicit permission.\n")

    ssid = check_wifi_connection()
    print("Wi-Fi SSID detected:" if ssid else "Wi-Fi not detected or unknown:", ssid or "-")

    guessed = detect_iface_guess()
    if guessed:
        print("Guessed interface:", guessed)

    ifaces = get_if_list()
    print("\nAvailable interfaces:")
    for idx, itf in enumerate(ifaces, start=1):
        print(f"  {idx}. {itf}")

    choice = input("\nEnter interface name or number to sniff (or press Enter to use guessed): ").strip()
    if not choice and guessed:
        iface = guessed
    else:
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                iface = ifaces[idx]
            else:
                print("Invalid index. Exiting.")
                return
        else:
            iface = choice
            if iface not in ifaces:
                print("Specified interface not found in the list. Exiting.")
                return

    bpf = input("Enter BPF filter (e.g., 'tcp', 'udp', 'port 80') or leave blank: ").strip() or None
    try:
        cnt = int(input("Max packets to capture (0 = unlimited): ").strip() or "0")
    except Exception:
        cnt = 0
    try:
        timeout = int(input("Timeout in seconds (0 = none): ").strip() or "0")
    except Exception:
        timeout = 0
    save_pcap = input("Save capture to pcap file? Enter filename (or leave blank): ").strip() or None

    print(f"\nStarting capture on interface: {iface}")
    print("Press Ctrl+C to stop early.\n")

    try:
        start_sniffing(iface=iface, bpf=bpf, count=cnt, timeout=timeout if timeout > 0 else None)
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print("Sniffing error:", e)

    print_summary(save_pcap)


if __name__ == "__main__":
    main()
