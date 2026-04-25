from scapy.all import *
from datetime import datetime
import socket
from urllib.parse import urlparse

# Suspicious IP tracker
ip_count = {}

def detect_suspicious(ip):
    if ip not in ip_count:
        ip_count[ip] = 0
    ip_count[ip] += 1
    
    if ip_count[ip] > 20:
        print(f"🚨 ALERT: Possible DoS attack from {ip}")

def process_packet(packet):
    print("\n" + "="*60)
    print(f"⏰ Time: {datetime.now()}")

    # IP Layer
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"🌐 Source IP      : {src}")
        print(f"🌐 Destination IP : {dst}")

        detect_suspicious(src)

    # TCP
    if packet.haslayer(TCP):
        print("📡 Protocol: TCP")
        print(f"🔢 Src Port: {packet[TCP].sport}")
        print(f"🔢 Dst Port: {packet[TCP].dport}")

    # UDP
    elif packet.haslayer(UDP):
        print("📡 Protocol: UDP")
        print(f"🔢 Src Port: {packet[UDP].sport}")
        print(f"🔢 Dst Port: {packet[UDP].dport}")

    # ICMP
    elif packet.haslayer(ICMP):
        print("📡 Protocol: ICMP (Ping)")

    # HTTP (Raw data)
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        
        try:
            payload = payload.decode(errors='ignore')
            
            # Detect HTTP Requests
            if "GET" in payload or "POST" in payload:
                print("🌍 HTTP Request Found!")
                
                lines = payload.split("\n")
                print(f"➡️ {lines[0]}")  # GET /index.html
                
                for line in lines:
                    if "Host:" in line:
                        print(f"🌐 Host: {line}")
            
        except:
            pass

    # DNS
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        print("🔎 DNS Query Detected!")
        print(f"🌍 Domain: {packet[DNSQR].qname.decode()}")

def run_interactive_mode():
    print("\n" + "="*60)
    print("🧪  INTERACTIVE TEST MODE")
    print("    Enter packet details below to simulate and analyze.")
    print("="*60)

    while True:
        print("\n--- New Packet ---")
        src = input("📌 Source IP       (e.g. 192.168.1.10) : ").strip()
        dst = input("📌 Destination IP  (e.g. 8.8.8.8)      : ").strip()

        print("📌 Protocol options: TCP | UDP | ICMP")
        proto = input("📌 Protocol        : ").strip().upper()

        pkt = IP(src=src, dst=dst)

        if proto == "TCP":
            sport = input("📌 Source Port     (e.g. 54321)        : ").strip()
            dport = input("📌 Destination Port(e.g. 80)            : ").strip()
            pkt /= TCP(sport=int(sport), dport=int(dport))

        elif proto == "UDP":
            sport = input("📌 Source Port     (e.g. 54321)        : ").strip()
            dport = input("📌 Destination Port(e.g. 53)            : ").strip()
            pkt /= UDP(sport=int(sport), dport=int(dport))

        elif proto == "ICMP":
            pkt /= ICMP()

        else:
            print("❌ Unknown protocol. Please enter TCP, UDP, or ICMP.")
            continue

        process_packet(pkt)

        again = input("\n🔁 Test another packet? [y/N]: ").strip().lower()
        if again != "y":
            print("\n✅ Test mode ended.")
            break


def run_url_mode():
    print("\n" + "="*60)
    print("🌐  URL TEST MODE")
    print("    Enter a URL — the script will resolve & analyze it.")
    print("="*60)

    while True:
        url = input("\n🔗 Enter URL (e.g. https://www.google.com): ").strip()

        # Auto-add scheme if missing
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        parsed = urlparse(url)
        scheme   = parsed.scheme                          # http or https
        hostname = parsed.hostname or ""
        path     = parsed.path or "/"
        port     = parsed.port or (443 if scheme == "https" else 80)

        if not hostname:
            print("❌ Could not parse hostname. Try again.")
            continue

        # Resolve domain → IP
        print(f"\n🔍 Resolving {hostname} ...")
        try:
            dst_ip = socket.gethostbyname(hostname)
            print(f"✅ Resolved: {hostname}  →  {dst_ip}")
        except socket.gaierror as e:
            print(f"❌ DNS resolution failed: {e}")
            again = input("\n🔁 Try another URL? [y/N]: ").strip().lower()
            if again != "y":
                break
            continue

        # Build simulated HTTP GET packet
        src_ip  = "192.168.1.100"   # simulated local machine
        payload = (f"GET {path} HTTP/1.1\r\n"
                   f"Host: {hostname}\r\n"
                   f"Connection: close\r\n\r\n")

        pkt = (IP(src=src_ip, dst=dst_ip) /
               TCP(sport=54321, dport=port) /
               Raw(load=payload.encode()))

        print(f"\n📦 Simulated Packet Info:")
        print(f"   Scheme   : {scheme.upper()}")
        print(f"   Host     : {hostname}")
        print(f"   Path     : {path}")
        print(f"   Dst Port : {port}  ({'HTTPS' if port == 443 else 'HTTP'})")
        print(f"   Dst IP   : {dst_ip}")

        process_packet(pkt)

        again = input("\n🔁 Test another URL? [y/N]: ").strip().lower()
        if again != "y":
            print("\n✅ URL test mode ended.")
            break

# Main Menu — keep prompting until valid input
print("\n" + "="*60)
print("🚀  Network Packet Analyzer")
print("="*60)
print("  [1] Live Sniffing       (requires Npcap + Admin)")
print("  [2] Interactive Test    (enter IPs & ports manually)")
print("  [3] URL Test            (enter a URL like www.google.com)")
print("─"*60)

while True:
    mode = input("Choose mode [1/2/3]: ").strip()
    if mode in ("1", "2", "3"):
        break
    print("❌ Invalid choice. Please enter 1, 2, or 3.")

if mode == "2":
    run_interactive_mode()
elif mode == "3":
    run_url_mode()

else:
    print("\n🚀 Advanced Sniffer Started...\n")
    print("📌 Note: Press Ctrl+C to stop capturing.\n")

    packets = []
    try:
        packets = sniff(prn=process_packet, store=True)
    except RuntimeError as e:
        err = str(e).lower()
        if "winpcap" in err or "layer 2" in err or "npcap" in err or "libpcap" in err:
            print("⚠️  Npcap/libpcap not available — switching to Layer 3 socket.\n")
            try:
                l3sock = conf.L3socket()
                packets = sniff(prn=process_packet, store=True, opened_socket=l3sock)
            except KeyboardInterrupt:
                print("\n✅ Capture stopped by user.")
            except Exception as e2:
                print(f"❌ Layer 3 sniffing also failed: {e2}")
                print("💡 Install Npcap from https://npcap.com and run as Administrator.")
                print("💡 Or use mode [2] Interactive Test instead.")
        else:
            raise
    except KeyboardInterrupt:
        print("\n✅ Capture stopped by user.")

    if packets:
        wrpcap("capture.pcap", packets)
        print(f"\n💾 Saved {len(packets)} packets to capture.pcap")
    else:
        print("\n⚠️  No packets captured — nothing saved.")