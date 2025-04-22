#!/usr/bin/env python3

import socket
import os
import requests
import threading
from scapy.all import ARP, Ether, srp, IP, TCP, sr1

# ------------------------- Live Host Detection ------------------------- #
def scan_network(ip_range):
    """Scan for active hosts on the network."""
    print("\nScanning for active devices...")
    try:
        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=2, verbose=False)

        if not answered:
            print("[-] No active devices found.")
            return

        print("\nIP Address\t\tMAC Address")
        print("-" * 40)
        for sent, received in answered:
            print(f"{received.psrc}\t\t{received.hwsrc}")

    except Exception as e:
        print(f"[-] Error scanning network: {e}")

# ------------------------- Port Scanning ------------------------- #
def scan_ports(ip, ports):
    """Scan for open ports on a target IP."""
    print(f"\nScanning {ip} for open ports...")
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    print(f"[+] Port {port} is open")
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

# ------------------------- Service Detection (Banner Grabbing) ------------------------- #
def grab_banner(ip, port):
    """Detect services running on open ports."""
    try:
        with socket.socket() as sock:
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b"GET / HTTP/1.1\r\n\r\n")
            banner = sock.recv(1024).decode().strip()
            print(f"[+] Port {port} banner: {banner}")
    except:
        print(f"[-] No response from port {port}")

# ------------------------- OS Detection ------------------------- #
def detect_os(ip):
    """Guess the OS type using TTL values."""
    try:
        if os.name == "nt":  # Windows
            response = os.popen(f"ping -n 1 {ip}").read()
        else:  # Linux/macOS
            response = os.popen(f"ping -c 1 {ip}").read()

        if "ttl=64" in response:
            print("[+] OS: Linux-based (Ubuntu, Debian, etc.)")
        elif "ttl=128" in response:
            print("[+] OS: Windows-based")
        else:
            print("[-] OS detection failed")
    except Exception as e:
        print(f"[-] Error detecting OS: {e}")

# ------------------------- Stealth Scanning (SYN Scan) ------------------------- #
def stealth_scan(ip, port):
    """Perform a stealth SYN scan to bypass firewalls."""
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=False)

        if response and response.haslayer(TCP):
            if response[TCP].flags == 18:  # SYN-ACK Response
                print(f"[+] Port {port} is open (stealth mode)")
            elif response[TCP].flags == 20:  # RST-ACK Response
                print(f"[-] Port {port} is closed (stealth mode)")
        else:
            print(f"[*] Port {port} may be filtered (no response)")

    except Exception as e:
        print(f"[-] Error in stealth scan: {e}")

# ------------------------- Check for Vulnerabilities ------------------------- #
def check_vulnerability(service):
    """Look up known vulnerabilities for a detected service."""
    try:
        url = f"https://www.exploit-db.com/search?q={service}"
        response = requests.get(url, timeout=5)
        if "No Results" not in response.text:
            print(f"[+] Possible exploits found for {service}!")
        else:
            print(f"[-] No known exploits for {service}")
    except Exception as e:
        print(f"[-] Error checking vulnerabilities: {e}")

# ------------------------- Multi-Threading for Faster Scanning ------------------------- #
def multi_scan(ip, ports):
    """Perform multi-threaded port scanning for speed."""

    def scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, port)) == 0:
                    print(f"[+] Port {port} is open")
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")

    threads = []
    for port in ports:
        t = threading.Thread(target=scan, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# ------------------------- Main Execution ------------------------- #
if __name__ == "__main__":
    target_ip = input("Enter target IP (or network range): ").strip()

    print("\nChoose scan type:")
    print("1. Live Host Scan")
    print("2. Port Scan")
    print("3. Service Detection")
    print("4. OS Detection")
    print("5. Stealth Scan")
    print("6. Full Scan")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        scan_network(target_ip + "/24")
    elif choice == "2":
        ports = [21, 22, 23, 80, 443, 8080]
        scan_ports(target_ip, ports)
    elif choice == "3":
        grab_banner(target_ip, 80)
    elif choice == "4":
        detect_os(target_ip)
    elif choice == "5":
        stealth_scan(target_ip, 80)
    elif choice == "6":
        print("\n[+] Running Full Network Scan...")
        scan_network(target_ip + "/24")
        ports = [21, 22, 23, 80, 443, 8080]
        multi_scan(target_ip, ports)
        grab_banner(target_ip, 80)
        detect_os(target_ip)
    else:
        print("Invalid choice. Exiting.")
