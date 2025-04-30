"""
ObsiLAN - Local network scanner with Markdown export for Obsidian
Auteur : DevCrown
Description : Scans active hosts, ports, SMB, web fingerprint, and generates reports in macro with Obsidian graphical view.
"""

import shutil
import sys
import socket
import fcntl
import struct
import os
import ipaddress
import subprocess
import re
import platform

YELLOW = "\033[33m"
NORMAL = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"

class Machine:
    def __init__(self, ip, mac=None, vendor=None):
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.netbios = None
        self.os_details = None
        self.network_distance = None
        self.services = []
        self.smb_shares = []
        self.web_fingerprint = {}
        self.nmap_raw = None       
        self.smb_raw = None        
        self.whatweb_raw = None    

    def __str__(self):
        out = (
            f"Machine :\n"
            f"  IP       : {self.ip}\n"
            f"  MAC      : {self.mac or 'Unknown'}\n"
            f"  Fabricant: {self.vendor or 'Unknown'}\n"
            f"  NetBIOS  : {self.netbios or 'Unknown'}\n"
        )
        out += f"  OS : {self.os_details or 'Unknown'}\n"
        out += f"  Network distance : {self.network_distance or 'Unknown'}\n"
        if self.services:
            out += "  Services :\n"
            for s in self.services:
                out += f"    - {s['port']}/{s['proto']} {s['name']} ({s['product']})\n"
        if self.smb_shares:
            out += "  Shares SMB :\n"
            for s in self.smb_shares:
                out += f"    - {s['name']} ({s['type']})\n"
        if self.web_fingerprint:
            out += "  Web Fingerprint :\n"
            for url, techs in self.web_fingerprint.items():
                out += f"    - {url} :\n"
                for tech in techs:
                    out += f"        • {tech}\n"
        return out

##################
## NETWORK INIT ##
##################
def get_interface_ip_netmask(interface: str):
    """ Retrieve IP address and net mask """
    try:
        if platform.system() == "Darwin":
            output = subprocess.getoutput(f"ifconfig {interface}")
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', output)
            mask_match = re.search(r'netmask 0x([0-9a-f]+)', output)
            if ip_match and mask_match:
                ip = ip_match.group(1)
                mask_hex = int(mask_match.group(1), 16)
                mask = socket.inet_ntoa(mask_hex.to_bytes(4, 'big'))
                return ip, mask
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', interface.encode('utf-8'))
            )[20:24])
            netmask = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(),
                0x891b,  # SIOCGIFNETMASK
                struct.pack('256s', interface.encode('utf-8'))
            )[20:24])
            return ip, netmask
    except Exception as e:
        print(f"{RED}[NETMASK] [ERROR] {e}")
        return None, None

def get_network_range(interface='eth0'):
    """ return CIDR """
    ip, netmask = get_interface_ip_netmask(interface)
    if ip and netmask:
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception as e:
            print(f"{RED}[CIDR] [ERROR] {e}")
    return None

def get_active_interface():
    """ Net Interface """
    try:
        if platform.system() == "Darwin":  # macOS
            output = subprocess.getoutput("route get default | grep interface")
            match = re.search(r'interface: (\w+)', output)
            if match:
                return match.group(1)
            else:
                return "en0"  # défaut pour mac
        else:  # Linux
            interfaces = os.listdir('/sys/class/net/')
            for iface in interfaces:
                if iface != 'lo':
                    return iface
            return 'eth0'  # défaut Linux
    except Exception as e:
        print(f"{RED}[INTERFACE] [ERROR] {e}")
        return 'eth0'

##########
## NMAP ##
##########
def scan_nmap_basic(network_range):
    """ Scan nmap """
    try:
        result = subprocess.getoutput(f"timeout 60s sudo nmap -sn {network_range}")

        return result
    except Exception as e:
        return None

def parse_nmap_basic(nmap_output):
    """ nmap parsing """
    machines = []
    current = {}

    for line in nmap_output.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            if current:
                machines.append(current)
                current = {}
            ip_match = re.search(r'Nmap scan report for (.+)', line)
            if ip_match:
                current['ip'] = ip_match.group(1)
                print(YELLOW + "[FOUND] " + NORMAL + ip_match.group(1))
        elif line.startswith("MAC Address:"):
            mac_vendor_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)', line)
            if mac_vendor_match:
                current['mac'] = mac_vendor_match.group(1)
                current['vendor'] = mac_vendor_match.group(2)
            else:
                mac_only_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})', line)
                if mac_only_match:
                    current['mac'] = mac_only_match.group(1)
                    current['vendor'] = None
    if current:
        machines.append(current)
    return machines

def scan_ports_nmap(ip):
    """ nmap scan port """
    try:
        cmd = f"sudo nmap -sV -O --max-retries 1 --host-timeout 60s {ip}"
        output = subprocess.getoutput(cmd)
        services = []
        os_details = None
        network_distance = None
        capture = False
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("PORT"):
                capture = True
                continue
            elif capture and line == "":
                capture = False
            # Parse services
            if capture and line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0]
                    name = parts[1]
                    product = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    if '/' in port_proto:
                        port, proto = port_proto.split('/')
                        services.append({
                            "port": port,
                            "proto": proto,
                            "name": name,
                            "product": product
                        })
            # Parse OS details
            if line.startswith("OS details:"):
                os_details = line.replace("OS details:", "").strip()
            # Parse network distance
            if line.startswith("Network Distance:"):
                network_distance = line.replace("Network Distance:", "").strip()
        return services, output, os_details, network_distance
    except Exception as e:
        print(f"{RED}[NMAP] [ERROR] {ip} : {e}")
        return [], "", None, None

#############
## NETBIOS ##
#############
def get_netbios_names(network_range):
    try:
        result = subprocess.getoutput(f"timeout 60s nbtscan {network_range}")
        netbios_map = {}
        for line in result.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                name = parts[1]
                netbios_map[ip] = name
        return netbios_map
    except Exception as e:
        print(f"{RED}[NBTSCAN] [ERROR] {e}")
        return {}

###############
## SMBCLIENT ##
###############
def scan_smb_shares(ip):
    try:
        output = subprocess.getoutput(f"timeout 60s smbclient -L //{ip} -N")
        shares = []
        capture = False
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Sharename") or line.startswith("Nom de partage"):
                capture = True
                continue
            if capture:
                if line == "" or line.startswith("Server") or line.startswith("Workgroup"):
                    break
                if line.startswith("------"): 
                    continue
                if any(keyword in line.lower() for keyword in ["reconnecting", "unable", "failed", "smb1", "disabled", "support"]):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    shares.append({
                        "name": share_name,
                        "type": share_type
                    })
        return shares, output
    except Exception as e:
        print(f"{RED}[SMBSCAN] [ERROR] {ip} : {e}")
        return [], ""
    
#############
## WHATWEB ##
#############
def scan_with_whatweb_ports(machine):
    fingerprints = {}
    raw_outputs = []
    for svc in machine.services:
        port = svc["port"]
        url = f"http://{machine.ip}:{port}"
        print(f"{YELLOW}[WHATWEB] {NORMAL}{url}")
        try:
            output = subprocess.getoutput(f"timeout 60s whatweb --no-errors --color=never {url}")
            raw_outputs.append(f"### {url} ###\n{output}\n")
            matches = re.findall(r'\[([^\]]+)\]', output)
            techs = []
            for match in matches:
                for f in match.split(','):
                    f = f.strip()
                    if f and f not in techs:
                        techs.append(f)
            if techs:
                fingerprints[url] = techs
        except Exception as e:
            raw_outputs.append(f"### {url} ###\nError : {e}\n")
    machine.web_fingerprint = fingerprints
    machine.whatweb_raw = "\n".join(raw_outputs)

def get_next_scan_directory(base_dir="scans"):
        """ Create export directory """
        os.makedirs(base_dir, exist_ok=True)
        existing = [d for d in os.listdir(base_dir) if d.startswith("scan_") and os.path.isdir(os.path.join(base_dir, d))]
        next_id = len(existing)
        scan_dir = os.path.join(base_dir, f"scan_{next_id}")
        os.makedirs(os.path.join(scan_dir, "Machines"), exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "Report NMAP"), exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "Report SMB"), exist_ok=True)
        os.makedirs(os.path.join(scan_dir, "Report WHATWEB"), exist_ok=True)
        return scan_dir

try:
    # If sudo
    if os.geteuid() != 0:
        print("This script must be run with administrator rights (sudo)")
        sys.exit(1)
    print(f"{YELLOW}[DEBUG] PATH utilisé : {os.environ.get('PATH')}{NORMAL}")
    print(f"{YELLOW}[DEBUG] whereis whatweb : {shutil.which('whatweb')}{NORMAL}")

    # Requirements
    tools = ["nmap", "nbtscan", "smbclient", "whatweb"]
    for tool in tools:
        path = shutil.which(tool)
        if not path:
            print(f"{RED}[ERROR] {tool} missing")
            sys.exit()

    # IP
    interface = get_active_interface()
    plage = get_network_range(interface)

    # IP, MAC, manufacturer avec nmap
    output = scan_nmap_basic(plage)
    if output == None:
        print(f"{RED}[NMAP] [ERROR] nothing")
        sys.exit()
    machines = parse_nmap_basic(output)
    if not machines:
        print(RED + "No machine detected")
        sys.exit()

    objets_machine = []
    for m in machines:
        objets_machine.append(Machine(m.get("ip"), m.get("mac"), m.get("vendor")))

    netbios_dict = get_netbios_names(plage)

    for machine in objets_machine:
        if machine.ip in netbios_dict:
            machine.netbios = netbios_dict[machine.ip]
    cnt = 0
    for machine in objets_machine:
        cnt += 1
        print(f"{YELLOW}[SCAN] {NORMAL}{cnt}/{len(objets_machine)} {machine.ip}")
        print(f"{YELLOW}[NMAP] {NORMAL}{machine.ip}")
        services, raw_output, os_details, net_distance = scan_ports_nmap(machine.ip)
        machine.services = services
        machine.nmap_raw = raw_output
        machine.os_details = os_details
        machine.network_distance = net_distance
        
        print(f"{YELLOW}[SMBCLIENT] {NORMAL}{machine.ip}")
        shares, smb_raw = scan_smb_shares(machine.ip)
        machine.smb_shares = shares
        machine.smb_raw = smb_raw
    
        print(f"{YELLOW}[WHATWEB] {NORMAL}{machine.ip}")
        scan_with_whatweb_ports(machine)

    for m in objets_machine:
        print(m)

    export_dir = get_next_scan_directory()

    for machine in objets_machine:
        ip = machine.ip.replace(":", "_")

        if machine.services:
            nmap_path = os.path.join(export_dir, "Report NMAP", f"NMAP {ip}.md")
            with open(nmap_path, "w") as f:
                f.write(f"# raw report NMAP for {machine.ip}\n\n")
                f.write("```\n")
                f.write(machine.nmap_raw or "Unknown\n")
                f.write("\n```")

        if machine.smb_shares:
            smb_path = os.path.join(export_dir, "Report SMB", f"SMB {ip}.md")
            with open(smb_path, "w") as f:
                f.write(f"# Raw report SMB for {machine.ip}\n\n")
                f.write("```\n")
                f.write(machine.smb_raw or "Unknown\n")
                f.write("\n```")

        if machine.web_fingerprint:
            whatweb_path = os.path.join(export_dir, "Report WHATWEB", f"WHATWEB {ip}.md")
            with open(whatweb_path, "w") as f:
                f.write(f"# Raw report WHATWEB for {machine.ip}\n\n")
                f.write("```\n")
                f.write(machine.whatweb_raw or "Unknown\n")
                f.write("\n```")

    machines_dir = os.path.join(export_dir, "Machines")
    nmap_reports = os.path.join(export_dir, "Report NMAP")
    smb_reports = os.path.join(export_dir, "Report SMB")
    whatweb_reports = os.path.join(export_dir, "Report WHATWEB")

    for machine in objets_machine:
        safe_ip = machine.ip.replace(":", "_").replace("/", "_").replace(" ", "_")
        fname = f"{safe_ip}.md"
        path = os.path.join(machines_dir, fname)

        nmap_file = f"NMAP {safe_ip}.md"
        smb_file = f"SMB {safe_ip}.md"
        www_file = f"WHATWEB {safe_ip}.md"

        try:
            with open(path, "w") as f:
                f.write(f"IP: {machine.ip}\n")
                f.write(f"MAC: {machine.mac or 'Unknown'}\n")
                f.write(f"Fabricant: {machine.vendor or 'Unknown'}\n")
                f.write(f"NetBIOS: {machine.netbios or 'Unknown'}\n")
                f.write(f"OS: {machine.os_details or 'Unknown'}\n")
                f.write(f"Network distance: {machine.network_distance or 'Unknown'}\n\n")

                f.write("### Scan Nmap\n\n")
                f.write("| Port | Proto | Service | Version |\n")
                f.write("|:----:|:-----:|:--------|:--------|\n")
                for svc in machine.services:
                    f.write(f"| {svc['port']} | {svc['proto']} | {svc['name']} | {svc['product']} |\n")
                f.write("\n")

                f.write("### Scan SMBClient\n\n")
                f.write("| Partage | Type |\n")
                f.write("|:--------|:-----|\n")
                for share in machine.smb_shares:
                    f.write(f"| {share['name']} | {share['type']} |\n")
                f.write("\n")

                f.write("### Scan WhatWeb\n\n")
                f.write("| URL | Technologies |\n")
                f.write("|:----|:--------------|\n")
                for url, techs in machine.web_fingerprint.items():
                    tech_list = ", ".join(techs)
                    f.write(f"| {url} | {tech_list} |\n")
                f.write("\n")

                f.write("### Links\n\n")
                safe_ip = machine.ip.replace(":", "_").replace("/", "_").replace(" ", "_")
                if os.path.exists(os.path.join(nmap_reports, nmap_file)):
                    f.write(f"- [[NMAP {safe_ip}]]\n")  
                if os.path.exists(os.path.join(smb_reports, smb_file)):
                    f.write(f"- [[SMB {safe_ip}]]\n")
                if os.path.exists(os.path.join(whatweb_reports, www_file)):
                    f.write(f"- [[WHATWEB {safe_ip}]]\n")      
        except Exception as e:
            print(f"ERROR file {e}")
        
        network_md_path = os.path.join(export_dir, "Network.md")
        try:
            with open(network_md_path, "w") as f:
                f.write("### Summary\n\n")
                f.write("| IP | NetBIOS | OS | Distance |\n")
                f.write("|:--|:--------|:--|:---------|\n")

                for machine in objets_machine:
                    ip_link = f"[[{machine.ip}]]"
                    netbios = machine.netbios or "Unknown"
                    os_name = machine.os_details or "Unknown"
                    distance = machine.network_distance or "Unknown"
                    f.write(f"| {ip_link} | {netbios} | {os_name} | {distance} |\n")
        except Exception as e:
            print(f"ERROR file {e}")

    source_obsidian = ".obsidian"
    destination_obsidian = os.path.join(export_dir, ".obsidian")

    if os.path.exists(source_obsidian):
        try:
            shutil.copytree(source_obsidian, destination_obsidian, dirs_exist_ok=True)
            print(f"{GREEN}[VISIT] {export_dir}")
        except Exception as e:
            print(f"{RED}[COPY] [ERREUR] {e}")
    else:
        print(f"{RED}[COPY] [WARNING].obsidian not found")
            
except KeyboardInterrupt:
    sys.exit(0)