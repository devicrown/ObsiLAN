# ObsiLAN

ObsiLAN is a local network scanner written in Python. It detects machines on the network, analyzes their services, SMB shares, and the web pages they host, then automatically generates a set of curated Markdown files to be integrated into **Obsidian** using the graphical view.

---

## ✨ Features

- 🔍 Scan local IP range with `nmap`
- 🧠 NetBIOS name detection via `nbtscan`
- 🧰 Scan services, ports and OS with `nmap -sV -O`
- 📁 Detecting SMB shares with `smbclient`
- 🌐 Detecting web pages via `whatweb`
- 📝 Full export to `.md` files for Obsidian and graphical view :
  - Network Summary (`Network.md`)
  - Details by machine (`Machines/`)
  - Raw reports (`Rapport NMAP/`, `Rapport SMB/`, `Rapport WHATWEB/`)
- 🔁 A new directory is generated on each execution (`scans/scan_0`, `scan_1`, etc.)

---

## 📁 Generated tree structure
```
scans/ 
└── scan_0/ 
├── Network.md 
├── Machines/ 
│ ├── 192.168.1.1.md 
│ └── ... 
├── Rapport NMAP/ 
│ └── NMAP 192.168.1.1.md 
├── Rapport SMB/ 
│ └── SMB 192.168.1.1.md 
└── Rapport WHATWEB/ 
└── WHATWEB 192.168.1.1.md
```
Each machine has :
- Smmary file (fichier Markdown)
- A link to his raw reports
- A display in Obsidian's graphics view
---

## 🛠️ Prérequis

These tools are necessary :

- `nmap`
- `nbtscan`
- `smbclient`
- `whatweb`
- Python 3 (≥ 3.8)

### Installing the tools :

```bash
sudo apt install nmap nbtscan smbclient ruby
sudo gem install whatweb
```
## 🚀 Start a scan
```bash
git clone https://github.com/votre-utilisateur/ObsiLAN.git
cd ObsiLAN

sudo python3 obsilanscan.py
```

## 🍎 macOS installation
On macOS, the same tools must be installed but the method differs slightly.
```bash
brew install nmap smbclient
```
🧠 Install nbtscan manually (not available via brew)
```bash
git clone https://github.com/resurrecting-open-source-projects/nbtscan.git
cd nbtscan
make
sudo cp nbtscan /usr/local/bin/nbtscan
```
🌐 Install whatweb manually
```bash
git clone https://github.com/urbanadventurer/WhatWeb.git
cd WhatWeb
sudo cp whatweb /usr/local/bin/whatweb
chmod +x /usr/local/bin/whatweb
```
If you want to run obsilanscan.py from anywhere, you can move it to your ~/bin directory (add it to your $PATH if needed):
```bash
mkdir -p ~/bin
cp obsilanscan.py ~/bin/obsilan
chmod +x ~/bin/obsilan
```
DeviCrown
