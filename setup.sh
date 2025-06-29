#!/bin/bash

echo "🛠  RedShadow V1 - Initial Setup"

# Check for python3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed. Please install it first."
    exit 1
fi

# Check for pip
if ! command -v pip &> /dev/null; then
    echo "[!] pip is not installed. Try: sudo apt install python3-pip"
    exit 1
fi

# Create virtual environment if not already there
if [ ! -d "venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "[+] Installing Python libraries..."
pip install -r requirements.txt

# Install Nmap if missing
if ! command -v nmap &> /dev/null; then
    echo "[+] Installing Nmap..."
    sudo apt-get update
    sudo apt-get install -y nmap
else
    echo "[✓] Nmap already installed"
fi

echo "[✓] Setup complete. Run using: source venv/bin/activate && python3 main.py --help"
