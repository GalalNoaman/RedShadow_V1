#!/bin/bash

echo "🛠️  RedShadow V1 - Initial Setup"

# Exit on any error
set -e

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed. Install it and try again."
    exit 1
fi

# Check for pip
if ! command -v pip &> /dev/null; then
    echo "[!] pip is not installed. Try: sudo apt install python3-pip"
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo "[+] Creating Python virtual environment..."
    python3 -m venv venv
else
    echo "[✓] Virtual environment already exists."
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo "[+] Installing Python packages from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for Nmap
if ! command -v nmap &> /dev/null; then
    echo "[+] Installing Nmap..."
    sudo apt update
    sudo apt install -y nmap
else
    echo "[✓] Nmap is already installed."
fi

echo
echo "[✓] Setup complete."
echo "👉 To start using RedShadow V1:"
echo "   source venv/bin/activate"
echo "   python3 main.py --help"
