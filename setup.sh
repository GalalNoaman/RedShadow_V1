#!/bin/bash

echo -e "\e[34m🛠️  RedShadow V1 - Initial Setup\e[0m"

# Exit on any error
set -e

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "\e[31m[!] Python3 is not installed. Install it and try again.\e[0m"
    exit 1
fi

# Check for pip
if ! command -v pip &> /dev/null; then
    echo -e "\e[31m[!] pip is not installed. Try: sudo apt install python3-pip\e[0m"
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo -e "\e[33m[+] Creating Python virtual environment...\e[0m"
    python3 -m venv venv
else
    echo -e "\e[32m[✓] Virtual environment already exists.\e[0m"
fi

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo -e "\e[33m[+] Installing Python packages from requirements.txt...\e[0m"
pip install --upgrade pip
pip install -r requirements.txt

# Check for Nmap
if ! command -v nmap &> /dev/null; then
    echo -e "\e[33m[+] Installing Nmap...\e[0m"
    sudo apt update
    sudo apt install -y nmap
else
    echo -e "\e[32m[✓] Nmap is already installed.\e[0m"
fi

# Create outputs directory
if [ ! -d "outputs" ]; then
    echo -e "\e[33m[+] Creating outputs directory...\e[0m"
    mkdir -p outputs
else
    echo -e "\e[32m[✓] outputs/ directory already exists.\e[0m"
fi

echo
echo -e "\e[32m[✓] Setup complete.\e[0m"
echo -e "\e[34m👉 To start using RedShadow V1:\e[0m"
echo -e "\e[36m   source venv/bin/activate"
echo -e "   python3 main.py --help\e[0m"
