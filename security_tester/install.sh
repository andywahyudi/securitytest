#!/bin/bash

echo "Installing Web Security Testing Tool..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make main script executable
chmod +x main.py

echo "Installation complete!"
echo ""
echo "Usage examples:"
echo "  python3 main.py --all http://target.com"
echo "  python3 main.py --xss --csrf http://target.com --output report.txt"
echo "  python3 main.py --xss http://target.com --cookies 'session=abc123' --verbose"
