#!/usr/bin/env python3
"""
Test script to demonstrate the security testing tool against the demo application
"""

import subprocess
import sys
import time
import requests
import os

def start_demo_server():
    """Start the demo PHP server"""
    print("Starting demo server...")
    
    # Change to demo_target directory
    demo_dir = os.path.join(os.path.dirname(__file__), 'demo_target')
    if not os.path.exists(demo_dir):
        print("Demo target directory not found. Please ensure demo_target exists.")
        return None
    
    # Start PHP server
    try:
        process = subprocess.Popen(
            ['php', '-S', 'localhost:8080'],
            cwd=demo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Wait for server to start
        time.sleep(2)
        
        # Test if server is running
        try:
            response = requests.get('http://localhost:8080', timeout=5)
            if response.status_code == 200:
                print("✓ Demo server started successfully on http://localhost:8080")
                return process
            else:
                print("✗ Demo server failed to start properly")
                process.terminate()
                return None
        except requests.exceptions.RequestException:
            print("✗ Demo server is not responding")
            process.terminate()
            return None
            
    except FileNotFoundError:
        print("✗ PHP not found. Please install PHP to run the demo.")
        return None
    except Exception as e:
        print(f"✗ Failed to start demo server: {e}")
        return None

def run_security_test(test_type, target_url):
    """Run security test against target"""
    print(f"\nRunning {test_type} test against {target_url}...")
    
    try:
        cmd = [sys.executable, 'main.py', f'--{test_type}', target_url, '--verbose']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"✓ {test_type.upper()} test completed successfully")
            
            # Count vulnerabilities in output
            lines = result.stdout.split