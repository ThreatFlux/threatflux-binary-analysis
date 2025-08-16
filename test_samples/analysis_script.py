#!/usr/bin/env python3
"""
ThreatFlux Binary Analysis - Python Test Script
A sample Python script for testing script analysis capabilities.
"""

import os
import sys
import hashlib
import base64
import subprocess
import json
from pathlib import Path

# Global configuration
CONFIG = {
    "version": "1.0.0",
    "analysis_mode": "static",
    "debug": False,
    "output_format": "json"
}

# Hardcoded strings for testing string extraction
API_ENDPOINTS = [
    "https://api.threatflux.com/v1/analysis",
    "https://malware-db.example.com/lookup",
    "http://suspicious-domain.net/callback"
]

MALWARE_SIGNATURES = [
    "4d5a90000300000004000000ffff0000",  # PE header
    "7f454c460201010000000000000000000",  # ELF header
    "cafebabe00000034001f0a00060012",     # Java class
]

class BinaryAnalyzer:
    """Sample binary analyzer class for testing."""
    
    def __init__(self, target_path):
        self.target_path = Path(target_path)
        self.results = {}
        self.suspicious_patterns = [
            b"CreateRemoteThread",
            b"VirtualAllocEx", 
            b"WriteProcessMemory",
            b"LoadLibrary",
            b"GetProcAddress"
        ]
    
    def calculate_hashes(self):
        """Calculate various hashes of the target file."""
        if not self.target_path.exists():
            return None
        
        hashes = {}
        with open(self.target_path, 'rb') as f:
            data = f.read()
            
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
        
        return hashes
    
    def scan_for_patterns(self):
        """Scan file for suspicious patterns."""
        if not self.target_path.exists():
            return []
        
        found_patterns = []
        with open(self.target_path, 'rb') as f:
            content = f.read()
            
        for pattern in self.suspicious_patterns:
            if pattern in content:
                found_patterns.append(pattern.decode('utf-8', errors='ignore'))
        
        return found_patterns
    
    def extract_strings(self, min_length=4):
        """Extract printable strings from binary."""
        if not self.target_path.exists():
            return []
        
        strings = []
        current_string = ""
        
        with open(self.target_path, 'rb') as f:
            while True:
                byte = f.read(1)
                if not byte:
                    break
                
                char = chr(byte[0])
                if char.isprintable() and char not in '\r\n\t':
                    current_string += char
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""
        
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings[:50]  # Limit to first 50 strings
    
    def analyze(self):
        """Perform complete analysis."""
        print(f"Analyzing: {self.target_path}")
        
        self.results['file_info'] = {
            'name': self.target_path.name,
            'size': self.target_path.stat().st_size if self.target_path.exists() else 0,
            'exists': self.target_path.exists()
        }
        
        self.results['hashes'] = self.calculate_hashes()
        self.results['suspicious_patterns'] = self.scan_for_patterns()
        self.results['strings'] = self.extract_strings()
        
        return self.results
    
    def save_report(self, output_path):
        """Save analysis report to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)

def simulate_network_activity():
    """Simulate suspicious network activity for testing."""
    # This would be flagged by network monitoring
    suspicious_urls = [
        "http://malware-c2.example.com/beacon",
        "https://data-exfil.badsite.net/upload",
        "ftp://backdoor.suspicious.org/download"
    ]
    
    print("Simulating network connections...")
    for url in suspicious_urls:
        print(f"[SIMULATED] Connecting to: {url}")

def obfuscated_payload():
    """Example of obfuscated code that might be flagged."""
    # Base64 encoded payload (actually just "Hello World")
    encoded = "SGVsbG8gV29ybGQ="
    decoded = base64.b64decode(encoded).decode('utf-8')
    print(f"Decoded payload: {decoded}")
    
    # Simulated shell command construction
    cmd_parts = ["echo", "System", "analysis", "complete"]
    command = " ".join(cmd_parts)
    print(f"Executing: {command}")

def main():
    """Main function."""
    print("ThreatFlux Binary Analysis - Python Test Script")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
        analyzer = BinaryAnalyzer(target_file)
        results = analyzer.analyze()
        
        print(f"Analysis Results:")
        print(f"File: {results['file_info']['name']}")
        print(f"Size: {results['file_info']['size']} bytes")
        
        if results['hashes']:
            print(f"MD5: {results['hashes']['md5']}")
            print(f"SHA256: {results['hashes']['sha256']}")
        
        if results['suspicious_patterns']:
            print(f"Suspicious patterns found: {len(results['suspicious_patterns'])}")
        
        if results['strings']:
            print(f"Strings extracted: {len(results['strings'])}")
    else:
        print("Usage: python3 analysis_script.py <target_file>")
        simulate_network_activity()
        obfuscated_payload()
    
    print("Analysis complete.")

if __name__ == "__main__":
    main()