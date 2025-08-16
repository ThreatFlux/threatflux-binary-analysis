#!/usr/bin/env python3
"""
Script to create a small binary file with known patterns for testing.
"""

import struct

def create_test_binary():
    """Create a binary file with various patterns."""
    data = bytearray()
    
    # PE header signature
    data.extend(b'MZ')
    data.extend(b'\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00')
    
    # Some padding
    data.extend(b'\x00' * 50)
    
    # ELF header signature
    data.extend(b'\x7fELF')
    data.extend(b'\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    
    # More padding
    data.extend(b'\x00' * 30)
    
    # Java class file signature
    data.extend(b'\xCA\xFE\xBA\xBE')
    data.extend(b'\x00\x00\x00\x34')
    
    # Some string patterns
    data.extend(b'ThreatFlux\x00')
    data.extend(b'BinaryAnalysis\x00')
    data.extend(b'TestPattern\x00')
    
    # Add some integers in different endianness
    data.extend(struct.pack('<I', 0x12345678))  # Little endian
    data.extend(struct.pack('>I', 0x87654321))  # Big endian
    
    # Add some suspicious API names
    api_names = [
        b'CreateRemoteThread\x00',
        b'VirtualAllocEx\x00',
        b'WriteProcessMemory\x00',
        b'LoadLibrary\x00',
        b'GetProcAddress\x00'
    ]
    
    for api in api_names:
        data.extend(api)
    
    # Add some URL patterns
    urls = [
        b'http://malware.example.com\x00',
        b'https://c2server.net/beacon\x00',
        b'ftp://exfil.badsite.org\x00'
    ]
    
    for url in urls:
        data.extend(url)
    
    # Add repeating pattern for entropy testing
    data.extend(b'\xAA\xBB\xCC\xDD' * 64)
    
    # Add some random-looking data
    import random
    random.seed(42)  # Reproducible
    for _ in range(128):
        data.append(random.randint(0, 255))
    
    # Add final signature
    data.extend(b'THREATFLUX_END')
    
    return bytes(data)

if __name__ == "__main__":
    binary_data = create_test_binary()
    
    with open('test_binary.bin', 'wb') as f:
        f.write(binary_data)
    
    print(f"Created test_binary.bin with {len(binary_data)} bytes")
    print("Contains PE, ELF, and Java signatures")
    print("Includes suspicious API names and URLs")
    print("Has patterns for entropy and string analysis")