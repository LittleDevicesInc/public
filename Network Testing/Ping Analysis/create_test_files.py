#!/usr/bin/env python3
import os
import subprocess
from datetime import datetime

def create_ping_file(target, filename):
    """Create a ping file with simulated data."""
    with open(filename, 'w') as f:
        # Write ping header
        f.write(f"PING {target} ({target}) 56(84) bytes of data.\n")

        # Generate 25 ping responses
        for i in range(1, 26):
            # Simulate ping times between 1ms and 100ms
            ping_time = 1 + (i % 100)  # Varies between 1 and 100ms
            f.write(f"64 bytes from {target}: icmp_seq={i} ttl=64 time={ping_time:.2f} ms\n")

def main():
    # Create test directory if it doesn't exist
    test_dir = "test_ping_files"
    os.makedirs(test_dir, exist_ok=True)

    # List of animals for AP names
    animals = ["bear", "wolf", "eagle", "hawk", "lion"]

    # Create AP files
    for i, animal in enumerate(animals, 1):
        filename = f"ap-{animal}{i*100}.log"
        create_ping_file("127.0.0.1", os.path.join(test_dir, filename))

    # Create switch files with MAC addresses
    macs = [
        "6A:F3:28:6F:81:74",
        "7B:E4:39:8G:92:85",
        "8C:D5:4A:9H:A3:96"
    ]
    for i, mac in enumerate(macs, 1):
        filename = f"switch-{mac}.log"
        create_ping_file("127.0.0.1", os.path.join(test_dir, filename))

    # Create gateway file
    create_ping_file("127.0.0.1", os.path.join(test_dir, "gateway-salmon386.log"))

    # Create VoIP phone files
    for i in range(1, 26):
        mac = f"9D:C6:5B:0I:B4:A{i:02d}"
        filename = f"voip-{mac}.log"
        create_ping_file("127.0.0.1", os.path.join(test_dir, filename))

    print(f"Created test files in {test_dir}/")
    print("\nFiles created:")
    print("- 5 AP files (bear, wolf, eagle, hawk, lion)")
    print("- 3 switch files with MAC addresses")
    print("- 1 gateway file")
    print("- 25 VoIP phone files with MAC addresses")

if __name__ == "__main__":
    main()