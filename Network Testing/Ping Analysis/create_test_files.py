#!/usr/bin/env python3
import os
import random
import argparse
import ipaddress
from datetime import datetime, timedelta
import socket
import numpy as np
import time

def generate_random_domain():
    """Generate a random domain name."""
    tlds = ['.com', '.net', '.org', '.io', '.co', '.cloud', '.tech']
    prefixes = ['server', 'api', 'cdn', 'app', 'mail', 'web', 'db', 'cache', 'static', 'media']
    companies = ['acme', 'globex', 'initech', 'umbrella', 'stark', 'wayne', 'aperture', 'cyberdyne', 'oscorp']

    prefix = random.choice(prefixes)
    company = random.choice(companies)
    tld = random.choice(tlds)

    return f"{prefix}.{company}{tld}"

def generate_random_ip(private=False):
    """Generate a random IP address."""
    if private:
        # Generate private IP in 192.168.0.0/16 range
        return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # Generate public IP (avoiding reserved ranges)
        first_octet = random.choice([n for n in range(1, 224) if n not in [10, 127, 169, 172, 192, 198, 203]])
        return f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_device_name(device_type):
    """Generate a realistic device name based on type."""
    # Animals for access points
    animals = ["antelope", "badger", "cheetah", "dolphin", "elephant", "falcon", "giraffe", "hippo",
              "iguana", "jaguar", "kangaroo", "lemur", "mongoose", "narwhal", "octopus", "penguin",
              "quail", "raccoon", "snake", "tiger", "unicorn", "vulture", "walrus", "xerus", "yak", "zebra"]

    # Planets/stars for switches
    celestial = ["mercury", "venus", "earth", "mars", "jupiter", "saturn", "uranus", "neptune", "pluto",
                "sirius", "vega", "polaris", "antares", "betelgeuse", "rigel", "arcturus", "aldebaran"]

    # Mountains for gateways
    mountains = ["everest", "k2", "kilimanjaro", "denali", "matterhorn", "fuji", "rainier", "whitney",
                "mckinley", "aconcagua", "elbrus", "blanc", "olympus", "hood", "shasta", "pike"]

    # Cities for VoIP phones
    cities = ["tokyo", "paris", "london", "newyork", "sydney", "berlin", "rome", "madrid", "moscow",
             "beijing", "cairo", "dubai", "toronto", "chicago", "miami", "seattle", "boston", "austin"]

    if device_type.lower() == "ap" or device_type.lower() == "access_point":
        name = f"AP-{random.choice(animals).capitalize()}"
        ip = generate_random_ip(private=True)
    elif device_type.lower() == "switch":
        name = f"SW-{random.choice(celestial).capitalize()}"
        ip = generate_random_ip(private=True)
    elif device_type.lower() == "gateway":
        name = f"GW-{random.choice(mountains).capitalize()}"
        ip = generate_random_ip(private=True)
    elif device_type.lower() == "voip" or device_type.lower() == "phone":
        name = f"VOIP-{random.choice(cities).capitalize()}"
        ip = generate_random_ip(private=True)
    elif device_type.lower() == "server":
        name = generate_random_domain()
        ip = generate_random_ip(private=random.random() < 0.7)  # 70% chance of private IP
    elif device_type.lower() == "dns":
        dns_services = ["google-dns", "cloudflare-dns", "opendns", "quad9", "comodo-dns", "norton-dns"]
        name = random.choice(dns_services)
        ip = random.choice(["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "64.6.64.6"])
    else:
        name = f"Device-{random.randint(1, 999)}"
        ip = generate_random_ip(private=random.random() < 0.5)

    return name, ip

def get_base_ping_time(ip):
    """Determine base ping time based on IP address type."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            # Private IPs have very low ping times
            return random.uniform(0.1, 0.9)
        elif str(ip_obj).startswith(('8.8', '1.1', '9.9', '208.67', '64.6')):
            # Known DNS services
            return random.uniform(6.0, 15.0)
        else:
            # Public IPs have higher ping times
            return random.uniform(5.0, 30.0)
    except ValueError:
        # Domain names have higher ping times
        return random.uniform(8.0, 25.0)

def apply_time_pattern(base_time, pattern, progress, jitter_factor=0.1):
    """Apply a time pattern to the base ping time."""
    # Add normal jitter
    jitter = np.random.normal(0, base_time * jitter_factor)

    if pattern == "stable":
        return max(0.1, base_time + jitter)
    elif pattern == "increasing":
        # Gradually increase up to 3x the base time
        increase_factor = 1 + (2 * progress)
        return max(0.1, base_time * increase_factor + jitter)
    elif pattern == "decreasing":
        # Start high and gradually decrease
        decrease_factor = 3 - (2 * progress)
        return max(0.1, base_time * decrease_factor + jitter)
    elif pattern == "spiky":
        # Occasional spikes
        if random.random() < 0.1:  # 10% chance of spike
            return base_time * random.uniform(5, 10) + jitter
        return max(0.1, base_time + jitter)
    elif pattern == "problem":
        # Problematic pattern with high latency and packet loss
        if progress < 0.3:
            # Start normal
            return max(0.1, base_time + jitter)
        elif progress < 0.6:
            # Gradually worsening
            increase_factor = 1 + (10 * (progress - 0.3))
            return max(0.1, base_time * increase_factor + jitter)
        else:
            # Severe problems
            return base_time * random.uniform(20, 50) + jitter
    else:
        return max(0.1, base_time + jitter)

def create_ping_file(target_name, target_ip, filename, hours=24, pattern="stable", problem_device=False):
    """Create a ping file with simulated data over the specified time period."""
    # Determine base ping time based on IP
    base_ping_time = get_base_ping_time(target_ip)

    # Set up time parameters
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)

    # Determine ping interval (average 30 seconds, with some randomness)
    avg_interval = 30  # seconds

    # Calculate approximate number of pings
    approx_pings = int((hours * 3600) / avg_interval)

    # Limit to a reasonable number to avoid huge files
    max_pings = 10000
    if approx_pings > max_pings:
        # Adjust interval to get a reasonable number of pings
        avg_interval = (hours * 3600) / max_pings

    # Determine if this is the problem device
    if problem_device:
        pattern = "problem"

    # Generate timestamps with slight randomness in intervals
    timestamps = []
    current_time = start_time

    while current_time < end_time:
        timestamps.append(current_time)
        # Add some randomness to the interval
        interval = random.normalvariate(avg_interval, avg_interval * 0.2)
        current_time += timedelta(seconds=max(1, interval))

    # Ensure we don't exceed max_pings
    if len(timestamps) > max_pings:
        # Randomly sample to reduce
        timestamps = sorted(random.sample(timestamps, max_pings))

    # Calculate packet loss probability (higher for problem devices)
    packet_loss_prob = 0.01  # 1% for normal devices
    if pattern == "problem":
        packet_loss_prob = 0.15  # 15% for problem devices

    # Write the ping file
    with open(filename, 'w') as f:
        # Write ping header
        f.write(f"PING {target_name} ({target_ip}) 56(84) bytes of data.\n")

        # Track sequence numbers and successful pings
        seq = 1
        successful_pings = 0
        min_time = float('inf')
        max_time = 0
        sum_time = 0

        # Generate ping responses
        for i, timestamp in enumerate(timestamps):
            # Determine if this ping is lost
            is_lost = random.random() < packet_loss_prob

            # Calculate progress through the time period (0 to 1)
            progress = i / len(timestamps)

            if not is_lost:
                # Generate ping time based on pattern and progress
                ping_time = apply_time_pattern(base_ping_time, pattern, progress)

                # Format timestamp
                time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

                # Write ping response
                f.write(f"[{time_str}] 64 bytes from {target_ip}: icmp_seq={seq} ttl=64 time={ping_time:.3f} ms\n")

                # Update statistics
                successful_pings += 1
                min_time = min(min_time, ping_time)
                max_time = max(max_time, ping_time)
                sum_time += ping_time

            seq += 1

        # Write ping summary
        if successful_pings > 0:
            avg_time = sum_time / successful_pings
            packet_loss = (seq - 1 - successful_pings) / (seq - 1) * 100

            f.write(f"\n--- {target_name} ping statistics ---\n")
            f.write(f"{seq - 1} packets transmitted, {successful_pings} received, {packet_loss:.1f}% packet loss, time {hours * 3600}ms\n")
            f.write(f"rtt min/avg/max/mdev = {min_time:.3f}/{avg_time:.3f}/{max_time:.3f}/{(max_time - min_time) / 4:.3f} ms\n")

    return {
        "name": target_name,
        "ip": target_ip,
        "pattern": pattern,
        "packets": seq - 1,
        "successful": successful_pings,
        "loss_percent": (seq - 1 - successful_pings) / (seq - 1) * 100 if seq > 1 else 0,
        "min_time": min_time if min_time != float('inf') else 0,
        "max_time": max_time,
        "avg_time": sum_time / successful_pings if successful_pings > 0 else 0
    }

def main():
    parser = argparse.ArgumentParser(description="Generate realistic ping test files")
    parser.add_argument("--output-dir", default="test_ping_files", help="Directory to store generated files")
    parser.add_argument("--hours", type=int, default=24, help="Number of hours of ping data to generate")
    parser.add_argument("--access-points", type=int, default=5, help="Number of access points to simulate")
    parser.add_argument("--switches", type=int, default=3, help="Number of switches to simulate")
    parser.add_argument("--gateways", type=int, default=2, help="Number of gateways to simulate")
    parser.add_argument("--voip-phones", type=int, default=8, help="Number of VoIP phones to simulate")
    parser.add_argument("--servers", type=int, default=4, help="Number of servers to simulate")
    parser.add_argument("--dns-services", type=int, default=2, help="Number of DNS services to simulate")
    parser.add_argument("--problem-devices", type=int, default=1, help="Number of devices with problems to simulate")

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Generate device lists
    devices = []

    # Access Points
    for _ in range(args.access_points):
        name, ip = generate_device_name("ap")
        devices.append({"type": "access_point", "name": name, "ip": ip})

    # Switches
    for _ in range(args.switches):
        name, ip = generate_device_name("switch")
        devices.append({"type": "switch", "name": name, "ip": ip})

    # Gateways
    for _ in range(args.gateways):
        name, ip = generate_device_name("gateway")
        devices.append({"type": "gateway", "name": name, "ip": ip})

    # VoIP Phones
    for _ in range(args.voip_phones):
        name, ip = generate_device_name("voip")
        devices.append({"type": "voip_phone", "name": name, "ip": ip})

    # Servers
    for _ in range(args.servers):
        name, ip = generate_device_name("server")
        devices.append({"type": "server", "name": name, "ip": ip})

    # DNS Services
    for _ in range(args.dns_services):
        name, ip = generate_device_name("dns")
        devices.append({"type": "dns_service", "name": name, "ip": ip})

    # Randomly select problem devices
    problem_indices = random.sample(range(len(devices)), min(args.problem_devices, len(devices)))

    # Assign patterns to devices
    patterns = ["stable", "increasing", "decreasing", "spiky"]
    for i, device in enumerate(devices):
        if i in problem_indices:
            device["pattern"] = "problem"
        else:
            device["pattern"] = random.choice(patterns)

    # Generate ping files and collect results
    results = []
    print(f"Generating ping files for {len(devices)} devices over {args.hours} hours...")

    for i, device in enumerate(devices):
        filename = os.path.join(args.output_dir, f"{device['type']}-{device['name']}.log")
        print(f"  Creating {filename}...")

        result = create_ping_file(
            device['name'],
            device['ip'],
            filename,
            hours=args.hours,
            pattern=device['pattern'],
            problem_device=(i in problem_indices)
        )

        results.append(result)

    # Generate summary report
    summary_file = os.path.join(args.output_dir, "summary.txt")
    with open(summary_file, 'w') as f:
        f.write("=== Ping Test Summary ===\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Time period: {args.hours} hours\n")
        f.write(f"Total devices: {len(devices)}\n\n")

        # List devices by type
        device_types = set(d["type"] for d in devices)
        for device_type in device_types:
            type_count = sum(1 for d in devices if d["type"] == device_type)
            f.write(f"{device_type.replace('_', ' ').title()}: {type_count}\n")

        f.write("\n=== Performance Summary ===\n\n")

        # Sort by max response time to highlight potential problems
        results.sort(key=lambda x: x["max_time"], reverse=True)

        f.write(f"{'Device':<25} {'IP':<15} {'Packets':<10} {'Loss %':<10} {'Min (ms)':<10} {'Avg (ms)':<10} {'Max (ms)':<10} {'Pattern':<10}\n")
        f.write("-" * 100 + "\n")

        for result in results:
            f.write(f"{result['name']:<25} {result['ip']:<15} {result['packets']:<10} {result['loss_percent']:<10.1f} ")
            f.write(f"{result['min_time']:<10.2f} {result['avg_time']:<10.2f} {result['max_time']:<10.2f} {result['pattern']:<10}\n")

        f.write("\n=== Problem Devices ===\n\n")
        problem_results = [r for r in results if r["pattern"] == "problem"]

        if problem_results:
            for result in problem_results:
                f.write(f"* {result['name']} ({result['ip']})\n")
                f.write(f"  - Max response time: {result['max_time']:.2f} ms\n")
                f.write(f"  - Packet loss: {result['loss_percent']:.1f}%\n")
                f.write(f"  - Pattern: {result['pattern']}\n\n")
        else:
            f.write("No problem devices identified.\n")

    print(f"\nGenerated {len(devices)} ping files and summary report in {args.output_dir}/")
    print(f"Summary report: {summary_file}")

if __name__ == "__main__":
    main()