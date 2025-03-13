#!/usr/bin/env python3
import sys
import re
import glob
import os
from datetime import datetime
import argparse

def analyze_ping_file(filename):
    """Analyze a ping file and extract key metrics."""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filename}: {str(e)}", file=sys.stderr)
        return None

    # Extract target information from first line
    target_info = {"ip": "Unknown", "hostname": None}
    ip_match = re.search(r'PING\s+(\S+)(?:\s+\((\S+)\))?', lines[0]) if lines else None
    if ip_match:
        if ip_match.group(2):  # Has both hostname and IP
            target_info["hostname"] = ip_match.group(1)
            target_info["ip"] = ip_match.group(2).strip('()')
        else:
            target_info["ip"] = ip_match.group(1)

    # Check if file has timestamp data (-D option)
    has_timestamps = any(re.search(r'^\[\d+\.\d+\]', line) for line in lines if line.strip())

    # Extract ping times and timestamps
    ping_times = []
    timestamps = []
    sequences = []

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Extract timestamp if available
        if has_timestamps:
            ts_match = re.search(r'^\[(\d+\.\d+)\]', line)
            if ts_match:
                timestamps.append(float(ts_match.group(1)))

        # Extract sequence number and ping time
        seq_match = re.search(r'icmp_seq=(\d+)', line)
        time_match = re.search(r'time=(\d+\.?\d*)', line)

        if seq_match and time_match:
            sequences.append(int(seq_match.group(1)))
            ping_times.append(float(time_match.group(1)))

    # Calculate statistics
    stats = {
        "min": min(ping_times) if ping_times else 0,
        "max": max(ping_times) if ping_times else 0,
        "avg": sum(ping_times) / len(ping_times) if ping_times else 0,
        "total_pings": len(ping_times),
        "packet_loss": 0
    }

    # Calculate packet loss
    if sequences:
        expected_count = max(sequences) - min(sequences) + 1
        stats["packet_loss"] = ((expected_count - len(sequences)) / expected_count) * 100

    # Calculate time range if timestamps available
    time_range = None
    if timestamps:
        start_time = datetime.fromtimestamp(min(timestamps))
        end_time = datetime.fromtimestamp(max(timestamps))
        time_range = (start_time, end_time)

    return {
        "target": target_info,
        "stats": stats,
        "time_range": time_range,
        "has_timestamps": has_timestamps
    }

def generate_markdown(results):
    """Generate markdown output from analysis results."""
    markdown = []

    for filename, data in results.items():
        if not data:
            continue

        # Add header with filename
        markdown.append(f"## Ping Analysis: {os.path.basename(filename)}")
        markdown.append("")

        # Add target information
        target = data["target"]
        if target["hostname"]:
            markdown.append(f"**Host:** {target['hostname']} ({target['ip']})")
        else:
            markdown.append(f"**Host:** {target['ip']}")
        markdown.append("")

        # Add time range if available
        if data["time_range"]:
            start, end = data["time_range"]
            markdown.append(f"**Time Range:** {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}")
            markdown.append("")

        # Add statistics table
        markdown.append("| Metric | Value |")
        markdown.append("|--------|-------|")
        markdown.append(f"| Minimum Latency | {data['stats']['min']:.1f} ms |")
        markdown.append(f"| Average Latency | {data['stats']['avg']:.1f} ms |")
        markdown.append(f"| Maximum Latency | {data['stats']['max']:.1f} ms |")
        markdown.append(f"| Packet Loss | {data['stats']['packet_loss']:.1f}% |")
        markdown.append(f"| Total Pings | {data['stats']['total_pings']} |")
        markdown.append("")
        markdown.append("")

    return "\n".join(markdown)

def main():
    """Main function to process ping files and generate markdown output."""
    # Get files from command line arguments or use default pattern
    if len(sys.argv) > 1:
        files = []
        for pattern in sys.argv[1:]:
            matched_files = glob.glob(pattern)
            if matched_files:
                files.extend(matched_files)
            else:
                print(f"Warning: No files found matching pattern '{pattern}'", file=sys.stderr)
    else:
        # Default to common ping output file patterns
        patterns = ["*ping*.txt", "*ping*.log"]
        files = []
        for pattern in patterns:
            files.extend(glob.glob(pattern))

    if not files:
        print("Error: No files found to analyze.", file=sys.stderr)
        sys.exit(1)

    # Analyze each file
    results = {}
    for file in files:
        result = analyze_ping_file(file)
        if result:
            results[file] = result

    # Generate and print markdown
    if results:
        print(generate_markdown(results))
    else:
        print("No valid ping data found in input files.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()