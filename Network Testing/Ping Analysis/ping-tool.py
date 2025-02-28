#!/usr/bin/env python3
import re
import glob
import sys
import os
import subprocess
from datetime import datetime


def analyze_ping_file(filename):
    """Analyze a ping file for missing pings and abnormal intervals."""
    print(f"Analyzing {filename}...")
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filename}: {str(e)}")
        return None

    # Extract IP/MAC address from first line if available
    target_address = "Unknown"
    target_domain = None
    ip_match = re.search(r'PING\s+(\S+)(?:\s+\((\S+)\))?', lines[0]) if lines else None
    if ip_match:
        # Could be domain (IP) or just IP
        if ip_match.group(2):  # Has both domain and IP
            target_domain = ip_match.group(1)
            target_address = ip_match.group(2)
        else:
            target_address = ip_match.group(1)

    # Check if the file has timestamp data (using -D option)
    has_timestamps = any(re.search(r'^\[\d+\.\d+\]', line) for line in lines if line.strip())

    # Extract sequence numbers, timestamps and ping times
    # Different patterns for with/without timestamp format
    timestamp_pattern = (r'\[(\d+\.\d+)\] 64 bytes from (?:([^()]+) \(([^()]+)\)|([^:]+)): '
                         r'icmp_req=(\d+) ttl=\d+ time=(.+) ms')

    standard_pattern = (r'64 bytes from (?:([^()]+) \(([^()]+)\)|([^:]+)): '
                       r'icmp_req=(\d+) ttl=\d+ time=(.+) ms')

    seq_nums = []
    timestamps = []
    ping_times = []
    domain_names = set()

    for i, line in enumerate(lines):
        # Try timestamp pattern first, then standard pattern
        if has_timestamps:
            match = re.search(timestamp_pattern, line)
            if match:
                timestamp = float(match.group(1))

                # Check which format we have - domain (IP) or just IP
                if match.group(2) and match.group(3):
                    # Format: domain (IP)
                    domain = match.group(2).strip()
                    ip = match.group(3).strip()
                    if domain and not target_domain:
                        domain_names.add(domain)
                    seq_num = int(match.group(5))
                    ping_time = float(match.group(6))
                else:
                    # Format: just IP
                    seq_num = int(match.group(5))
                    ping_time = float(match.group(6))

                seq_nums.append(seq_num)
                timestamps.append(timestamp)
                ping_times.append(ping_time)
        else:
            # No timestamps, use standard pattern
            match = re.search(standard_pattern, line)
            if match:
                # For files without timestamps, create artificial timestamp based on line number
                # This helps maintain the analysis flow but won't be used for precise interval calculations
                artificial_timestamp = float(i)

                # Check which format we have - domain (IP) or just IP
                if match.group(1) and match.group(2):
                    # Format: domain (IP)
                    domain = match.group(1).strip()
                    ip = match.group(2).strip()
                    if domain and not target_domain:
                        domain_names.add(domain)
                    seq_num = int(match.group(4))
                    ping_time = float(match.group(5))
                else:
                    # Format: just IP
                    seq_num = int(match.group(4))
                    ping_time = float(match.group(5))

                seq_nums.append(seq_num)
                timestamps.append(artificial_timestamp)  # Use artificial timestamp
                ping_times.append(ping_time)

    # Check for missing sequence numbers
    if not seq_nums:
        print(f"No ping data found in {filename}")
        return None

    expected_seq = list(range(min(seq_nums), max(seq_nums) + 1))
    missing_seq = [seq for seq in expected_seq if seq not in seq_nums]

    # Calculate time intervals between pings - only meaningful with real timestamps
    intervals = []
    if has_timestamps:
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0

        # Look for abnormal intervals (potential missed pings without sequence gap)
        threshold = avg_interval * 1.8  # 80% higher than average interval
        abnormal_intervals = [
            (seq_nums[i], intervals[i])
            for i in range(len(intervals))
            if intervals[i] > threshold
        ]
    else:
        # Without real timestamps, we can't reliably detect abnormal intervals
        avg_interval = 0
        abnormal_intervals = []
        print("Note: This file doesn't contain timestamp data (-D option), so interval analysis is not available.")

    # Calculate ping time statistics
    avg_ping_time = sum(ping_times) / len(ping_times) if ping_times else 0
    max_ping_time = max(ping_times) if ping_times else 0
    min_ping_time = min(ping_times) if ping_times else 0

    # Add domain to the results if available
    if target_domain:
        display_target = f"{target_domain} ({target_address})"
    elif domain_names:
        main_domain = next(iter(domain_names))
        display_target = f"{main_domain} ({target_address})"
    else:
        display_target = target_address

    # Prepare results
    results = {
        "filename": filename,
        "target_address": target_address,
        "target_domain": target_domain if target_domain else (next(iter(domain_names)) if domain_names else None),
        "display_target": display_target,
        "total_pings": len(seq_nums),
        "first_sequence": min(seq_nums),
        "last_sequence": max(seq_nums),
        "has_timestamps": has_timestamps,
        "avg_interval": avg_interval if has_timestamps else None,
        "missing_seq": missing_seq,
        "abnormal_intervals": abnormal_intervals,
        "avg_ping_time": avg_ping_time,
        "min_ping_time": min_ping_time,
        "max_ping_time": max_ping_time
    }

    # Print summary
    print(f"Target: {display_target}")
    print(f"Total pings: {len(seq_nums)}")
    print(f"First sequence: {min(seq_nums)}")
    print(f"Last sequence: {max(seq_nums)}")

    if has_timestamps:
        print(f"Average interval: {avg_interval:.2f} seconds")

    print(f"Ping statistics: {avg_ping_time:.2f}ms avg, "
          f"{min_ping_time:.2f}ms min, {max_ping_time:.2f}ms max")

    if missing_seq:
        print(f"Missing sequences: {missing_seq}")
    else:
        print("No missing sequences")

    if has_timestamps and abnormal_intervals:
        print("Abnormal intervals (potential missed pings):")
        for seq, interval in abnormal_intervals:
            print(f"  After sequence {seq}: {interval:.2f} seconds "
                  f"(expected ~{avg_interval:.2f})")
    elif has_timestamps:
        print("No abnormal intervals detected")

    print("-" * 50)
    return results


def is_mac_address_in_filename(filename):
    """
    Check if filename contains a MAC address in any format.
    Supports MAC addresses with or without delimiters and in any case
    (uppercase, lowercase, or mixed).

    Examples of supported formats:
    - 02-9F-79-A1-6D-A9 (uppercase with hyphens)
    - 02:9f:79:a1:6d:a9 (lowercase with colons)
    - 029F79A16DA9 (uppercase without delimiters)
    - 029f79a16da9 (lowercase without delimiters)
    - 02_9F_79_A1_6D_A9 (with underscores)
    - 0A1B.2C3D.4E5F (Cisco format)
    """
    # Remove non-alphanumeric characters and look for 12 hex digits in a row
    normalized = re.sub(r'[^a-zA-Z0-9]', '', filename)
    # Explicitly use case-insensitive flag to ensure lowercase matches
    mac_match = re.search(r'[0-9a-fA-F]{12}', normalized, re.IGNORECASE)

    if mac_match:
        return True

    # Also check standard formats (with delimiters) just to be sure
    formats = [
        # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX format
        r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
        # XXXX.XXXX.XXXX format (Cisco)
        r'([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}',
        # XX-XX-XX-XX-XX-X format (sometimes last octet is short)
        r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{1,2}',
        # XX_XX_XX_XX_XX_XX format (with underscores)
        r'([0-9a-fA-F]{2}_){5}[0-9a-fA-F]{2}'
    ]

    for pattern in formats:
        if re.search(pattern, filename, re.IGNORECASE):
            return True

    return False


def get_files_to_analyze(file_args):
    """Get list of files to analyze based on command-line arguments."""
    files = []

    for arg in file_args:
        # If arg is a specific file that exists
        if os.path.isfile(arg):
            files.append(arg)
        else:
            # Treat as a pattern
            matched_files = glob.glob(arg)
            if matched_files:
                files.extend(matched_files)
            else:
                print(f"Warning: No files found matching pattern '{arg}'")

    # Make list unique while preserving order
    unique_files = []
    for f in files:
        if f not in unique_files:
            unique_files.append(f)

    return unique_files


def start_ping(target, output_file=None, count=None, interval=None, use_timestamp=True):
    """
    Start a ping and save output to a file.

    Args:
        target: The target to ping (IP, hostname, etc.)
        output_file: Name of the file to save output to (optional)
        count: Number of pings to send (optional)
        interval: Interval between pings in seconds (optional)
        use_timestamp: Whether to use the -D option for timestamps (default: True)

    Returns:
        The path to the output file
    """
    # If no output file is specified, create one based on the target
    if not output_file:
        # Clean the target to create a valid filename
        clean_target = re.sub(r'[:/\\\s]', '-', target)
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        output_file = f"ping-{clean_target}-{timestamp}.log"

    # Build the ping command with or without -D
    cmd = ["ping"]
    if use_timestamp:
        cmd.append("-D")

    # Add optional parameters
    if count:
        cmd.extend(["-c", str(count)])
    if interval:
        cmd.extend(["-i", str(interval)])

    # Add the target
    cmd.append(target)

    print(f"Starting ping to {target}, output will be saved to {output_file}")
    print(f"Command: {' '.join(cmd)} > {output_file}")

    try:
        # Start the ping process and redirect output to the file
        with open(output_file, 'w') as f:
            process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)

        print(f"Ping process started with PID {process.pid}")
        print(f"The ping is running in the background. To stop it, use: kill {process.pid}")
        return output_file
    except Exception as e:
        print(f"Error starting ping: {str(e)}")
        return None


def categorize_ping_files(files):
    """Categorize ping files by type."""
    # Initialize categories
    categories = {
        "mac": [],
        "ap": [],
        "gw": [],
        "switch": [],
        "fw": [],  # Added firewall category
        "host": [],  # Added host category
        "ip": [],
        "other": []
    }

    # IPv4 address pattern
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    # Categorize files
    for file in files:
        lowercase_name = os.path.basename(file).lower()

        # Check for MAC addresses
        if is_mac_address_in_filename(file):
            categories["mac"].append(file)
            continue

        # Check for device types with various delimiters
        # Look for device type identifiers in filenames
        device_types = {
            "ap": ["ap", "aps", "access-point", "accesspoint", "access_point"],
            "gw": ["gw", "gateway", "gtw"],
            "switch": ["switch", "sw"],
            "fw": ["fw", "firewall"],
            "host": ["host", "device", "client"]
        }

        # Check if any device type identifiers are in the filename
        categorized = False
        for category, identifiers in device_types.items():
            # Check if any identifier matches as a word pattern
            # This handles cases like "ping-ap-123.log" or "ping_ap_123.log"
            for identifier in identifiers:
                # Word boundaries or common delimiters
                patterns = [
                    fr'\b{identifier}\b',  # Whole word
                    fr'[_\-\.]{identifier}[_\-\.]',  # With delimiters
                    fr'^{identifier}[_\-\.]',  # At start with delimiter
                    fr'[_\-\.]{identifier}$'   # At end with delimiter
                ]

                if any(re.search(pattern, lowercase_name) for pattern in patterns):
                    categories[category].append(file)
                    categorized = True
                    break

            if categorized:
                break

        # If not categorized by device type, check for IP address
        if not categorized and re.search(ip_pattern, file):
            categories["ip"].append(file)
            continue

        # If still not categorized, put in "other"
        if not categorized:
            categories["other"].append(file)

    return categories


def generate_summary_report(all_results, output_file=None):
    """Generate a summary report of all ping analysis results."""
    # Start capturing output if file specified
    original_stdout = None
    if output_file:
        original_stdout = sys.stdout
        f = open(output_file, 'w')
        sys.stdout = f

    # Report header
    report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print("\n" + "=" * 80)
    print("PING ANALYSIS SUMMARY REPORT")
    print("=" * 80)
    print(f"Report generated on: {report_time}")
    print("-" * 80)

    # Count total files with issues
    files_with_missing = 0
    files_with_abnormal = 0
    total_missing_pings = 0
    total_abnormal_intervals = 0
    files_with_timestamps = 0
    files_without_timestamps = 0

    for category, results_list in all_results.items():
        for results in results_list:
            if results["missing_seq"]:
                files_with_missing += 1
                total_missing_pings += len(results["missing_seq"])
            if results.get("abnormal_intervals", []):
                files_with_abnormal += 1
                total_abnormal_intervals += len(
                    results["abnormal_intervals"]
                )
            if results.get("has_timestamps", False):
                files_with_timestamps += 1
            else:
                files_without_timestamps += 1

    # Calculate total files analyzed
    total_files = sum(
        len(results_list) for results_list in all_results.values()
    )

    print(f"Total files analyzed: {total_files}")
    print(f"Files with timestamp data (-D option): {files_with_timestamps}")
    print(f"Files without timestamp data: {files_without_timestamps}")
    print(f"Files with missing pings: {files_with_missing}")
    print(f"Files with abnormal intervals: {files_with_abnormal}")
    print(f"Total missing pings: {total_missing_pings}")
    print(f"Total abnormal intervals: {total_abnormal_intervals}")
    print("-" * 80)

    # Summary by category
    print("\nCATEGORY SUMMARY:")
    for category, results_list in all_results.items():
        if not results_list:
            continue

        cat_missing = sum(len(r["missing_seq"]) for r in results_list)
        cat_abnormal = sum(
            len(r.get("abnormal_intervals", [])) for r in results_list
        )

        # Calculate average ping time for this category
        if results_list:
            cat_avg_ping = sum(
                r["avg_ping_time"] for r in results_list
            ) / len(results_list)
        else:
            cat_avg_ping = 0

        # Count how many have timestamps in this category
        cat_with_timestamps = sum(1 for r in results_list if r.get("has_timestamps", False))
        cat_total = len(results_list)

        print(f"\n{category.upper()} ({len(results_list)} files, {cat_with_timestamps} with timestamps):")
        print(f"  Missing pings: {cat_missing}")
        print(f"  Abnormal intervals: {cat_abnormal}")
        print(f"  Average ping time: {cat_avg_ping:.2f}ms")

        # List files with issues
        for results in results_list:
            filename = results["filename"]
            target = results["display_target"]
            issues = []

            if results["missing_seq"]:
                issues.append(f"{len(results['missing_seq'])} missing pings")
            if results.get("abnormal_intervals", []):
                abnormal_count = len(results["abnormal_intervals"])
                issues.append(f"{abnormal_count} abnormal intervals")

            if issues:
                print(f"  - {filename} ({target}): {', '.join(issues)}")

    print("\n" + "=" * 80)
    print("END OF REPORT")
    print("=" * 80)

    # Restore stdout if needed
    if original_stdout:
        sys.stdout = original_stdout
        f.close()
        print(f"Report saved to {output_file}")


def print_usage():
    """Print usage instructions."""
    print("Ping Tool")
    print("=========")
    print("\nA comprehensive tool for initiating and analyzing ping log files.")
    print("Detects issues such as missed pings, abnormal response times, and network latency patterns.")
    print("\nUsage:")
    print("  python ping-tool.py [options] [files/patterns]")
    print("\nOptions:")
    print("  -h, --help                   Show this help message and exit")
    print("  -o FILE, --output=FILE       Write report to FILE")
    print("  -p PATTERN, --pattern=PATTERN  Specify file pattern (default: *ping*.txt or *ping*.log)")
    print("  --ping TARGET                Start a ping to the specified target")
    print("  --count N                    Number of pings to send (optional)")
    print("  --interval SEC              Interval between pings in seconds (optional)")
    print("  --ping-output FILE           Output file for ping results (optional)")
    print("  --no-timestamp              Don't use -D timestamp option when starting a ping")
    print("\nExamples:")
    print("  # Start a ping to a target and save the output:")
    print("  python ping-tool.py --ping 192.168.1.1")
    print("\n  # Start a ping without timestamps:")
    print("  python ping-tool.py --ping google.com --no-timestamp")
    print("\n  # Start a ping with a specific count and interval:")
    print("  python ping-tool.py --ping ap-123.local --count 100 --interval 0.5")
    print("\n  # Analyze all ping files in current directory:")
    print("  python ping-tool.py")
    print("\n  # Analyze a specific file:")
    print("  python ping-tool.py ping-ap1.txt")
    print("\n  # Analyze multiple specific files:")
    print("  python ping-tool.py ping-ap1.txt ping-ap2.txt")
    print("\n  # Analyze files matching a pattern and save report:")
    print("  python ping-tool.py -p \"ping-ap*.txt\" -o report.txt")
    print("\n  # Mix specific files and patterns:")
    print("  python ping-tool.py ping-ap1.txt \"ping-switch*.txt\"")
    print("\nFile Categories:")
    print("  Files are automatically categorized based on naming patterns:")
    print("  - MAC: Files containing a MAC address in any format/case")
    print("         (e.g., ping-02:9F:79:A1:6D:A9.txt, ping_029f79a16da9.txt)")
    print("  - AP:  Files containing 'ap', 'aps', or 'access-point' in the name")
    print("  - GW:  Files containing 'gw' or 'gateway' in the name")
    print("  - SWITCH: Files containing 'switch' or 'sw' in the name")
    print("  - FW:  Files containing 'fw' or 'firewall' in the name")
    print("  - HOST: Files containing 'host' or 'device' in the name")
    print("  - IP:  Files containing an IP address pattern")
    print("  - OTHER: Any other ping files")


def parse_args():
    """Parse command-line arguments."""
    args = {
        "output_file": None,
        "pattern": None,
        "files": [],
        "ping_target": None,
        "ping_count": None,
        "ping_interval": None,
        "ping_output": None,
        "no_timestamp": False
    }

    # Process all arguments
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]

        # Handle help flags
        if arg in ("--help", "-h"):
            print_usage()
            sys.exit(0)

        # Handle output file
        elif arg.startswith("--output="):
            args["output_file"] = arg.split("=", 1)[1]
            i += 1
        elif arg == "-o" and i+1 < len(sys.argv):
            args["output_file"] = sys.argv[i+1]
            i += 2

        # Handle pattern
        elif arg.startswith("--pattern="):
            args["pattern"] = arg.split("=", 1)[1]
            i += 1
        elif arg == "-p" and i+1 < len(sys.argv):
            args["pattern"] = sys.argv[i+1]
            i += 2

        # Handle ping command
        elif arg == "--ping" and i+1 < len(sys.argv):
            args["ping_target"] = sys.argv[i+1]
            i += 2
        elif arg == "--count" and i+1 < len(sys.argv):
            args["ping_count"] = int(sys.argv[i+1])
            i += 2
        elif arg == "--interval" and i+1 < len(sys.argv):
            args["ping_interval"] = float(sys.argv[i+1])
            i += 2
        elif arg == "--ping-output" and i+1 < len(sys.argv):
            args["ping_output"] = sys.argv[i+1]
            i += 2
        elif arg == "--no-timestamp":
            args["no_timestamp"] = True
            i += 1

        # Treat other arguments as files or patterns
        else:
            args["files"].append(arg)
            i += 1

    return args


def analyze_ping_files():
    """Analyze ping files according to command-line arguments."""
    # Parse command-line arguments
    args = parse_args()
    output_file = args["output_file"]

    # Check if we should start a ping
    if args["ping_target"]:
        ping_file = start_ping(
            args["ping_target"],
            args["ping_output"],
            args["ping_count"],
            args["ping_interval"],
            not args["no_timestamp"]
        )
        # If we're just starting a ping and not analyzing files, exit
        if not args["files"] and not args["pattern"]:
            return None

    # Determine files to analyze
    if args["files"]:
        # User specified files or patterns directly
        files = get_files_to_analyze(args["files"])
    elif args["pattern"]:
        # User specified a pattern
        files = glob.glob(args["pattern"])
    else:
        # Default: all ping files in current directory
        # Look for both .txt and .log files
        txt_files = glob.glob("*ping*.txt")
        log_files = glob.glob("*ping*.log")
        files = txt_files + log_files

    # Filter out non-text files
    files = [f for f in files if f.endswith(('.txt', '.log'))]

    # Make sure we have files to analyze
    if not files:
        print("No ping files found to analyze.")
        sys.exit(1)

    # Categorize files
    categories = categorize_ping_files(files)
    all_results = {}

    # Print summary of files found
    print("=" * 80)
    print("PING FILES ANALYSIS")
    print("=" * 80)

    total_files = sum(len(files) for files in categories.values())
    print(f"Found {total_files} ping files to analyze:")
    for category, category_files in categories.items():
        if category_files:
            print(f"- {category.upper()}: {len(category_files)} files")
            for file in category_files:
                print(f"  - {file}")
    print("=" * 80)

    # Analyze each category
    for category, category_files in categories.items():
        if not category_files:
            continue

        print(f"\nANALYZING {category.upper()} PING FILES")
        print("=" * 80)

        category_results = []
        for file in category_files:
            results = analyze_ping_file(file)
            if results:
                category_results.append(results)

        all_results[category] = category_results

    # Generate summary report
    generate_summary_report(all_results, output_file)

    return all_results


if __name__ == "__main__":
    analyze_ping_files()