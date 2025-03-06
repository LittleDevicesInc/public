#!/usr/bin/env python3
import sys
import ipaddress
import argparse
import subprocess

# Check for dependencies before importing them
try:
    import re
    import glob
    import os
    import subprocess
    from datetime import datetime, timedelta
    import random
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    import numpy as np
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    import io
    import math
    import tempfile
    import markdown
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration
    import json
    import urllib.request
    import pytz
except ImportError as e:
    print(f"Error: Missing dependency - {str(e).split()[-1]}")
    print("\nPlease follow the installation instructions in the README.md:")
    print("1. Create a virtual environment: python -m venv .venv")
    print("2. Activate the virtual environment:")
    print("   - Linux/Mac: source .venv/bin/activate")
    print("   - Windows: .venv\\Scripts\\activate")
    print("3. Install dependencies: pip install -r requirements.txt")
    print("\nRunning this tool directly from system Python is not recommended.")
    sys.exit(1)

# Check if running in a virtual environment
def in_virtualenv():
    return (hasattr(sys, 'real_prefix') or
            (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

if not in_virtualenv():
    print("Warning: This tool is not running in a virtual environment.")
    print("For best results, please follow the installation instructions in README.md.")
    print("Continue anyway? (y/n)")
    response = input().strip().lower()
    if response != 'y':
        print("Exiting. Please set up and activate a virtual environment before running.")
        sys.exit(0)
    print("Continuing without virtual environment...")

# OUI database for MAC address lookup
OUI_DB = {}

def load_oui_database():
    """
    Load the OUI database from the IEEE website or a local cache.
    Returns a dictionary mapping MAC address prefixes to manufacturer names.
    """
    global OUI_DB
    cache_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'oui_cache.json')

    # Try to load from cache first
    try:
        if os.path.exists(cache_file) and (datetime.now() - datetime.fromtimestamp(os.path.getmtime(cache_file))).days < 30:
            with open(cache_file, 'r') as f:
                OUI_DB = json.load(f)
                print(f"Loaded OUI database from cache with {len(OUI_DB)} entries")
                return OUI_DB
    except Exception as e:
        print(f"Error loading OUI cache: {e}")

    # If cache doesn't exist or is too old, try to download
    try:
        print("Downloading OUI database...")
        url = "https://raw.githubusercontent.com/silverwind/oui-data/master/index.json"
        with urllib.request.urlopen(url, timeout=10) as response:
            OUI_DB = json.loads(response.read().decode('utf-8'))

        # Save to cache
        with open(cache_file, 'w') as f:
            json.dump(OUI_DB, f)

        print(f"Downloaded OUI database with {len(OUI_DB)} entries")
        return OUI_DB
    except Exception as e:
        print(f"Error downloading OUI database: {e}")

        # If download fails, try to use an existing cache even if it's old
        if os.path.exists(cache_file):
            try:
                with open(cache_file, 'r') as f:
                    OUI_DB = json.load(f)
                    print(f"Using old OUI cache with {len(OUI_DB)} entries")
                    return OUI_DB
            except:
                pass

        # If all else fails, return an empty dictionary
        return {}

def get_manufacturer_from_mac(mac_address):
    """
    Look up the manufacturer name from a MAC address using the OUI database.

    Args:
        mac_address (str): MAC address in any format

    Returns:
        str: Manufacturer name or "Unknown"
    """
    if not OUI_DB:
        load_oui_database()

    # Normalize MAC address format
    mac = mac_address.upper().replace(':', '').replace('-', '').replace('.', '')

    # Check if it's a valid MAC address
    if not re.match(r'^[0-9A-F]{12}$', mac):
        return "Unknown"

    # Get the OUI prefix (first 6 characters)
    oui = mac[:6]

    # Look up in the database
    manufacturer = OUI_DB.get(oui)
    if manufacturer:
        # Return just the first line (company name)
        return manufacturer.split('\n')[0]

    return "Unknown"

def analyze_ping_file(filename):
    """Analyze a ping file for missing pings and abnormal intervals."""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filename}: {str(e)}")
        return None

    # Extract IP/MAC address from first line if available
    target_address = "Unknown"
    target_domain = None
    mac_address = None

    # Try to extract MAC address from filename
    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', filename)
    if mac_match:
        mac_address = mac_match.group(0)

    # Extract IP from ping command line
    ip_match = re.search(r'PING\s+(\S+)(?:\s+\((\S+)\))?', lines[0]) if lines else None
    if ip_match:
        # Could be domain (IP) or just IP
        if ip_match.group(2):  # Has both domain and IP
            target_domain = ip_match.group(1)
            target_address = ip_match.group(2)
        else:
            target_address = ip_match.group(1)

    # If no MAC in filename, try to find it in the ping output
    if not mac_address:
        for line in lines:
            # Look for ARP responses or other MAC address mentions
            mac_in_line = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
            if mac_in_line:
                mac_address = mac_in_line.group(0)
                break

        # If still no MAC address, try ARP lookup if it's a private IP
        if not mac_address and is_private_ip(target_address):
            print(f"Attempting to get MAC address for {target_address} using ARP...")
            mac_address = get_mac_from_ip(target_address)
            if mac_address:
                print(f"Found MAC address: {mac_address}")

    # Check if the file has timestamp data (using -D option)
    has_timestamps = any(re.search(r'^\[\d+\.\d+\]', line) for line in lines if line.strip())

    # Extract ping times and sequence numbers
    ping_times = []
    sequences = []
    timestamps = []

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Extract timestamp if available
        timestamp = None
        if has_timestamps:
            ts_match = re.search(r'^\[(\d+\.\d+)\]', line)
            if ts_match:
                timestamp = float(ts_match.group(1))

        # Extract sequence number and ping time
        seq_match = re.search(r'icmp_seq=(\d+)', line)
        time_match = re.search(r'time=(\d+\.?\d*)', line)

        if seq_match and time_match:
            seq_num = int(seq_match.group(1))
            ping_time = float(time_match.group(1))

            sequences.append(seq_num)
            ping_times.append(ping_time)
            if timestamp:
                timestamps.append(timestamp)

    # If no pings were found, return None
    if not ping_times:
        return None

    # Find missing sequences
    if sequences:
        expected_sequences = set(range(min(sequences), max(sequences) + 1))
        actual_sequences = set(sequences)
        missing_sequences = sorted(expected_sequences - actual_sequences)
    else:
        missing_sequences = []

    # Calculate intervals between timestamps
    intervals = []
    abnormal_intervals = []

    if len(timestamps) > 1:
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)

            # Check for abnormal intervals (more than 2x the median)
            if len(intervals) > 5:  # Wait until we have enough data
                median_interval = sorted(intervals[-10:])[len(intervals[-10:]) // 2]
                if interval > 2 * median_interval:
                    abnormal_intervals.append((i-1, i, interval, median_interval))

    # Get manufacturer if MAC address is available
    manufacturer = None
    if mac_address:
        manufacturer = get_manufacturer_from_mac(mac_address)

    # Return the analysis results
    return {
        "filename": filename,
        "ip": target_address,
        "domain": target_domain,
        "mac_address": mac_address,
        "manufacturer": manufacturer,
        "times": ping_times,
        "sequences": sequences,
        "timestamps": timestamps,
        "missing_sequences": missing_sequences,
        "intervals": intervals,
        "abnormal_intervals": abnormal_intervals,
        "has_timestamps": has_timestamps
    }


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


def check_screen_available():
    """Check if screen is available on the system."""
    try:
        subprocess.run(['screen', '-version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False


def cleanup_old_screen_sessions():
    """Clean up completed screen sessions older than 24 hours."""
    try:
        # List all screen sessions
        result = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        if result.returncode != 0:
            return

        # Find completed sessions (status: "Dead")
        for line in result.stdout.split('\n'):
            if 'Dead' in line:
                # Extract session ID
                session_id = line.split()[0]
                # Remove the session
                subprocess.run(['screen', '-wipe'])
                print(f"Cleaned up dead screen session: {session_id}")
    except Exception as e:
        print(f"Warning: Could not clean up screen sessions: {str(e)}")


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

    # Build the ping command
    cmd = ["ping"]

    # Always use -D option for timestamps unless explicitly disabled
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
    print(f"Note: Using -D option for timestamps to enable time series analysis")

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


def categorize_devices(items, item_type='target'):
    """
    Unified function to categorize network devices.

    Args:
        items: List of items to categorize (can be filenames or IP addresses/hostnames)
        item_type: Type of items to categorize ('target' or 'file')

    Returns:
        Dictionary of categorized items
    """
    # Define standard categories based on item type
    if item_type == 'target':
        categories = {
            'Gateways': [],
            'Switches': [],
            'Access Points': [],
            'VOIP Handsets': [],
            'Public Hosts': [],
            'LAN Hosts': []
        }
    else:  # file type
        categories = {
            'mac': [],
            'ap': [],
            'gw': [],
            'switch': [],
            'fw': [],
            'host': [],
            'ip': [],
            'other': []
        }

    # IPv4 address pattern
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

    # Device type identifiers
    device_types = {
        'ap': ['ap', 'aps', 'access-point', 'accesspoint', 'access_point'],
        'gw': ['gw', 'gateway', 'gtw'],
        'switch': ['switch', 'sw'],
        'fw': ['fw', 'firewall'],
        'voip': ['voip', 'phone', 'telephony'],
        'host': ['host', 'device', 'client']
    }

    # Process each item
    for item in items:
        if item_type == 'file':
            # Process filename
            lowercase_name = os.path.basename(item).lower()

            # Check for MAC addresses
            if is_mac_address_in_filename(item):
                categories['mac'].append(item)
                continue

            # Check for device types with various delimiters
            categorized = False
            for category, identifiers in device_types.items():
                for identifier in identifiers:
                    # Word boundaries or common delimiters
                    patterns = [
                        fr'\b{identifier}\b',  # Whole word
                        fr'[_\-\.]{identifier}[_\-\.]',  # With delimiters
                        fr'^{identifier}[_\-\.]',  # At start with delimiter
                        fr'[_\-\.]{identifier}$'   # At end with delimiter
                    ]

                    if any(re.search(pattern, lowercase_name) for pattern in patterns):
                        if category in categories:
                            categories[category].append(item)
                        else:
                            # For backward compatibility with old category names
                            categories['other'].append(item)
                        categorized = True
                        break

                if categorized:
                    break

            # If not categorized by device type, check for IP address
            if not categorized and re.search(ip_pattern, item):
                categories['ip'].append(item)
                continue

            # If still not categorized, put in "other"
            if not categorized:
                categories['other'].append(item)

        else:  # target type
            # Process IP/hostname
            # Check if it's an IP address
            if re.match(ip_pattern, item):
                if is_private_ip(item):
                    categories['LAN Hosts'].append(item)
                else:
                    categories['Public Hosts'].append(item)
            else:
                # Try to categorize based on hostname patterns
                categorized = False
                for device_type, identifiers in device_types.items():
                    for identifier in identifiers:
                        if identifier in item.lower():
                            if device_type == 'gw':
                                categories['Gateways'].append(item)
                            elif device_type == 'switch':
                                categories['Switches'].append(item)
                            elif device_type == 'ap':
                                categories['Access Points'].append(item)
                            elif device_type == 'voip':
                                categories['VOIP Handsets'].append(item)
                            else:
                                # Default to LAN hosts for other device types
                                categories['LAN Hosts'].append(item)
                            categorized = True
                            break
                    if categorized:
                        break

                # If not categorized, assume it's a LAN host
                if not categorized:
                    categories['LAN Hosts'].append(item)

    # Remove empty categories
    return {k: v for k, v in categories.items() if v}


# Legacy function for backward compatibility
def categorize_ping_files(files):
    """Legacy function that calls the unified categorize_devices function."""
    return categorize_devices(files, item_type='file')


# Legacy function for backward compatibility
def categorize_targets(targets):
    """Legacy function for backward compatibility."""
    categorized = {}

    # Initialize standard categories
    standard_categories = ['Gateways', 'Switches', 'Access Points', 'VOIP Handsets', 'Public Hosts', 'LAN Hosts']
    for category in standard_categories:
        categorized[category] = []

    # Process user-provided categories
    for category, hosts in targets.items():
        if category in standard_categories:
            categorized[category].extend(hosts)
        elif category == 'Hosts' or category == 'Other':
            # Categorize hosts using the new function
            categorized_hosts = categorize_devices(hosts, item_type='target')
            for host_category, host_list in categorized_hosts.items():
                if host_category in categorized:
                    categorized[host_category].extend(host_list)
        else:
            # For any custom categories, keep them as is
            categorized[category] = hosts

    # Remove empty categories
    return {k: v for k, v in categorized.items() if v}


def create_visualization(results, output_dir='visualizations'):
    """
    Create visualizations for ping results and save them to the specified output directory.

    Args:
        results (dict): Dictionary containing ping results
        output_dir (str): Directory to save visualizations

    Returns:
        str: Path to the output directory
    """
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import os
    from datetime import datetime
    import numpy as np

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Clear any existing plots
    plt.close('all')

    # Group results by device type
    device_types = {
        'access_points': {},
        'gateways': {},
        'voip_phones': {},
        'switches': {}
    }

    # Process all devices, even those without timestamps
    for device_name, device_data in results.items():
        device_type = 'switches'  # default category

        if 'access_point' in device_name:
            device_type = 'access_points'
        elif 'gateway' in device_name:
            device_type = 'gateways'
        elif 'voip' in device_name:
            device_type = 'voip_phones'
        elif 'switch' in device_name:
            device_type = 'switches'

        device_types[device_type][device_name] = device_data

    # Create a simple line chart for each device type showing response times
    for device_type, devices in device_types.items():
        if not devices:
            continue

        plt.figure(figsize=(12, 8))

        # Color palette
        colors = plt.cm.tab10.colors

        # For devices without timestamps, create a simple line chart
        for i, (device_name, device_data) in enumerate(devices.items()):
            if len(device_data['times']) > 0:
                # Use sequence numbers or just indices if no timestamps
                x_values = list(range(len(device_data['times'])))

                # If we have timestamps, use those instead
                if 'timestamps' in device_data and device_data['timestamps'] and len(device_data['timestamps']) == len(device_data['times']):
                    x_values = [datetime.fromtimestamp(ts) for ts in device_data['timestamps']]

                # Plot with a specific color from the palette
                color_idx = i % len(colors)
                plt.plot(x_values, device_data['times'],
                         label=f"{device_name} ({device_data['ip']})",
                         linewidth=1.5,
                         color=colors[color_idx],
                         alpha=0.8)

        # Set title and labels
        plt.title(f'Ping Response Times for {device_type.replace("_", " ").title()}', fontsize=16)

        # If we used timestamps, format x-axis accordingly
        if any('timestamps' in device_data and device_data['timestamps'] for device_data in devices.values()):
            plt.xlabel('Time', fontsize=12)
            plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
            plt.gca().xaxis.set_major_locator(mdates.AutoDateLocator())
            plt.gcf().autofmt_xdate()
        else:
            plt.xlabel('Sequence Number', fontsize=12)

        plt.ylabel('Response Time (ms)', fontsize=12)

        # Add grid
        plt.grid(True, linestyle='--', alpha=0.7)

        # Add legend (only if there are not too many devices)
        if len(devices) <= 15:
            plt.legend(loc='upper right', fontsize=10)

        # Adjust layout
        plt.tight_layout()

        # Save the figure
        output_file = os.path.join(output_dir, f'{device_type}_ping_times.svg')
        plt.savefig(output_file, format='svg', bbox_inches='tight')
        print(f"Saved visualization to {output_file}")

        # Close the figure to free memory
        plt.close()

    # Create a horizontal line chart showing average response times by device
    plt.figure(figsize=(12, 8))

    # Collect data for horizontal bar chart
    device_names = []
    avg_times = []
    device_colors = []

    # Color mapping for device types
    type_colors = {
        'access_points': 'blue',
        'gateways': 'green',
        'voip_phones': 'red',
        'switches': 'orange'
    }

    # Collect data for all devices
    for device_type, devices in device_types.items():
        for device_name, device_data in devices.items():
            if device_data['times']:
                device_names.append(f"{device_name} ({device_data['ip']})")
                avg_times.append(sum(device_data['times']) / len(device_data['times']))
                device_colors.append(type_colors[device_type])

    # Sort by average time
    sorted_indices = np.argsort(avg_times)
    sorted_names = [device_names[i] for i in sorted_indices]
    sorted_times = [avg_times[i] for i in sorted_indices]
    sorted_colors = [device_colors[i] for i in sorted_indices]

    # Create horizontal bar chart
    plt.barh(sorted_names, sorted_times, color=sorted_colors, alpha=0.7)
    plt.xlabel('Average Response Time (ms)', fontsize=12)
    plt.ylabel('Device', fontsize=12)
    plt.title('Average Ping Response Time by Device', fontsize=16)
    plt.grid(True, linestyle='--', alpha=0.5, axis='x')

    # Add a legend for device types
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=color, label=device_type.replace('_', ' ').title())
                      for device_type, color in type_colors.items()]
    plt.legend(handles=legend_elements, loc='lower right')

    # Adjust layout
    plt.tight_layout()

    # Save the figure
    output_file = os.path.join(output_dir, 'average_response_times.svg')
    plt.savefig(output_file, format='svg', bbox_inches='tight')
    print(f"Saved visualization to {output_file}")

    # Close the figure
    plt.close()

    print(f"Visualizations saved to: {output_dir}/")
    return output_dir


def generate_pdf_report(results, output_file, visualizations_dir=None):
    """
    Generate a PDF report from ping results.

    Args:
        results (dict): Dictionary containing ping results
        output_file (str): Output PDF file path
        visualizations_dir (str, optional): Directory containing visualizations
    """
    import os
    import markdown
    from weasyprint import HTML, CSS
    from weasyprint.text.fonts import FontConfiguration

    # Calculate packet loss for each device
    for device_name, device_data in results.items():
        if 'sequences' in device_data and device_data['sequences']:
            # Only calculate if we have sequence numbers
            if len(device_data['sequences']) > 0:
                total_expected = max(device_data['sequences']) - min(device_data['sequences']) + 1
                total_received = len(device_data['sequences'])
                # Ensure we don't have negative packet loss
                if total_expected >= total_received:
                    packet_loss = ((total_expected - total_received) / total_expected) * 100
                else:
                    # If we somehow have more received than expected, set to 0
                    packet_loss = 0
            else:
                packet_loss = 0
        else:
            # If no sequence data, calculate based on missing_sequences if available
            if 'missing_sequences' in device_data and device_data['times']:
                total_missing = len(device_data['missing_sequences'])
                total_received = len(device_data['times'])
                total_expected = total_received + total_missing
                if total_expected > 0:
                    packet_loss = (total_missing / total_expected) * 100
                else:
                    packet_loss = 0

        device_data['packet_loss'] = packet_loss

    # Group devices by type
    gateways = {}
    switches = {}
    access_points = {}
    voip_phones = {}
    voip_providers = {}  # New category for VoIP providers
    lan_hosts = {}  # LAN hosts (private IP addresses)
    public_hosts = {}  # Public hosts (public IP addresses)
    web_services = {}  # Web services (domains and public web servers)

    for device_name, device_data in results.items():
        # Get device profile for categorization
        profile = get_device_network_profile(device_name, device_data)

        # Try to get hostname for public IPs
        if not profile['is_lan'] and 'hostname' not in device_data:
            hostname = lookup_hostname_for_ip(device_data.get('ip', ''))
            if hostname:
                device_data['hostname'] = hostname

        if profile['is_voip_provider']:
            voip_providers[device_name] = device_data
        elif 'gateway' in device_name:
            gateways[device_name] = device_data
        elif 'switch' in device_name:
            switches[device_name] = device_data
        elif 'access_point' in device_name:
            access_points[device_name] = device_data
        elif profile['is_voip_device']:
            voip_phones[device_name] = device_data
        elif profile['is_web_service']:
            web_services[device_name] = device_data
        else:
            # For hosts, check if the IP is private or public
            ip = device_data.get('ip', '')
            if is_private_ip(ip):
                lan_hosts[device_name] = device_data
            else:
                public_hosts[device_name] = device_data

    # Calculate overall statistics
    total_devices = len(results)
    total_pings = sum(len(data['times']) for data in results.values())
    missing_pings = sum(len(data.get('missing_sequences', [])) for data in results.values())
    abnormal_intervals = sum(len(data.get('abnormal_intervals', [])) for data in results.values())

    all_times = []
    for data in results.values():
        all_times.extend(data['times'])

    min_time = min(all_times) if all_times else 0
    max_time = max(all_times) if all_times else 0
    avg_time = sum(all_times) / len(all_times) if all_times else 0

    # Calculate overall packet loss
    total_expected_pings = total_pings + missing_pings
    overall_packet_loss = (missing_pings / total_expected_pings) * 100 if total_expected_pings > 0 else 0

    # Get current time in PST
    pst_timezone = pytz.timezone('America/Los_Angeles')
    current_time_pst = datetime.now(pst_timezone)

    # Find problematic devices (high latency or packet loss)
    high_latency_threshold = avg_time * 1.5  # 50% higher than average
    high_packet_loss_threshold = 5.0  # 5% packet loss or higher

    problematic_devices = []
    for device_name, device_data in results.items():
        device_avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
        packet_loss = device_data.get('packet_loss', 0)

        if device_avg_time > high_latency_threshold or packet_loss > high_packet_loss_threshold:
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            issue = []
            if device_avg_time > high_latency_threshold:
                issue.append(f"high latency ({device_avg_time:.2f}ms)")
            if packet_loss > high_packet_loss_threshold:
                issue.append(f"packet loss ({packet_loss:.2f}%)")

            problematic_devices.append({
                'name': display_name,
                'ip': device_data['ip'],
                'avg_time': device_avg_time,
                'packet_loss': packet_loss,
                'issue': ', '.join(issue)
            })

    # Sort problematic devices by severity (packet loss first, then latency)
    problematic_devices.sort(key=lambda x: (x['packet_loss'], x['avg_time']), reverse=True)

    # Generate markdown content
    markdown_content = f"""
# Network Ping Analysis Report
*Generated on {current_time_pst.strftime('%B %d, %Y at %I:%M:%S %p %Z')}*

## Summary

**Total Devices Tested:** {total_devices}"""

    # Only include device types that have devices
    if len(gateways) > 0:
        markdown_content += f"\n\n**Gateways:** {len(gateways)}"
    if len(switches) > 0:
        markdown_content += f"\n\n**Switches:** {len(switches)}"
    if len(access_points) > 0:
        markdown_content += f"\n\n**Access Points:** {len(access_points)}"
    if len(voip_providers) > 0:
        markdown_content += f"\n\n**VoIP Providers:** {len(voip_providers)}"
    if len(voip_phones) > 0:
        markdown_content += f"\n\n**VOIP Handsets:** {len(voip_phones)}"
    if len(web_services) > 0:
        markdown_content += f"\n\n**Web Services:** {len(web_services)}"
    if len(lan_hosts) > 0:
        markdown_content += f"\n\n**LAN Hosts:** {len(lan_hosts)}"
    if len(public_hosts) > 0:
        markdown_content += f"\n\n**Public Hosts:** {len(public_hosts)}"

    markdown_content += f"""

## Overall Performance

| Metric | Value |
|--------|-------|
| Total Pings | {total_pings:,} |
| Missing Pings | {missing_pings:,} |
| Packet Loss | {overall_packet_loss:.2f}% |
| Abnormal Intervals | {abnormal_intervals:,} |
| Min Response Time | {min_time:.2f}ms |
| Max Response Time | {max_time:.2f}ms |
| Avg Response Time | {avg_time:.2f}ms |

## Network Performance Guidelines

### LAN (Local Area Network) Thresholds
For private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)

**Latency:**
- Under 1ms: Excellent
- 1-5ms: Good
- 5-10ms: Acceptable
- Over 10ms: Investigate potential issues

**Packet Loss:**
- 0%: Optimal
- 0.1-0.5%: Acceptable
- Over 0.5%: Investigate immediately

### WAN/Public Services Thresholds

**Latency:**
- Under 20ms: Excellent (for regional connections)
- 20-50ms: Good
- 50-100ms: Acceptable
- 100-150ms: Borderline
- Over 150ms: Investigate (unless for very distant connections)

**Packet Loss:**
- 0%: Optimal
- 0.1-1%: Acceptable for most applications
- 1-2.5%: May impact real-time applications (VoIP, video)
- Over 2.5%: Investigate immediately

### Application-Specific Considerations

**VoIP/Video Conferencing:**
- Latency: Under 150ms
- Jitter: Under 30ms
- Packet Loss: Under 1%

**Web Services:**
- Latency: Under 300ms
- Packet Loss: Under 2%

## Device Performance
"""

    # Only include sections for device types that have devices
    if gateways:
        markdown_content += f"""
### Gateways

| Device | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|--------|------------|---------|--------------|--------------|------------|-------|
"""
        # Add gateway data
        for device_name, device_data in sorted(gateways.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get evaluations
            latency_status = evaluate_latency(avg_time, is_lan=profile['is_lan'])[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=profile['is_lan'])[1]

            markdown_content += f"| {display_name} | {device_data['ip']} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Only include switches section if there are switches
    if switches:
        markdown_content += f"""
### Switches

| Device | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|--------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(switches.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get evaluations
            latency_status = evaluate_latency(avg_time, is_lan=profile['is_lan'])[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=profile['is_lan'])[1]

            markdown_content += f"| {display_name} | {device_data['ip']} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Only include access points section if there are access points
    if access_points:
        markdown_content += f"""
### Access Points

| Device | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|--------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(access_points.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get evaluations
            latency_status = evaluate_latency(avg_time, is_lan=profile['is_lan'])[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=profile['is_lan'])[1]

            markdown_content += f"| {display_name} | {device_data['ip']} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Only include VoIP providers section if there are VoIP providers
    if voip_providers:
        markdown_content += f"""
### VoIP Providers

| Provider | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|----------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(voip_providers.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get hostname if available
            ip_display = device_data.get('hostname', device_data['ip']) if 'hostname' in device_data else device_data['ip']

            # Get evaluations (VoIP specific)
            latency_status = evaluate_latency(avg_time, is_lan=False)[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=False, is_voip=True)[1]

            markdown_content += f"| {display_name} | {ip_display} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Only include VoIP phones section if there are VoIP phones
    if voip_phones:
        markdown_content += f"""
### VOIP Handsets

| Device | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|--------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(voip_phones.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get evaluations (VoIP specific)
            latency_status = evaluate_latency(avg_time, is_lan=profile['is_lan'])[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=profile['is_lan'], is_voip=True)[1]

            markdown_content += f"| {display_name} | {device_data['ip']} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Add Web Services section if there are any
    if web_services:
        markdown_content += f"""
### Web Services

| Service | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|---------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(web_services.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get hostname if available
            ip_display = device_data.get('hostname', device_data['ip']) if 'hostname' in device_data else device_data['ip']

            # Get evaluations (Web specific)
            latency_status = evaluate_latency(avg_time, is_lan=False)[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=False, is_web=True)[1]

            markdown_content += f"| {display_name} | {ip_display} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Only include LAN hosts section if there are LAN hosts
    if lan_hosts:
        markdown_content += f"""
### LAN Hosts

| Device | IP | MAC Address | Manufacturer | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status |
|--------|------------|------------|------------|---------|--------------|--------------|------------|
"""
        for device_name, device_data in sorted(lan_hosts.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)
            mac_address = device_data.get('mac_address', 'Unknown')
            manufacturer = device_data.get('manufacturer', 'Unknown')

            # Get evaluations (LAN specific)
            latency_status = evaluate_latency(avg_time, is_lan=True)[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=True)[1]

            markdown_content += f"| {display_name} | {device_data['ip']} | {mac_address} | {manufacturer} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} |\n"

    # Only include public hosts section if there are public hosts
    if public_hosts:
        markdown_content += f"""
### Public Hosts

| Device | IP | Avg (ms) | Latency Status | Packet Loss (%) | Loss Status | Pings |
|--------|------------|---------|--------------|--------------|------------|-------|
"""
        for device_name, device_data in sorted(public_hosts.items()):
            # Clean up device name for display
            display_name = clean_device_name(device_name)

            # Get network profile
            profile = get_device_network_profile(device_name, device_data)

            # Calculate metrics
            avg_time = sum(device_data['times']) / len(device_data['times']) if device_data['times'] else 0
            min_time = min(device_data['times']) if device_data['times'] else 0
            max_time = max(device_data['times']) if device_data['times'] else 0
            packet_loss = device_data.get('packet_loss', 0)

            # Get hostname if available
            ip_display = device_data.get('hostname', device_data['ip']) if 'hostname' in device_data else device_data['ip']

            # Get evaluations (WAN specific)
            latency_status = evaluate_latency(avg_time, is_lan=False)[1]
            packet_loss_status = evaluate_packet_loss(packet_loss, is_lan=False)[1]

            markdown_content += f"| {display_name} | {ip_display} | {avg_time:.2f} | {latency_status} | {packet_loss:.2f} | {packet_loss_status} | {len(device_data['times']):,} |\n"

    # Add visualizations if available
    if visualizations_dir and os.path.exists(visualizations_dir):
        visualization_files = [f for f in os.listdir(visualizations_dir) if f.endswith('.svg')]

        if visualization_files:
            markdown_content += f"""

## Visualizations

The following visualizations show ping response times for different device types:

"""
            for viz_file in visualization_files:
                file_name = viz_file
                viz_path = os.path.join(visualizations_dir, viz_file)
                markdown_content += f"![{file_name}]({viz_path})\n\n"

    # Add actionable observations and recommendations based on actual data
    markdown_content += f"""

## Observations and Recommendations

### Critical Issues Detected

"""

    if problematic_devices:
        markdown_content += "The following devices are experiencing connectivity issues:\n\n"
        markdown_content += "| Device | IP | Issue | Avg Response | Packet Loss |\n"
        markdown_content += "|--------|------------|---------|---------|--------|\n"

        for device in problematic_devices[:10]:  # Show top 10 most problematic devices
            markdown_content += f"| {device['name']} | {device['ip']} | {device['issue']} | {device['avg_time']:.2f}ms | {device['packet_loss']:.2f}% |\n"

        # Add specific recommendations based on the issues found
        markdown_content += f"""

### Recommended Actions

1. **Investigate Network Segment Issues**: {len(problematic_devices)} devices are experiencing performance issues. Check network switches and cabling in affected areas.

2. **Prioritize High Packet Loss Devices**: Devices with packet loss above 5% should be investigated immediately, as this indicates connectivity problems.

3. **Monitor High Latency Devices**: Devices with response times above {high_latency_threshold:.2f}ms (network average: {avg_time:.2f}ms) may indicate local network congestion or hardware issues.

4. **Schedule Maintenance**: Consider scheduling maintenance for the most problematic devices identified above.

5. **Implement Regular Testing**: Set up automated ping tests during both peak and off-peak hours to better identify patterns.

"""
    else:
        markdown_content += """
* No critical issues were detected in this analysis. All devices are operating within normal parameters.

### Recommended Actions

1. **Continue Monitoring**: Maintain regular network monitoring to ensure continued performance.

2. **Establish Baselines**: Use these results to establish baseline performance metrics for future comparison.

3. **Expand Testing**: Consider expanding testing to include more devices and external targets.

"""

    # Convert markdown to HTML
    html_content = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])

    # Create a temporary HTML file
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
        temp_html.write(html_content.encode('utf-8'))
        temp_html_path = temp_html.name

    # Convert HTML to PDF
    font_config = FontConfiguration()
    html = HTML(filename=temp_html_path)
    css = CSS(string=f'''
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #652c90; color: white; }}
        h1, h2, h3 {{ color: #652c90; }}
        h1 {{ border-bottom: 2px solid #652c90; padding-bottom: 10px; }}
        h2 {{ border-bottom: 1px solid #652c90; padding-bottom: 5px; }}
        img {{ max-width: 100%; height: auto; }}
        blockquote {{ background-color: #f9f2ff; border-left: 4px solid #652c90; padding: 10px; margin: 20px 0; }}
    ''', font_config=font_config)

    # Generate PDF
    html.write_pdf(output_file, stylesheets=[css])

    # Clean up temporary file
    os.unlink(temp_html_path)

    return output_file


def generate_summary_report(results, skip_pdf=False):
    """Generate a summary report of ping analysis results."""
    # Count total files analyzed
    total_files = sum(len(device_results) for device_results in results.values())

    print("\n===== Ping Analysis Summary =====")
    print(f"Total files analyzed: {total_files}")

    # Calculate overall statistics
    total_pings = sum(len(data['times']) for data in results.values())
    missing_pings = sum(len(data.get('missing_sequences', [])) for data in results.values())
    abnormal_intervals = sum(len(data.get('abnormal_intervals', [])) for data in results.values())

    all_times = []
    for data in results.values():
        all_times.extend(data['times'])

    min_time = min(all_times) if all_times else 0
    max_time = max(all_times) if all_times else 0
    avg_time = sum(all_times) / len(all_times) if all_times else 0

    print(f"\nOverall Statistics:")
    print(f"  Total Pings: {total_pings:,}")
    print(f"  Missing Pings: {missing_pings:,}")
    print(f"  Abnormal Intervals: {abnormal_intervals:,}")
    print(f"  Min Response Time: {min_time:.2f}ms")
    print(f"  Max Response Time: {max_time:.2f}ms")
    print(f"  Avg Response Time: {avg_time:.2f}ms")

    # Group devices by type
    access_points = {}
    gateways = {}
    voip_phones = {}
    switches = {}

    for device_name, device_data in results.items():
        if 'access_point' in device_name:
            access_points[device_name] = device_data
        elif 'gateway' in device_name:
            gateways[device_name] = device_data
        elif 'voip' in device_name:
            voip_phones[device_name] = device_data
        elif 'switch' in device_name:
            switches[device_name] = device_data

    # Print device type summaries
    if access_points:
        print(f"\nAccess Points ({len(access_points)}):")
        for name, data in sorted(access_points.items()):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            print(f"  {name} ({data['ip']}): {avg_time:.2f}ms avg, {len(data['times']):,} pings")

    if gateways:
        print(f"\nGateways ({len(gateways)}):")
        for name, data in sorted(gateways.items()):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            print(f"  {name} ({data['ip']}): {avg_time:.2f}ms avg, {len(data['times']):,} pings")

    if voip_phones:
        print(f"\nVOIP Handsets ({len(voip_phones)}):")
        for name, data in sorted(voip_phones.items()):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            print(f"  {name} ({data['ip']}): {avg_time:.2f}ms avg, {len(data['times']):,} pings")

    if switches:
        print(f"\nSwitches ({len(switches)}):")
        for name, data in sorted(switches.items()):
            avg_time = sum(data['times']) / len(data['times']) if data['times'] else 0
            print(f"  {name} ({data['ip']}): {avg_time:.2f}ms avg, {len(data['times']):,} pings")

    print("\n=================================")

    # Generate PDF report if not skipped
    if not skip_pdf:
        try:
            pdf_file = "ping_analysis_report.pdf"
            generate_pdf_report(results, pdf_file)
            print(f"\nPDF report generated: {pdf_file}")
        except ImportError:
            print("\nReportLab library not installed. Install with: pip install reportlab")
        except Exception as e:
            print(f"\nError generating PDF report: {str(e)}")
            import traceback
            traceback.print_exc()


def parse_args():
    """Parse command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="A comprehensive tool for initiating and analyzing ping log files. "
                    "Detects issues such as missed pings, abnormal response times, and network latency patterns.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Output and pattern options
    parser.add_argument("-o", "--output", metavar="FILE", help="Write report to FILE")
    parser.add_argument("-p", "--pattern", metavar="PATTERN", help="Specify file pattern (default: *ping*.txt or *ping*.log)")

    # Ping options
    parser.add_argument("--ping", metavar="TARGET", help="Start a ping to the specified target")
    parser.add_argument("--count", type=int, metavar="N", help="Number of pings to send (optional)")
    parser.add_argument("--interval", type=float, metavar="SEC", help="Interval between pings in seconds (optional)")
    parser.add_argument("--ping-output", metavar="FILE", help="Output file for ping results (optional)")
    parser.add_argument("--no-timestamp", action="store_true", help="Don't use -D timestamp option when starting a ping")

    # Report and visualization options
    parser.add_argument("--pdf", metavar="FILE", help="Generate a PDF report (default: ping_analysis_report.pdf)")
    parser.add_argument("--visualize", action="store_true", help="Generate visualizations from ping data")

    # Other options
    parser.add_argument("--generate-test-files", action="store_true", help="Generate test ping files for demonstration")

    # Files to analyze (positional arguments)
    parser.add_argument("files", nargs="*", help="Files or patterns to analyze")

    # Add important notes as epilog
    parser.epilog = """
Important Notes:
  - The -D timestamp option is enabled by default and recommended for all pings
    as it allows for time series analysis and visualization.
  - For best results, always use the --visualize option with the --pdf option
    to include visualizations in the PDF report.

Examples:
  ping-tool --ping 8.8.8.8 --count 100
  ping-tool --pdf report.pdf ping_logs/*.log
  ping-tool --visualize ping_logs/*.log
  ping-tool --pdf network_report.pdf --visualize ping_logs/*.log
"""

    # Parse arguments
    parsed_args = parser.parse_args()

    # Convert to the expected dictionary format for backward compatibility
    args = {
        "output_file": parsed_args.output,
        "pattern": parsed_args.pattern,
        "files": parsed_args.files,
        "ping_target": parsed_args.ping,
        "ping_count": parsed_args.count,
        "ping_interval": parsed_args.interval,
        "ping_output": parsed_args.ping_output,
        "no_timestamp": parsed_args.no_timestamp,
        "generate_test_files": parsed_args.generate_test_files,
        "pdf_output": parsed_args.pdf,
        "visualize": parsed_args.visualize
    }

    return args


def clean_device_name(device_name):
    """
    Clean up device names by removing redundant type prefixes.
    For example: 'voip_phone-VOIP-Austin' becomes 'Austin'
    """
    # Define patterns to clean up
    patterns = [
        # Common device type prefixes
        r'^voip_phone-VOIP-', r'^voip-voip_phone-', r'^voip-', r'^voip_phone-',
        r'^access_point-AP-', r'^ap-access_point-', r'^ap-', r'^access_point-',
        r'^switch-SW-', r'^sw-switch-', r'^sw-', r'^switch-',
        r'^gateway-GW-', r'^gw-gateway-', r'^gw-', r'^gateway-',
        # Standard replacements
        r'gw-gateway', r'sw-switch', r'ap-access_point', r'voip-voip_phone'
    ]

    # Apply all the patterns
    result = device_name
    for pattern in patterns:
        result = re.sub(pattern, '', result, flags=re.IGNORECASE)

    # Apply special hostname mappings if needed
    mappings = {
        'dns_service-google-dns': 'dns.google.com',
        'dns_service-comodo-dns': 'dns.quad9.net',
        'server-db.acme.com': 'db.acme.com',
        'server-api.oscorp.org': 'api.oscorp.org',
        'server-mail.wayne.co': 'mail.wayne.co',
        'server-media.acme.org': 'media.acme.org'
    }

    if device_name in mappings:
        return mappings[device_name]

    return result


def generate_test_files(output_dir, num_files=5, duration_hours=24):
    """Generate test ping log files for demonstration purposes."""
    import os
    import random
    import time
    from datetime import datetime, timedelta

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Generating test files in {output_dir}...")

    # Define device types and their typical ping time ranges
    device_types = {
        "ap": {"name": "access_point", "min_ping": 1.5, "max_ping": 8.0, "count": 10},
        "sw": {"name": "switch", "min_ping": 0.8, "max_ping": 5.0, "count": 10},
        "gw": {"name": "gateway", "min_ping": 0.5, "max_ping": 3.0, "count": 8},
        "voip": {"name": "voip_phone", "min_ping": 2.0, "max_ping": 15.0, "count": 30}
    }

    # Create a 7-day window for test data
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)

    # Generate files for each device type
    for device_type, properties in device_types.items():
        # Generate multiple files for each device type
        for i in range(properties["count"]):
            # Create a unique device name and IP
            device_num = random.randint(1, 99)
            device_name = f"{device_type}-{properties['name']}{device_num:02d}"
            ip_address = f"192.168.{random.randint(1, 5)}.{random.randint(1, 254)}"

            # Determine if this will be a problem device (10% chance)
            is_problem_device = random.random() < 0.10

            # Create the file
            filename = os.path.join(output_dir, f"{device_name}.log")
            with open(filename, "w") as f:
                # Write header
                f.write(f"PING {ip_address} ({ip_address}): 56 data bytes\n")

                # Generate ping data across the time window
                # Create 10-20 measurement sessions across the 7 days
                num_sessions = random.randint(10, 20)

                # Distribute sessions across the time window
                session_times = []
                for _ in range(num_sessions):
                    # Random time within the window
                    random_offset = random.random() * (end_time - start_time).total_seconds()
                    session_time = start_time + timedelta(seconds=random_offset)
                    session_times.append(session_time)

                # Sort session times chronologically
                session_times.sort()

                # For each session, generate a series of pings
                total_pings = 0
                total_missing = 0

                for session_idx, session_start in enumerate(session_times):
                    # Each session lasts 5-30 minutes with pings every 1-5 seconds
                    session_duration = timedelta(minutes=random.randint(5, 30))
                    ping_interval = random.randint(1, 5)

                    # Determine ping pattern for this session
                    pattern = random.choice(["flat", "increasing", "decreasing", "fluctuating"])

                    # For problem devices, increase chance of issues in later sessions
                    problem_factor = 0.0
                    if is_problem_device:
                        # Gradually increase problems over time
                        problem_factor = min(0.8, session_idx / (num_sessions * 1.5))

                    # Generate pings for this session
                    current_time = session_start
                    session_end = session_start + session_duration
                    seq_num = 0

                    while current_time < session_end:
                        seq_num += 1
                        total_pings += 1

                        # Determine if this ping should be dropped (simulate packet loss)
                        packet_lost = random.random() < problem_factor

                        if packet_lost:
                            total_missing += 1
                            # Skip writing this ping (simulating packet loss)
                            current_time += timedelta(seconds=ping_interval)
                            continue

                        # Calculate ping time based on pattern
                        base_ping = random.uniform(properties["min_ping"], properties["max_ping"])

                        if pattern == "flat":
                            ping_time = base_ping + random.uniform(-0.5, 0.5)
                        elif pattern == "increasing":
                            # Gradually increase ping time throughout the session
                            progress = (current_time - session_start).total_seconds() / session_duration.total_seconds()
                            ping_time = base_ping + (properties["max_ping"] - base_ping) * progress * 0.8
                            ping_time += random.uniform(-0.3, 0.3)  # Add small variation
                        elif pattern == "decreasing":
                            # Gradually decrease ping time throughout the session
                            progress = (current_time - session_start).total_seconds() / session_duration.total_seconds()
                            ping_time = base_ping + (properties["max_ping"] - base_ping) * (1 - progress) * 0.8
                            ping_time += random.uniform(-0.3, 0.3)  # Add small variation
                        else:  # fluctuating
                            # Create a wave pattern
                            progress = (current_time - session_start).total_seconds() / session_duration.total_seconds()
                            wave = math.sin(progress * 6 * math.pi)  # Multiple waves during session
                            ping_time = base_ping + wave * (properties["max_ping"] - properties["min_ping"]) * 0.4
                            ping_time += random.uniform(-0.2, 0.2)  # Add small variation

                        # For problem devices, occasionally add spikes
                        if is_problem_device and random.random() < 0.05:
                            ping_time *= random.uniform(2.0, 5.0)

                        # Ensure minimum ping time
                        ping_time = max(0.2, ping_time)

                        # Format timestamp
                        timestamp = current_time.strftime("%a %b %d %H:%M:%S %Y")

                        # Write ping entry
                        f.write(f"64 bytes from {ip_address}: icmp_seq={seq_num} ttl=64 time={ping_time:.3f} ms\n")

                        # Add timestamp line (like ping -D option)
                        f.write(f"[{timestamp}]\n")

                        # Move to next ping time
                        current_time += timedelta(seconds=ping_interval)

                # Write summary statistics
                packet_loss = (total_missing / total_pings) * 100 if total_pings > 0 else 0
                f.write(f"\n--- {ip_address} ping statistics ---\n")
                f.write(f"{total_pings} packets transmitted, {total_pings - total_missing} received, {packet_loss:.1f}% packet loss\n")

    print(f"Generated {sum(p['count'] for p in device_types.values())} test files in {output_dir}")
    return output_dir


def generate_text_plot(results, device_type):
    """Generate a text-based plot for a device type."""
    if not results:
        return "No data available"

    # Get the time range and ping range
    timestamps = []
    ping_times = []
    for result in results:
        if result.get("has_timestamps"):
            timestamps.extend(result.get("timestamps", []))
            ping_times.extend(result.get("times", []))

    if not timestamps or not ping_times:
        return "No timestamp data available"

    # Calculate ranges
    time_range = max(timestamps) - min(timestamps)
    ping_range = max(ping_times) - min(ping_times)

    # Create ASCII plot
    width = 80
    height = 20
    plot = [[' ' for _ in range(width)] for _ in range(height)]

    # Plot points
    for ts, ping in zip(timestamps, ping_times):
        x = int((ts - min(timestamps)) / time_range * (width - 1))
        y = int((ping - min(ping_times)) / ping_range * (height - 1))
        if 0 <= x < width and 0 <= y < height:
            plot[y][x] = '.'

    # Add axes
    for i in range(height):
        plot[i][0] = '|'
    for i in range(width):
        plot[height-1][i] = '-'

    # Convert to string
    return '\n'.join(''.join(row) for row in plot)


def analyze_ping_files():
    """Main function to analyze ping files."""
    args = parse_args()

    # Handle test file generation
    if args["generate_test_files"]:
        generate_test_files("test_ping_files")
        print("Test files generated in test_ping_files/")
        if not args["files"] and not args["pdf_output"] and not args["visualize"]:
            return

    # Handle ping command
    if args["ping_target"]:
        start_ping(
            args["ping_target"],
            output_file=args["ping_output"],
            count=args["ping_count"],
            interval=args["ping_interval"],
            use_timestamp=not args["no_timestamp"]
        )
        return

    # Get files to analyze
    if args["files"]:
        # Use the files/patterns specified in the command line
        files = get_files_to_analyze(args["files"])
    else:
        # Use the default pattern
        pattern = args["pattern"] if args["pattern"] else "*ping*.txt *ping*.log *.ping"
        files = get_files_to_analyze(glob.glob(pattern))

    if not files:
        print("No files found to analyze.")
        return

    # Parse ping files and extract data
    results = {}
    for file in files:
        result = analyze_ping_file(file)
        if result:
            device_name = os.path.splitext(os.path.basename(file))[0]
            results[device_name] = result

    # Generate visualizations if requested
    if args["visualize"]:
        try:
            visualizations_dir = create_visualization(results)
            print(f"Visualizations saved to: {visualizations_dir}/")
        except Exception as e:
            print(f"Error generating visualizations: {str(e)}")
            import traceback
            traceback.print_exc()

    # Track if we've generated a custom PDF
    custom_pdf_generated = False

    # Generate custom PDF report if specified
    if args["pdf_output"]:
        try:
            print(f"Attempting to generate PDF report: {args['pdf_output']}")
            # Generate PDF with custom name
            pdf_file = generate_pdf_report(results, args["pdf_output"], "visualizations")
            print(f"PDF report generated: {args['pdf_output']}")
            print(f"Visualizations saved to: visualizations/")
            custom_pdf_generated = True
        except ImportError as e:
            print(f"\nRequired library error: {str(e)}")
            print("To install: pip install markdown weasyprint\n")
        except Exception as e:
            print(f"\nError generating PDF report: {str(e)}")
            import traceback
            traceback.print_exc()

    # Generate summary report (skip PDF if we already generated a custom one)
    if not args["visualize"] and not custom_pdf_generated:
        generate_summary_report(results, skip_pdf=custom_pdf_generated)

    # Output to file if requested
    if args["output_file"]:
        orig_stdout = sys.stdout
        with open(args["output_file"], 'w') as f:
            sys.stdout = f
            generate_summary_report(results, skip_pdf=True)  # Always skip PDF when outputting to file
            sys.stdout = orig_stdout
        print(f"Report saved to {args['output_file']}")


def is_private_ip(ip):
    """
    Check if an IP address is in one of the specified private subnet ranges:
    - 10.0.0.0/8 (Class A)
    - 172.16.0.0/12 (Class B)
    - 192.168.0.0/16 (Class C)
    - 169.254.0.0/16 (APIPA)
    """
    try:
        # Try to parse the IP address
        ip_obj = ipaddress.ip_address(ip)

        # Check if the IP is in one of the specified private ranges
        private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),       # Class A
            ipaddress.ip_network('172.16.0.0/12'),    # Class B
            ipaddress.ip_network('192.168.0.0/16'),   # Class C
            ipaddress.ip_network('169.254.0.0/16')    # APIPA
        ]

        for network in private_networks:
            if ip_obj in network:
                return True

        return False
    except ValueError:
        # If it's not a valid IP (e.g., a hostname), assume it's public
        return False


def get_mac_from_ip(ip):
    """
    Get MAC address for an IP address using ARP.
    Only works for IPs on the local network (private IPs).

    Args:
        ip (str): IP address to look up

    Returns:
        str: MAC address if found, None otherwise
    """
    # Only try ARP for private IPs
    if not is_private_ip(ip):
        return None

    try:
        # Run ARP command to get MAC address
        result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)

        # Parse the output
        if result.returncode == 0:
            # Look for MAC address in output
            mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', result.stdout)
            if mac_match:
                return mac_match.group(0)
    except (subprocess.SubprocessError, OSError) as e:
        print(f"Error running ARP command: {e}")

    return None


def evaluate_latency(avg_time, is_lan=True):
    """
    Evaluate the latency based on thresholds for LAN or WAN/Public IPs.

    Args:
        avg_time (float): Average ping time in milliseconds
        is_lan (bool): Whether the device is on the LAN (private IP) or WAN/Public

    Returns:
        tuple: (status, description) where status is one of 'excellent', 'good', 'acceptable', 'borderline', 'investigate'
    """
    if is_lan:
        # LAN thresholds
        if avg_time < 1:
            return ('excellent', 'Excellent (under 1ms)')
        elif avg_time < 5:
            return ('good', 'Good (1-5ms)')
        elif avg_time < 10:
            return ('acceptable', 'Acceptable (5-10ms)')
        else:
            return ('investigate', 'Poor - investigate (over 10ms)')
    else:
        # WAN/Public thresholds
        if avg_time < 20:
            return ('excellent', 'Excellent (under 20ms)')
        elif avg_time < 50:
            return ('good', 'Good (20-50ms)')
        elif avg_time < 100:
            return ('acceptable', 'Acceptable (50-100ms)')
        elif avg_time < 150:
            return ('borderline', 'Borderline (100-150ms)')
        else:
            return ('investigate', 'Poor - investigate (over 150ms)')


def evaluate_packet_loss(packet_loss, is_lan=True, is_voip=False, is_web=False):
    """
    Evaluate packet loss based on thresholds for different network types.

    Args:
        packet_loss (float): Packet loss percentage
        is_lan (bool): Whether the device is on the LAN (private IP) or WAN/Public
        is_voip (bool): Whether the device is a VoIP service
        is_web (bool): Whether the device is a web service

    Returns:
        tuple: (status, description) where status is one of 'optimal', 'acceptable', 'impact', 'investigate'
    """
    if is_voip:
        # VoIP-specific thresholds
        if packet_loss == 0:
            return ('optimal', 'Optimal (0%)')
        elif packet_loss < 1:
            return ('acceptable', 'Acceptable for VoIP (under 1%)')
        else:
            return ('investigate', 'Poor for VoIP - investigate immediately (over 1%)')
    elif is_web:
        # Web-specific thresholds
        if packet_loss == 0:
            return ('optimal', 'Optimal (0%)')
        elif packet_loss < 2:
            return ('acceptable', 'Acceptable for web services (under 2%)')
        else:
            return ('investigate', 'Poor for web services - investigate (over 2%)')
    elif is_lan:
        # LAN thresholds
        if packet_loss == 0:
            return ('optimal', 'Optimal (0%)')
        elif packet_loss < 0.5:
            return ('acceptable', 'Acceptable (0.1-0.5%)')
        else:
            return ('investigate', 'Poor - investigate immediately (over 0.5%)')
    else:
        # WAN/Public thresholds
        if packet_loss == 0:
            return ('optimal', 'Optimal (0%)')
        elif packet_loss < 1:
            return ('acceptable', 'Acceptable (0.1-1%)')
        elif packet_loss < 2.5:
            return ('impact', 'May impact real-time applications (1-2.5%)')
        else:
            return ('investigate', 'Poor - investigate immediately (over 2.5%)')


def get_device_network_profile(device_name, device_data):
    """
    Determine the network profile of a device for appropriate threshold evaluation.

    Args:
        device_name (str): Name of the device
        device_data (dict): Device data dictionary

    Returns:
        dict: Network profile with is_lan, is_voip, is_web flags
    """
    ip = device_data.get('ip', '')
    is_lan = is_private_ip(ip)

    # Check if it's a VoIP provider or service
    is_voip_provider = ('voip_provider' in device_name.lower() or
                       'voip-provider' in device_name.lower() or
                       'voip_service' in device_name.lower())

    # Check if it's a VoIP device (not provider)
    is_voip_device = ('voip' in device_name.lower() and not is_voip_provider)

    # Check if it's a web service (domain name or public IP)
    is_web_service = (not is_lan and ('www' in device_name.lower() or
                                    '.com' in device_name.lower() or
                                    '.org' in device_name.lower() or
                                    '.net' in device_name.lower() or
                                    'web' in device_name.lower() or
                                    'http' in device_name.lower()))

    return {
        'is_lan': is_lan,
        'is_voip_provider': is_voip_provider,
        'is_voip_device': is_voip_device,
        'is_web_service': is_web_service
    }


def lookup_hostname_for_ip(ip):
    """
    Try to lookup hostname for an IP address.
    Uses both DNS reverse lookup and whois if available.

    Args:
        ip (str): IP address to lookup

    Returns:
        str: Hostname if found, None otherwise
    """
    if not ip or is_private_ip(ip):
        return None

    # Try DNS reverse lookup first
    try:
        result = subprocess.run(['host', ip], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and 'domain name pointer' in result.stdout:
            hostname = result.stdout.split('domain name pointer')[-1].strip().rstrip('.')
            return hostname
    except (subprocess.SubprocessError, OSError):
        pass

    # Try whois lookup
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            # Look for common hostname fields in whois output
            for field in ['NetName:', 'Organization:', 'org-name:', 'descr:']:
                if field in result.stdout:
                    line = [l for l in result.stdout.split('\n') if field in l][0]
                    hostname = line.split(field, 1)[1].strip()
                    return hostname
    except (subprocess.SubprocessError, OSError):
        pass

    return None


if __name__ == "__main__":
    analyze_ping_files()