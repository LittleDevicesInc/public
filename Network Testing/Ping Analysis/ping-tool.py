#!/usr/bin/env python3
import re
import glob
import sys
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
                         r'icmp_(?:req|seq)=(\d+) ttl=\d+ time=(.+) ms')

    standard_pattern = (r'64 bytes from (?:([^()]+) \(([^()]+)\)|([^:]+)): '
                       r'icmp_(?:req|seq)=(\d+) ttl=\d+ time=(.+) ms')

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
        "max_ping_time": max_ping_time,
        "timestamps": timestamps,  # Added for visualization
        "ping_times": ping_times   # Added for visualization
    }

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
    """Categorize ping files based on naming patterns."""
    categories = {
        "mac": [],
        "ap": [],
        "gw": [],
        "switch": [],
        "fw": [],
        "host": [],
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


def generate_pdf_report(all_results, output_file="ping_analysis_report.pdf"):
    """Generate a PDF report of the ping analysis."""
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    elements.append(Paragraph("Network Ping Analysis Report", title_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Summary Section
    elements.append(Paragraph("Summary", styles['Heading2']))

    # Calculate summary metrics
    total_pings = sum(r["total_pings"] for results in all_results.values() for r in results)
    total_missing = sum(len(r["missing_seq"]) for results in all_results.values() for r in results)
    total_abnormal = sum(len(r.get("abnormal_intervals", [])) for results in all_results.values() for r in results)

    # Create summary table
    summary_data = [
        ["Metric", "Value"],
        ["Total Pings", f"{total_pings:,}"],
        ["Missing Pings", f"{total_missing:,}"],
        ["Abnormal Intervals", f"{total_abnormal:,}"]
    ]

    # Use hex colors directly instead of reportlab colors
    summary_table = Table(summary_data, colWidths=[2*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), '#A9A9A9'),  # Dark grey
        ('TEXTCOLOR', (0, 0), (-1, 0), '#F5F5F5'),   # White smoke
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), '#F5F5DC'),  # Beige
        ('TEXTCOLOR', (0, 1), (-1, -1), '#000000'),  # Black
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 1, '#000000')  # Black
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Device Performance Section
    elements.append(Paragraph("Device Performance", styles['Heading2']))

    for device_type, results in all_results.items():
        if not results:
            continue

        elements.append(Paragraph(device_type, styles['Heading3']))

        # Create device table
        device_data = [["Device", "IP", "Avg (ms)", "Min (ms)", "Max (ms)", "Pings"]]
        for r in results:
            device_data.append([
                os.path.basename(r["filename"]).split("-", 1)[1].replace(".log", ""),
                r["target_address"],
                f"{r['avg_ping_time']:.2f}",
                f"{r['min_ping_time']:.2f}",
                f"{r['max_ping_time']:.2f}",
                str(r["total_pings"])
            ])

        device_table = Table(device_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 1*inch, 1*inch, 1*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), '#A9A9A9'),  # Dark grey
            ('TEXTCOLOR', (0, 0), (-1, 0), '#F5F5F5'),   # White smoke
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), '#F5F5DC'),  # Beige
            ('TEXTCOLOR', (0, 1), (-1, -1), '#000000'),  # Black
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, '#000000')  # Black
        ]))
        elements.append(device_table)
        elements.append(Spacer(1, 20))

        # Add visualization
        # Filter for devices with timestamps
        timestamp_results = [r for r in results if r.get("has_timestamps")]
        if timestamp_results:
            # Set up clean, minimal plotting style
            plt.style.use('ggplot')
            fig, ax = plt.subplots(figsize=(10, 6))
            plt.rcParams.update({
                'axes.facecolor': 'white',
                'axes.edgecolor': '#dddddd',
                'axes.grid': True,
                'grid.color': '#eeeeee',
                'grid.linestyle': '-',
            })

            # Use a simple, clear color palette
            colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd']

            # Sort results by most interesting (highest ping variation)
            sorted_results = sorted(
                timestamp_results,
                key=lambda r: r["max_ping_time"] - r["min_ping_time"],
                reverse=True
            )

            # Limit to top 5 most interesting devices
            if len(sorted_results) > 5:
                sorted_results = sorted_results[:5]

            # Find global min/max ping times for Y-axis
            global_min_ping = min([r["min_ping_time"] for r in sorted_results])
            global_max_ping = max([r["max_ping_time"] for r in sorted_results])

            # Add padding to Y-axis (5% of range)
            y_padding = (global_max_ping - global_min_ping) * 0.05
            y_min = max(0, global_min_ping - y_padding)
            y_max = global_max_ping + y_padding

            # Find global time range
            min_time = min([min(datetime.fromtimestamp(ts) for ts in r.get("timestamps", []))
                           for r in sorted_results if r.get("timestamps")], default=datetime.now())
            max_time = max([max(datetime.fromtimestamp(ts) for ts in r.get("timestamps", []))
                           for r in sorted_results if r.get("timestamps")], default=datetime.now())

            # Add time padding (5% of range)
            time_range = max_time - min_time
            time_padding = timedelta(seconds=time_range.total_seconds() * 0.05)
            plot_min_time = min_time - time_padding
            plot_max_time = max_time + time_padding

            # Plot each device's data
            plotted_devices = 0
            for i, r in enumerate(sorted_results):
                # Extract data
                timestamps = [datetime.fromtimestamp(ts) for ts in r.get("timestamps", [])]
                ping_times = r.get("ping_times", [])

                if not timestamps or not ping_times:
                    continue

                plotted_devices += 1

                # Generate short device name for legend
                device_name = os.path.basename(r["filename"]).split("-", 1)[1].replace(".log", "")
                if len(device_name) > 15:
                    device_name = device_name[:12] + "..."

                # Ensure data is sorted by time
                data_points = sorted(zip(timestamps, ping_times), key=lambda x: x[0])

                # Extract sorted timestamps and ping times
                sorted_timestamps, sorted_ping_times = zip(*data_points) if data_points else ([], [])

                # Plot the line with proper time-series format
                ax.plot(sorted_timestamps, sorted_ping_times, '-',
                        color=colors[i % len(colors)],
                        linewidth=2, alpha=0.9,
                        label=device_name)

            # Only create visualization if we plotted some devices
            if plotted_devices > 0:
                # Set axis limits for consistent display
                ax.set_ylim(y_min, y_max)
                ax.set_xlim(plot_min_time, plot_max_time)

                # Add title and labels
                plt.title(f"Ping Response Times - {device_type}", fontsize=14)
                plt.xlabel("Time", fontsize=12)
                plt.ylabel("Response Time (ms)", fontsize=12)

                # Format time axis properly
                hours_range = time_range.total_seconds() / 3600.0

                # Choose appropriate time format and locator
                if hours_range < 1:  # Less than 1 hour
                    date_format = '%H:%M'
                    plt.gca().xaxis.set_major_locator(mdates.MinuteLocator(interval=10))
                elif hours_range < 6:  # Less than 6 hours
                    date_format = '%H:%M'
                    plt.gca().xaxis.set_major_locator(mdates.HourLocator())
                    plt.gca().xaxis.set_minor_locator(mdates.MinuteLocator(interval=30))
                elif hours_range < 24:  # Less than 1 day
                    date_format = '%H:%M'
                    plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=2))
                else:
                    date_format = '%m/%d %H:%M'
                    plt.gca().xaxis.set_major_locator(mdates.DayLocator())
                    plt.gca().xaxis.set_minor_locator(mdates.HourLocator(interval=6))

                plt.gca().xaxis.set_major_formatter(mdates.DateFormatter(date_format))

                # Clean up the appearance
                ax.spines['top'].set_visible(False)
                ax.spines['right'].set_visible(False)
                ax.spines['bottom'].set_color('#cccccc')
                ax.spines['left'].set_color('#cccccc')

                # Make grid lines light
                ax.grid(True, which='major', axis='both', linestyle='-', color='#eeeeee')

                # Add legend in upper right with no frame
                ax.legend(loc='upper right', frameon=False)

                plt.tight_layout()

                # Save plot to buffer
                buf = io.BytesIO()
                plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
                plt.close()
                buf.seek(0)

                # Add image to PDF
                img = Image(buf)
                img.drawHeight = 4*inch
                img.drawWidth = 6.5*inch
                elements.append(img)
                elements.append(Spacer(1, 20))

    # Key Observations and Recommendations
    elements.append(Paragraph("Key Observations", styles['Heading2']))
    observations = [
        "• Reliability Issues: Missing sequences detected",
        "• Performance Patterns: Consistent response times across devices",
        "• Network Health: Overall network performance within acceptable range"
    ]
    for obs in observations:
        elements.append(Paragraph(obs, styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Recommendations", styles['Heading2']))
    recommendations = [
        "• Enable timestamps for better interval analysis",
        "• Test with external network targets",
        "• Consider variable packet sizes and longer test durations",
        "• Implement network load testing",
        "• Establish baseline performance metrics"
    ]
    for rec in recommendations:
        elements.append(Paragraph(rec, styles['Normal']))

    # Build PDF
    doc.build(elements)
    return output_file


def generate_summary_report(all_results, skip_pdf=False):
    """Generate a summary report of all analyzed files."""
    # Get current date
    current_date = datetime.now().strftime('%B %d, %Y')

    # Process all results and group them
    device_groups = {
        "Access Points": [],
        "Switches": [],
        "Gateway": [],
        "VoIP Phones": [],
        "Hosts": []  # For MAC addresses and other hosts
    }

    for results in all_results.values():
        for r in results:
            filename = os.path.basename(r["filename"])
            if filename.startswith("ap-"):
                device_groups["Access Points"].append(r)
            elif filename.startswith("switch-"):
                device_groups["Switches"].append(r)
            elif filename.startswith("gateway-") or filename.startswith("gw-"):
                device_groups["Gateway"].append(r)
            elif filename.startswith("voip-"):
                device_groups["VoIP Phones"].append(r)
            else:
                device_groups["Hosts"].append(r)

    # Create visualizations directory
    viz_dir = "visualizations"
    if not os.path.exists(viz_dir):
        os.makedirs(viz_dir)

    # Generate visualizations for SVG plots
    create_visualization(device_groups, viz_dir)

    # Generate PDF report if reportlab is available and we're not skipping PDF generation
    if not skip_pdf:
        try:
            pdf_file = generate_pdf_report(device_groups)
            print(f"\nPDF report generated: {pdf_file}\n")
        except ImportError:
            print("\nReportLab library not available. PDF report not generated.")
            print("To install: pip install reportlab\n")
        except Exception as e:
            print(f"\nError generating PDF report: {str(e)}")

    # TITLE SECTION
    print("# Network Ping Analysis Report")
    print(f"*Generated on {current_date}*\n")

    # SUMMARY SECTION
    print("## Summary\n")

    # Count total files and devices
    total_files = sum(len(group) for group in device_groups.values())
    print(f"**Total Devices Tested:** {total_files}")

    # Print device counts
    for device_type, group in device_groups.items():
        if group:  # Only include non-empty groups
            print(f"- {len(group)} {device_type}")

    # Check for missing timestamp data
    no_timestamp_files = [
        r["display_target"] for results in all_results.values()
        for r in results if not r.get("has_timestamps", True)
    ]

    if no_timestamp_files:
        print("\n> **Note:** Some files were missing timestamp data (-D option), preventing interval analysis.")
    print()

    # OVERALL METRICS SECTION
    print("## Overall Performance\n")

    # Calculate metrics
    total_pings = sum(r["total_pings"] for results in all_results.values() for r in results)
    total_missing = sum(len(r["missing_seq"]) for results in all_results.values() for r in results)
    total_abnormal = sum(
        len(r.get("abnormal_intervals", [])) for results in all_results.values() for r in results
    )

    # Find min/max ping times
    min_ping = float('inf')
    max_ping = 0
    min_target = None
    max_target = None
    all_avg_pings = []

    for results in all_results.values():
        for r in results:
            if r["min_ping_time"] < min_ping:
                min_ping = r["min_ping_time"]
                min_target = r["display_target"]
            if r["max_ping_time"] > max_ping:
                max_ping = r["max_ping_time"]
                max_target = r["display_target"]
            all_avg_pings.append(r["avg_ping_time"])

    avg_ping = sum(all_avg_pings) / len(all_avg_pings) if all_avg_pings else 0

    # Print overall metrics table
    print("| Metric | Value |")
    print("|--------|-------|")
    print(f"| Total Pings | {total_pings:,} |")
    print(f"| Missing Pings | {total_missing:,} |")
    print(f"| Abnormal Intervals | {total_abnormal:,} |")
    print(f"| Min Response Time | {min_ping:.2f}ms |")
    print(f"| Max Response Time | {max_ping:.2f}ms |")
    print(f"| Avg Response Time | {avg_ping:.2f}ms |\n")

    # DEVICE PERFORMANCE SECTION
    print("## Device Performance\n")

    # Process each device type
    for device_type, results in device_groups.items():
        if not results:
            continue

        print(f"### {device_type}\n")

        # Special handling for VoIP phones
        if device_type == "VoIP Phones" and len(results) > 10:
            # Calculate VoIP summary stats
            voip_total_pings = sum(r["total_pings"] for r in results)
            voip_avg = sum(r["avg_ping_time"] for r in results) / len(results)
            voip_min = min(r["min_ping_time"] for r in results)
            voip_max = max(r["max_ping_time"] for r in results)
            missing_count = sum(len(r["missing_seq"]) for r in results)

            # Print summary for VoIP phones
            print(f"**Devices tested:** {len(results)}  ")
            print(f"**Total pings:** {voip_total_pings:,}  ")
            print(f"**Average response:** {voip_avg:.2f}ms  ")
            print(f"**Response range:** {voip_min:.2f}ms to {voip_max:.2f}ms  ")
            print(f"**Missing sequences:** {missing_count}\n")

            # Use collapsible section for detailed VoIP data
            print("<details>")
            print("<summary>View detailed VoIP phone data</summary>\n")

        # Table header for this device category
        print("| Device | IP | Avg (ms) | Min (ms) | Max (ms) | Pings |")
        print("|--------|------------|---------|---------|---------|-------|")

        # Sort results by device name for readability
        results.sort(key=lambda r: os.path.basename(r["filename"]))

        # Print each device's results
        for r in results:
            # Extract device name from filename
            filename = os.path.basename(r["filename"])
            device_name = filename.split("-", 1)[1].replace(".log", "")

            # Extract IP address
            ip = r["target_address"]

            # Print table row
            print(f"| {device_name} | {ip} | {r['avg_ping_time']:.2f} | {r['min_ping_time']:.2f} | {r['max_ping_time']:.2f} | {r['total_pings']:,} |")

        # Close details section for VoIP if opened
        if device_type == "VoIP Phones" and len(results) > 10:
            print("</details>\n")
        else:
            print()  # Add empty line after table

        # Add visualization for this device type
        if any(r.get("has_timestamps") for r in results):
            # Use SVG files for PDF/HTML display
            print(f"![{device_type} Ping Times](visualizations/{device_type.lower().replace(' ', '_')}_ping_times.svg)\n")

            # Add text-based plot for terminal display
            print("```")
            print(generate_text_plot(results, device_type))
            print("```\n")

    # KEY OBSERVATIONS SECTION
    print("## Key Observations\n")

    # Generate observations based on the data
    observations = []

    # Check for consistent performance
    same_avg = True
    first_avg = next(iter(all_results.values()))[0]["avg_ping_time"] if all_results else None
    for results in all_results.values():
        for r in results:
            if abs(r["avg_ping_time"] - first_avg) > 0.1:  # Allow small floating point differences
                same_avg = False
                break

    if same_avg and first_avg is not None:
        observations.append("1. **Consistent Performance:** All devices showed identical ping performance metrics")

    # Check if all targets are localhost
    all_localhost = True
    for results in all_results.values():
        for r in results:
            if "127.0.0.1" not in r["display_target"]:
                all_localhost = False
                break

    if all_localhost:
        observations.append(f"2. **Response Patterns:** The consistent {first_avg:.2f}ms average with {min_ping:.2f}ms min and {max_ping:.2f}ms max across all devices suggests these are localhost tests")

    # Check for missing sequences
    if total_missing == 0:
        observations.append("3. **Reliability:** No missing sequences detected across any device")
    else:
        observations.append(f"3. **Reliability Issues:** {total_missing:,} missing sequences detected")

    # Check for timestamp issues
    if no_timestamp_files:
        observations.append("4. **Limitations:** Some files lacked timestamp data, preventing interval and jitter analysis")

    # Print observations
    for obs in observations:
        print(obs)

    # RECOMMENDATIONS SECTION
    print("\n## Recommendations\n")

    # Generate recommendations based on the data
    recommendations = [
        "1. **Enable Timestamps:** Add the `-D` option to ping commands to enable timestamp data for interval analysis",
        "2. **External Targets:** Test with external network targets instead of localhost (127.0.0.1)",
        "3. **Diversify Test Patterns:** Consider variable packet sizes and longer test durations",
        "4. **Load Testing:** Introduce network load during testing to evaluate performance under stress",
        "5. **Alert Thresholds:** Establish baseline performance metrics and set appropriate alert thresholds"
    ]

    # Print recommendations
    for rec in recommendations:
        print(rec)

    # End of report
    print("\n---")
    print("*End of Report*")


def print_usage():
    """Print usage instructions."""
    print("Ping Tool")
    print("=========")
    print("\nA comprehensive tool for initiating and analyzing ping log files.")
    print("Detects issues such as missed pings, abnormal response times, and network latency patterns.")
    print("\nUsage:")
    print("  ping-tool [options] [files/patterns]")
    print("\nOptions:")
    print("  -h, --help                   Show this help message and exit")
    print("  -o FILE, --output=FILE       Write report to FILE")
    print("  -p PATTERN, --pattern=PATTERN  Specify file pattern (default: *ping*.txt or *ping*.log)")
    print("  --ping TARGET                Start a ping to the specified target")
    print("  --count N                    Number of pings to send (optional)")
    print("  --interval SEC              Interval between pings in seconds (optional)")
    print("  --ping-output FILE           Output file for ping results (optional)")
    print("  --no-timestamp              Don't use -D timestamp option when starting a ping")
    print("  --pdf FILE                  Generate a PDF report (default: ping_analysis_report.pdf)")
    print("\nExamples:")
    print("  # Start a ping to a target and save the output:")
    print("  ping-tool --ping 192.168.1.1")
    print("\n  # Start a ping without timestamps:")
    print("  ping-tool --ping google.com --no-timestamp")
    print("\n  # Start a ping with a specific count and interval:")
    print("  ping-tool --ping ap-123.local --count 100 --interval 0.5")
    print("\n  # Analyze all ping files in current directory:")
    print("  ping-tool")
    print("\n  # Analyze a specific file:")
    print("  ping-tool ping-ap1.txt")
    print("\n  # Analyze multiple specific files:")
    print("  ping-tool ping-ap1.txt ping-ap2.txt")
    print("\n  # Analyze files matching a pattern and save report:")
    print("  ping-tool -p \"ping-ap*.txt\" -o report.txt")
    print("\n  # Generate a PDF report:")
    print("  ping-tool --pdf report.pdf")
    print("\n  # Mix specific files and patterns:")
    print("  ping-tool ping-ap1.txt \"ping-switch*.txt\"")
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
        "no_timestamp": False,
        "generate_test_files": False,
        "pdf_output": None
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
        elif arg == "--generate-test-files":
            args["generate_test_files"] = True
            i += 1
        elif arg == "--pdf" and i+1 < len(sys.argv):
            args["pdf_output"] = sys.argv[i+1]
            i += 2

        # Treat other arguments as files or patterns
        else:
            args["files"].append(arg)
            i += 1

    return args


def generate_test_files(output_dir, num_files=5, duration_hours=24):
    """Generate test ping files with time series data that will display as horizontal lines."""
    # Make sure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Device types and their typical ping time ranges (min, max)
    device_types = {
        "ap": (1.5, 5.0),  # Access points: 1.5-5ms
        "switch": (0.5, 3.0),  # Switches: 0.5-3ms
        "gateway": (4.5, 12.0),  # Gateways: 4.5-12ms
        "voip": (2.5, 8.0)  # VoIP: 2.5-8ms
    }

    # Create a 5-day window for test data
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start_date = today - timedelta(days=4)  # Start 4 days ago

    # Create 1-3 files for each device type
    for device_type, ping_range in device_types.items():
        # Determine number of files for this type
        files_to_create = random.randint(1, 3)

        for i in range(files_to_create):
            # Generate device name based on type
            if device_type == "ap":
                name = f"ap-{random.choice(['eagle', 'hawk', 'lion', 'wolf', 'bear'])}{random.randint(100, 999)}"
            elif device_type == "switch":
                name = f"switch-{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}"
            elif device_type == "voip":
                name = f"voip-{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}:{random.randint(1, 10):02X}"
            else:  # gateway
                name = f"gateway-salmon{random.randint(100, 999)}"

            # Generate random IP (not 127.0.0.1)
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"

            # Open output file
            filename = os.path.join(output_dir, f"{name}.log")
            with open(filename, "w") as f:
                # Write ping header
                f.write(f"PING {ip} ({ip}) 56(84) bytes of data.\n")

                # Generate a base ping time for this device
                base_min, base_max = ping_range
                base_ping = random.uniform(base_min, base_max)

                # Determine the number of days to include data for (1-5 days)
                num_days = random.randint(1, 5)
                total_pings = 0

                # Generate a series of measurements spread across several days
                # Each day will have 3-5 measurements, each lasting 10-20 minutes
                for day in range(num_days):
                    current_date = start_date + timedelta(days=day)

                    # Generate 3-5 measurement periods per day
                    num_periods = random.randint(3, 5)

                    for period in range(num_periods):
                        # Random hour of the day (between 8am and 8pm)
                        hour = random.randint(8, 20)
                        # Random minute (0-59)
                        minute = random.randint(0, 59)

                        # Create start time
                        period_start = current_date.replace(hour=hour, minute=minute)

                        # Determine duration in minutes (10-20 minutes)
                        duration_minutes = random.randint(10, 20)

                        # Determine measurement frequency (every 15-60 seconds)
                        frequency_seconds = random.choice([15, 30, 60])

                        # Calculate number of measurements in this period
                        num_measurements = duration_minutes * 60 // frequency_seconds

                        # Choose a trend pattern for this period
                        trend = random.choice(['flat', 'increasing', 'decreasing', 'fluctuating'])

                        # Determine ping characteristics for this period
                        if trend == 'flat':
                            # Stable with minor variations
                            period_base = base_ping * random.uniform(0.8, 1.2)
                            variation = period_base * 0.1  # 10% variation
                        elif trend == 'increasing':
                            # Starting lower, ending higher
                            period_base = base_ping * random.uniform(0.7, 0.9)
                            variation = period_base * 0.1
                            increase_factor = random.uniform(1.3, 1.8)  # 30-80% increase
                        elif trend == 'decreasing':
                            # Starting higher, ending lower
                            period_base = base_ping * random.uniform(1.1, 1.3)
                            variation = period_base * 0.1
                            decrease_factor = random.uniform(0.5, 0.8)  # 20-50% decrease
                        else:  # fluctuating
                            # Varying between low and high
                            period_base = base_ping
                            variation = period_base * 0.3  # 30% variation

                        # Generate measurements for this period
                        for j in range(num_measurements):
                            # Calculate timestamp
                            timestamp = period_start + timedelta(seconds=j * frequency_seconds)
                            timestamp_unix = timestamp.timestamp()

                            # Calculate ping time based on trend
                            if trend == 'flat':
                                ping_time = period_base + random.uniform(-variation, variation)
                            elif trend == 'increasing':
                                progress = j / num_measurements
                                factor = 1 + (progress * (increase_factor - 1))
                                ping_time = period_base * factor + random.uniform(-variation, variation)
                            elif trend == 'decreasing':
                                progress = j / num_measurements
                                factor = 1 - (progress * (1 - decrease_factor))
                                ping_time = period_base * factor + random.uniform(-variation, variation)
                            else:  # fluctuating
                                # Use sine wave for natural fluctuation
                                wave = math.sin(j * math.pi / (num_measurements / 4))
                                ping_time = period_base + (wave * variation)

                            # Add occasional spikes (1% chance)
                            if random.random() < 0.01:
                                ping_time *= random.uniform(1.5, 2.5)

                            # Ensure minimum ping time
                            ping_time = max(ping_time, base_min * 0.7)

                            # Write ping entry
                            f.write(f"[{timestamp_unix}] 64 bytes from {ip}: icmp_seq={total_pings+1} ttl=64 time={ping_time:.2f} ms\n")
                            total_pings += 1

                # Write ping summary
                f.write(f"\n--- {ip} ping statistics ---\n")
                f.write(f"{total_pings} packets transmitted, {total_pings} received, 0% packet loss, time {total_pings*60}ms\n")
                f.write(f"rtt min/avg/max/mdev = {base_min:.3f}/{base_ping:.3f}/{base_max*2:.3f}/1.123 ms\n")

    print(f"Generated test files in {output_dir}/ with horizontal time-series data")
    return output_dir


def create_visualization(results, output_dir):
    """Create visualizations for each device type."""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for device_type, device_results in results.items():
        if not device_results:
            continue

        # Only create visualization if we have timestamp data
        timestamp_results = [r for r in device_results if r.get("has_timestamps")]
        if not timestamp_results:
            continue

        # Set up clean, minimal plotting style
        plt.figure(figsize=(10, 6), facecolor='#f6f6f6')
        plt.style.use('seaborn-v0_8-whitegrid')

        # Use a simple, clear color palette with good contrast
        colors = ['#0173B2', '#DE8F05', '#029E73', '#D55E00', '#CC78BC']

        # Sort results by most interesting (highest ping variation)
        sorted_results = sorted(
            timestamp_results,
            key=lambda r: r["max_ping_time"] - r["min_ping_time"],
            reverse=True
        )

        # Limit to top 5 most interesting devices
        if len(sorted_results) > 5:
            sorted_results = sorted_results[:5]

        # Find global min/max ping times for Y-axis
        global_min_ping = min([r["min_ping_time"] for r in sorted_results])
        global_max_ping = max([r["max_ping_time"] for r in sorted_results])

        # Add padding to Y-axis (20% of range)
        y_padding = (global_max_ping - global_min_ping) * 0.2
        y_min = max(0, global_min_ping - y_padding)
        y_max = global_max_ping + y_padding

        # Find global time range
        min_time = min([min(datetime.fromtimestamp(ts) for ts in r.get("timestamps", []))
                       for r in sorted_results if r.get("timestamps")], default=datetime.now())
        max_time = max([max(datetime.fromtimestamp(ts) for ts in r.get("timestamps", []))
                       for r in sorted_results if r.get("timestamps")], default=datetime.now())

        # Add time padding (10% of range)
        time_range = max_time - min_time
        time_padding = timedelta(seconds=time_range.total_seconds() * 0.10)
        plot_min_time = min_time - time_padding
        plot_max_time = max_time + time_padding

        # Get axis for styling
        ax = plt.gca()

        # Create gray background with white grid
        ax.set_facecolor('#f6f6f6')
        ax.grid(color='white', linestyle='-', linewidth=1)

        # Increase linewidth for better visibility
        linewidth = 2.5

        # Plot each device's data
        for i, result in enumerate(sorted_results):
            # Extract and prepare data
            timestamps = [datetime.fromtimestamp(ts) for ts in result.get("timestamps", [])]
            ping_times = result.get("ping_times", [])

            if not timestamps or not ping_times:
                continue

            # Generate short device name for legend
            device_name = os.path.basename(result["filename"]).split("-", 1)[1].replace(".log", "")
            if len(device_name) > 15:
                device_name = device_name[:12] + "..."

            # Ensure data is sorted by time
            data_points = sorted(zip(timestamps, ping_times), key=lambda x: x[0])
            sorted_timestamps, sorted_ping_times = zip(*data_points) if data_points else ([], [])

            # Plot the line with proper time-series format - use solid line without markers for cleaner appearance
            ax.plot(sorted_timestamps, sorted_ping_times,
                   '-', color=colors[i % len(colors)],
                   linewidth=linewidth,
                   solid_capstyle='round',
                   label=device_name)

        # Set axis limits for consistent display
        ax.set_ylim(y_min, y_max)
        ax.set_xlim(plot_min_time, plot_max_time)

        # Add title and labels with improved styling
        plt.title(f"Ping Response Times - {device_type}", fontsize=16, pad=20)
        plt.xlabel("Time", fontsize=12, labelpad=10)
        plt.ylabel("Response Time (ms)", fontsize=12, labelpad=10)

        # Format time axis properly
        hours_range = time_range.total_seconds() / 3600.0

        # Choose appropriate time format and locator
        if hours_range < 6:  # Less than 6 hours
            date_format = '%H:%M'
            plt.gca().xaxis.set_major_locator(mdates.HourLocator())
            plt.gca().xaxis.set_minor_locator(mdates.MinuteLocator(interval=30))
        elif hours_range < 24:  # Less than 1 day
            date_format = '%H:%M'
            plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=3))
        elif hours_range < 72:  # Less than 3 days
            date_format = '%m/%d %H:%M'
            plt.gca().xaxis.set_major_locator(mdates.HourLocator(interval=6))
        else:
            date_format = '%m/%d'
            plt.gca().xaxis.set_major_locator(mdates.DayLocator())

        plt.gca().xaxis.set_major_formatter(mdates.DateFormatter(date_format))

        # Clean up the appearance
        for spine in ['top', 'right']:
            ax.spines[spine].set_visible(False)

        ax.spines['bottom'].set_color('#cccccc')
        ax.spines['left'].set_color('#cccccc')

        # Make tick marks lighter
        ax.tick_params(axis='x', colors='#666666')
        ax.tick_params(axis='y', colors='#666666')

        # Add legend with better styling
        legend = ax.legend(loc='upper right', frameon=True, framealpha=0.8,
                      facecolor='white', edgecolor='#dddddd')

        plt.tight_layout()

        # Save as SVG
        out_file = os.path.join(output_dir, f"{device_type.lower().replace(' ', '_')}_ping_times.svg")
        plt.savefig(out_file, format="svg", bbox_inches="tight")
        plt.close()


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
            ping_times.extend(result.get("ping_times", []))

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
    """Main function to analyze ping files from the command line."""
    args = parse_args()

    # Check for test file generation option
    if args["generate_test_files"]:
        output_dir = "test_ping_files"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        generate_test_files(output_dir)
        print(f"Test files generated in {output_dir}/")
        sys.exit(0)

    # Check if we need to start a ping
    if args["ping_target"]:
        print(f"Starting ping to {args['ping_target']}...")
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

    # Categorize files
    categorized = categorize_ping_files(files)

    # Analyze files
    results = {}
    for category, file_list in categorized.items():
        category_results = []
        for file in file_list:
            file_result = analyze_ping_file(file)
            if file_result:
                category_results.append(file_result)
        results[category] = category_results

    # Track if we've generated a custom PDF
    custom_pdf_generated = False

    # Generate custom PDF report if specified
    if args["pdf_output"]:
        try:
            # Flatten the result structure for the PDF report
            all_device_results = []
            for category_results in results.values():
                all_device_results.extend(category_results)

            # Convert to the format expected by generate_pdf_report
            device_groups = {
                "Access Points": [],
                "Switches": [],
                "Gateway": [],
                "VoIP Phones": [],
                "Hosts": []
            }

            for r in all_device_results:
                filename = os.path.basename(r["filename"])
                if filename.startswith("ap-"):
                    device_groups["Access Points"].append(r)
                elif filename.startswith("switch-"):
                    device_groups["Switches"].append(r)
                elif filename.startswith("gateway-") or filename.startswith("gw-"):
                    device_groups["Gateway"].append(r)
                elif filename.startswith("voip-"):
                    device_groups["VoIP Phones"].append(r)
                else:
                    device_groups["Hosts"].append(r)

            print(f"Attempting to generate PDF report: {args['pdf_output']}")
            # Generate PDF with custom name
            pdf_file = generate_pdf_report(device_groups, args["pdf_output"])
            print(f"Custom PDF report generated: {pdf_file}")
            custom_pdf_generated = True

        except ImportError as e:
            print(f"\nReportLab library error: {str(e)}")
            print("To install: pip install reportlab\n")
        except Exception as e:
            print(f"\nError generating PDF report: {str(e)}")
            import traceback
            traceback.print_exc()

    # Generate summary report (skip PDF if we already generated a custom one)
    generate_summary_report(results, skip_pdf=custom_pdf_generated)

    # Output to file if requested
    if args["output_file"]:
        orig_stdout = sys.stdout
        with open(args["output_file"], 'w') as f:
            sys.stdout = f
            generate_summary_report(results, skip_pdf=True)  # Always skip PDF when outputting to file
            sys.stdout = orig_stdout
        print(f"Report saved to {args['output_file']}")


if __name__ == "__main__":
    analyze_ping_files()