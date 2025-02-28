# Ping Tool

A comprehensive tool for initiating ping tests and analyzing ping log files to detect network issues such as packet loss, abnormal response times, and latency patterns.

## Features

- **Ping Initiation**: Start ping tests to any target with customizable parameters
- **Timestamp-based Analysis**: Uses the `-D` option to capture precise epoch timestamps
- **Standard Ping Support**: Also works with standard ping output without timestamps
- **Domain Name Support**: Fully supports both domain names and IP addresses
- **Automatic File Detection**: Analyzes all ping files in a directory or specific files provided as arguments
- **Smart Categorization**: Automatically groups files based on naming patterns (MAC addresses, APs, switches, etc.)
- **Flexible MAC Address Detection**: Recognizes MAC addresses in various formats (uppercase, lowercase, with/without delimiters)
- **Missing Ping Detection**: Identifies any sequence numbers missing in the ping logs
- **Abnormal Response Detection**: Flags ping responses with unusually high latency
- **Detailed Statistics**: Provides comprehensive statistics including avg/min/max ping times
- **Summary Reporting**: Generates both per-file and category-level summary reports
- **Report Export**: Save analysis results to a file for later reference

## Installation

No installation required. Just ensure you have Python 3.6+ installed.

```bash
# Verify your Python version
python --version
```

## Usage

```bash
python ping-tool.py [options] [files/patterns]
```

### Options

- `-h, --help`: Show the help message and exit
- `-o FILE, --output=FILE`: Write report to FILE
- `-p PATTERN, --pattern=PATTERN`: Specify file pattern (default: `*ping*.txt` or `*ping*.log`)
- `--ping TARGET`: Start a ping to the specified target
- `--count N`: Number of pings to send (optional)
- `--interval SEC`: Interval between pings in seconds (optional)
- `--ping-output FILE`: Output file for ping results (optional)
- `--no-timestamp`: Don't use the -D timestamp option when starting a ping

### Examples

#### Start a ping to a target and save the output

```bash
python ping-tool.py --ping 192.168.1.1
```

#### Start a ping without timestamps

```bash
python ping-tool.py --ping google.com --no-timestamp
```

#### Start a ping with a specific count and interval

```bash
python ping-tool.py --ping ap-123.local --count 100 --interval 0.5
```

#### Analyze all ping files in current directory

```bash
python ping-tool.py
```

#### Analyze a specific file

```bash
python ping-tool.py ping-ap1.txt
```

#### Analyze multiple specific files

```bash
python ping-tool.py ping-ap1.txt ping-ap2.txt
```

#### Analyze files matching a pattern and save report

```bash
python ping-tool.py -p "ping-ap*.txt" -o report.txt
```

#### Mix specific files and patterns

```bash
python ping-tool.py ping-ap1.txt "ping-switch*.txt"
```

## File Categorization

Files are automatically categorized based on naming patterns:

- **MAC**: Files containing a MAC address in any format/case
  - Examples: `ping-02:9F:79:A1:6D:A9.txt`, `ping_029f79a16da9.txt`
- **AP**: Files containing 'ap', 'aps', or 'access-point' in the name
- **GW**: Files containing 'gw' or 'gateway' in the name
- **SWITCH**: Files containing 'switch' or 'sw' in the name
- **FW**: Files containing 'fw' or 'firewall' in the name
- **HOST**: Files containing 'host' or 'device' in the name
- **IP**: Files containing an IP address pattern
- **OTHER**: Any other ping files

## Supported MAC Address Formats

The tool recognizes MAC addresses in various formats:

- **Standard with hyphens**: `02-9F-79-A1-6D-A9`
- **Standard with colons**: `02:9F:79:A1:6D:A9`
- **Standard with underscores**: `02_9F_79_A1_6D_A9`
- **Without delimiters**: `029F79A16DA9`
- **Cisco format**: `0A1B.2C3D.4E5F`
- Any combination of uppercase and lowercase hex characters

## Supported Ping Output Formats

The tool supports two ping output formats:

1. **With timestamps** (using the `-D` option):
   ```
   [1740760790.891082] 64 bytes from sfo03s25-in-f14.1e100.net (142.250.189.206): icmp_req=1 ttl=116 time=82.1 ms
   ```

2. **Standard ping output** (without timestamps):
   ```
   64 bytes from sea09s30-in-f14.1e100.net (142.250.217.110): icmp_req=1 ttl=120 time=18.6 ms
   ```

Note that when analyzing files without timestamps, the tool cannot perform interval analysis to detect abnormal gaps between pings.

## Analysis Report

The analysis report includes:

1. **Per-file Analysis**:
   - Target address (with domain name if available)
   - Total number of pings
   - First and last sequence numbers
   - Average interval between pings (for timestamp data only)
   - Ping time statistics (avg/min/max)
   - Any missing sequence numbers
   - Abnormal ping intervals (for timestamp data only)

2. **Summary Statistics**:
   - Total files analyzed
   - Number of files with timestamps vs. without timestamps
   - Number of files with issues
   - Total missing pings across all files
   - Total abnormal intervals detected

3. **Category Summary**:
   - Statistics per category (MAC, AP, etc.)
   - List of files with issues in each category

## Example Output

```
================================================================================
PING FILES ANALYSIS
================================================================================
Found 4 ping files to analyze:
- MAC: 1 files
  - ping_mac_029f79a16da9.txt
- AP: 2 files
  - ping-ap1.txt
  - ping-ap2.txt
- SWITCH: 1 files
  - ping-switch.txt
================================================================================

ANALYZING MAC PING FILES
================================================================================
Analyzing ping_mac_029f79a16da9.txt...
...

================================================================================
PING ANALYSIS SUMMARY REPORT
================================================================================
Report generated on: 2023-07-27 14:32:45
--------------------------------------------------------------------------------
Total files analyzed: 4
Files with timestamp data (-D option): 3
Files without timestamp data: 1
Files with missing pings: 0
Files with abnormal intervals: 1
Total missing pings: 0
Total abnormal intervals: 9
--------------------------------------------------------------------------------

CATEGORY SUMMARY:

MAC (1 files, 1 with timestamps):
  Missing pings: 0
  Abnormal intervals: 0
  Average ping time: 0.00ms

AP (2 files, 1 with timestamps):
  Missing pings: 0
  Abnormal intervals: 0
  Average ping time: 0.90ms

SWITCH (1 files, 1 with timestamps):
  Missing pings: 0
  Abnormal intervals: 9
  Average ping time: 5.72ms
  - ping-switch.txt (192.168.249.102): 9 abnormal intervals

================================================================================
END OF REPORT
================================================================================
```

## Troubleshooting

- **No files found**: Make sure your file pattern is correct or specify the full path to the ping log files
- **No ping data found**: The tool expects a specific ping log format with timestamps and sequence numbers
- **File read errors**: Check file permissions and ensure the files are accessible
- **Ping command not starting**: Ensure you have appropriate permissions to run ping commands
- **Missing interval data**: Files without timestamp data (-D option) cannot provide interval analysis

## License

This tool is provided under the MIT License. See LICENSE file for details.