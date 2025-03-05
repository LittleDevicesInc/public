# Network Ping Analysis Tool

A comprehensive tool for initiating ping tests and analyzing ping log files to detect network issues such as packet loss, abnormal response times, and latency patterns.

## Features

- **Ping Testing**: Run ping tests against multiple targets with customizable parameters
- **Log Analysis**: Analyze ping log files to identify missing sequences and abnormal intervals
- **Visualization**: Generate visual representations of ping response times
- **PDF Reporting**: Create detailed PDF reports with network performance metrics
- **Device Categorization**: Automatically categorize devices (gateways, switches, access points, VoIP phones, hosts)
- **MAC Address Lookup**: Identify device manufacturers using OUI database

## Usage

### Running Ping Tests

```bash
python ping-tool.py --ping <target_ip> [--count <num>] [--interval <seconds>]
```

### Analyzing Log Files

```bash
python ping-tool.py --analyze <log_file1> [<log_file2> ...]
```

### Generating PDF Reports

```bash
python ping-tool.py --pdf <output_file.pdf> <log_file1> [<log_file2> ...]
```

### Creating Visualizations

```bash
python ping-tool.py --visualize <log_file1> [<log_file2> ...]
```

### Generating Test Files (for development)

```bash
python ping-tool.py --generate-test-files [--num-files <num>] [--duration <hours>]
```

## Requirements

- Python 3.6+
- Required packages:
  - matplotlib
  - numpy
  - reportlab
  - weasyprint
  - markdown
  - pytz

## Installation

1. Clone the repository
2. Create a virtual environment: `python -m venv .venv`
3. Activate the virtual environment: `source .venv/bin/activate` (Linux/Mac) or `.venv\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`

## License

This project is licensed under the MIT License - see the LICENSE file for details.