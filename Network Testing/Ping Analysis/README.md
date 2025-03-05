# Network Ping Analysis Tool

A comprehensive tool for initiating ping tests and analyzing ping log files to detect network issues such as packet loss, abnormal response times, and latency patterns.

## Features

- **Ping Testing**: Initiates ping tests to specified targets
- **Log Analysis**: Parses and analyzes ping log files to detect network issues
- **Visualization**: Creates charts and plots to visualize ping data
- **PDF Reporting**: Generates comprehensive PDF reports with detailed analysis
  * Reports now include improved formatting with bullet points for observations
  * Empty sections are automatically filtered out for cleaner reports
  * Device categories are clearly separated for better readability
- **Device Categorization**: Automatically categorizes network devices based on naming patterns
- **MAC Address Lookup**: Identifies device vendors from MAC addresses

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

## Code Organization and Maintenance

The codebase is organized into several key functional areas:

* **File Parsing**: Functions for reading and parsing ping log files
* **Analysis**: Functions for analyzing ping data and detecting issues
* **Reporting**: Functions for generating reports in different formats
* **Visualization**: Functions for creating visual representations of ping data
* **Command Line Interface**: Handling of command-line arguments and user interaction
* **Device Categorization**: Unified system for categorizing network devices

Recent improvements:
1. **Modernized Argument Parsing**: Replaced custom argument parsing with the standard `argparse` library for better help messages and more robust handling of command-line options.
2. **Unified Device Categorization**: Implemented a consistent approach to categorizing both ping files and target devices with the `categorize_devices` function, while maintaining backward compatibility.
3. **Removed Redundant Code**: Identified and documented unused functions to simplify future maintenance.

For maintainers looking to make changes, note that the `generate_pdf_report` function is the primary report generation function used in the tool. The `generate_report` function was unused and has been removed to simplify the codebase.