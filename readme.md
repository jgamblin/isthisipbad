# Is This IP Bad?

A Python tool to check an IP address against popular IP and DNS blacklists for threat intelligence.

## Features

- **Async/Parallel Checks**: Fast parallel DNS and HTTP lookups
- **DNS-based Blacklists (DNSBLs)**: Checks against 15+ reliable DNSBLs including Spamhaus, SpamCop, Barracuda, and more
- **HTTP Threat Feeds**: Queries multiple threat intelligence feeds including Emerging Threats, Abuse.ch, Blocklist.de, and more
- **GeoIP Lookup**: Shows geographic information for the IP
- **TOR Exit Node Detection**: Identifies if an IP is a TOR exit node
- **Multiple Output Formats**: Table, JSON, and CSV output
- **Batch Processing**: Check multiple IPs from a file
- **Modern CLI**: Beautiful terminal output with progress bars and color-coded results
- **Threat Level Scoring**: Automatic threat level classification (Clean, Low, Medium, High, Critical)

## Installation

### Using pip

```bash
pip install -r requirements.txt
pip install -e .
```

### Development installation

```bash
pip install -r requirements-dev.txt
pip install -e .
```

## Usage

### Basic Usage

```bash
# Check a single IP
isthisipbad check 8.8.8.8

# Interactive mode (detects your public IP)
isthisipbad check

# Show all results including clean
isthisipbad check 8.8.8.8 --show-clean
```

### Output Formats

```bash
# JSON output
isthisipbad check 8.8.8.8 --format json

# Save to JSON file
isthisipbad check 8.8.8.8 --output results.json

# CSV output
isthisipbad check 8.8.8.8 --format csv --output results.csv
```

### Batch Processing

```bash
# Check multiple IPs from a file
isthisipbad check --file ips.txt

# With output
isthisipbad check --file ips.txt --output results.json
```

The input file should have one IP per line. Lines starting with `#` are treated as comments.

### Other Commands

```bash
# Show version
isthisipbad version

# List all threat intelligence sources
isthisipbad sources

# Get help
isthisipbad --help
isthisipbad check --help
```

### Options

| Option | Description |
|--------|-------------|
| `--file`, `-f` | File containing IPs to check |
| `--output`, `-o` | Output file (.json or .csv) |
| `--format` | Output format: table, json, csv |
| `--show-clean`, `-a` | Show clean (not listed) results |
| `--timeout`, `-t` | HTTP timeout in seconds (default: 10) |
| `--dns-timeout` | DNS timeout in seconds (default: 5) |
| `--no-info` | Skip FQDN and GeoIP lookup |
| `--quiet`, `-q` | Minimal output |

### Exit Codes

- `0`: Clean or Low threat level
- `1`: Medium threat level
- `2`: High or Critical threat level

### Legacy Script

The original `isthisipbad.py` script is still available for backward compatibility:

```bash
python3 isthisipbad.py -i 8.8.8.8 --success
```

## Data Sources

### DNS Blacklists
- Spamhaus (ZEN, SBL, XBL, PBL)
- SpamCop
- Barracuda
- SORBS
- UCEPROTECT
- DroneRL
- Mailspike
- And more...

### HTTP Threat Feeds
- Emerging Threats (Proofpoint)
- Blocklist.de
- Abuse.ch (Feodo Tracker, SSL Blacklist)
- CI Army
- IPsum
- Spamhaus DROP
- TOR Exit Nodes

## Requirements

- Python 3.8+
- httpx
- dnspython
- typer
- rich

## Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=isthisipbad
```

## Python API

You can also use isthisipbad as a library:

```python
import asyncio
from isthisipbad import IPChecker

async def main():
    async with IPChecker() as checker:
        report = await checker.check_ip("8.8.8.8")
        print(f"Threat Level: {report.threat_level.value}")
        print(f"Blacklisted: {report.blacklist_count}/{report.total_checks}")

asyncio.run(main())
```

Or synchronously:

```python
from isthisipbad import IPChecker

checker = IPChecker()
report = checker.check_ip_sync("8.8.8.8")
print(report.to_dict())
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - See [license](license) file for details.

## Author

[@jgamblin](https://twitter.com/jgamblin)

## Disclaimer

This tool is for informational purposes only. Results should be used as one data point in your security analysis, not as the sole basis for blocking decisions. Some blacklists may have false positives.
