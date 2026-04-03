# Recon Tool

A cross-platform reconnaissance tool for RISC OS and Linux that performs DNS analysis, subdomain discovery, web fingerprinting, email security checks, and optional TCP port scanning with minimal dependencies.

## Features

- Subdomain brute-forcing from a supplied or downloaded wordlist
- DNS record collection for:
  - A
  - AAAA
  - MX
  - TXT
  - NS
  - CNAME
  - DMARC
  - DKIM, using supplied selectors
  - SPF
- Email security summary reporting
- HTTP and HTTPS metadata collection, including:
  - status code
  - page title
  - server header
  - basic content preview
  - TLS certificate expiry
  - simple login form detection
- Optional common-port TCP scanning on discovered hosts
- Wildcard DNS detection to reduce false positives
- CSV output for both DNS results and discovered subdomains
- RISC OS launcher generation with an Obey file

## Platform support

This tool is designed for:

- RISC OS
- Linux

The script aims to stay within a conservative Python 3 feature set and uses the standard library wherever possible.

## Dependency model

The tool is designed to work with minimal dependencies.

### Core operation

The following parts use only the Python standard library:

- argument parsing
- CSV writing
- socket-based host resolution
- HTTP and HTTPS collection
- HTML parsing
- optional port scanning

### Optional DNS enhancement

If `dnspython` is available, the script can perform richer DNS lookups for records such as:

- MX
- TXT
- NS
- CNAME
- DMARC
- DKIM

If `dnspython` is not installed:

- on Linux, the script may use an external DNS helper if one is available
- on RISC OS, the script falls back to limited DNS mode

Limited DNS mode still allows address resolution and web checks, but richer DNS reporting will be reduced.

## Requirements

- Python 3.8 or later is recommended
- Internet access for DNS and HTTP or HTTPS checks
- `dnspython` if you want full DNS record support

## Installation

Clone the repository:

```bash
git clone https://github.com/yourname/recon-tool.git
cd recon-tool
```

Optional dependency for richer DNS support:

```bash
pip install dnspython
```

## Usage

Basic usage:

```bash
python3 recon.py example.com
```

Multiple domains:

```bash
python3 recon.py example.com,example.org
```

Enable debug output:

```bash
python3 recon.py example.com --debug
```

Enable port scanning:

```bash
python3 recon.py example.com --ports
```

Supply DKIM selectors:

```bash
python3 recon.py example.com --dkim-selector default --dkim-selector google
```

Use a custom wordlist:

```bash
python3 recon.py example.com --wordlist mysubs.txt
```

Limit the wordlist size:

```bash
python3 recon.py example.com --limit 1000
```

Generate a RISC OS Obey launcher:

```bash
python3 recon.py example.com --make-riscos-obey
```

Specify the Python command used in the generated launcher:

```bash
python3 recon.py example.com --make-riscos-obey --python-command Python3
```

## Output files

For each scanned domain, the script writes two CSV files.

### DNS results

```text
example_com_dns.csv
```

Contains rows such as:

- domain
- record type
- value

### Subdomain results

```text
example_com_subdomains.csv
```

Contains columns for:

- subdomain
- IP address or addresses
- CNAME
- reverse DNS
- HTTP title
- server header
- HTTPS availability
- TLS expiry
- HTTP status code
- HTTP load time
- headers
- content preview
- content CRC32
- login form detection
- domain email security summary
- open ports

## DNS operating modes

The script can operate in different DNS modes depending on what is available on the target system.

### Full DNS mode

Used when `dnspython` is installed.

This gives the best results and is the preferred mode.

### Helper-assisted mode

Used on supported non-RISC OS systems if a suitable external DNS helper is available.

This mode is intended as a fallback and may vary by platform.

### Limited mode

Used when neither `dnspython` nor a helper is available.

This still supports:

- host resolution via `socket.getaddrinfo()`
- HTTP and HTTPS metadata checks
- wildcard detection
- optional port scanning

But it will not provide full record-type coverage.

## RISC OS notes

- The script is designed to avoid assuming Linux-specific tooling on RISC OS
- External DNS helpers are not assumed to exist on RISC OS
- If `dnspython` is not available on RISC OS, the script will run in limited DNS mode
- The `--make-riscos-obey` option writes a simple launcher file named `run_recon.obey`
- You may need to set the filetype to `Obey` on RISC OS depending on how your system is configured
- You can adjust the Python interpreter name in the launcher with `--python-command`

## Linux notes

- Linux should provide the smoothest experience
- Full DNS mode is recommended by installing `dnspython`
- If `dnspython` is unavailable, the script may still be able to use a helper-based fallback depending on the host environment

## Performance notes

- Subdomain enumeration can produce a large number of network operations
- Port scanning significantly increases runtime
- You can tune concurrency using:
  - `--threads`
  - `--port-threads`
- You can reduce workload by using:
  - `--limit`
  - a smaller custom wordlist

## Safety and scope

This tool is intended for legitimate defensive, administrative, and research use only.

Only use it against systems and domains that you own or are explicitly authorised to assess.

## Limitations

- DKIM discovery is selector-based and requires you to provide likely selectors
- Login form detection is heuristic and intentionally simple
- Web fingerprinting is shallow and not a substitute for full content analysis
- Port scanning is limited to a predefined common-port list
- Limited DNS mode cannot replace a full DNS library
- Some behaviour will vary depending on local resolver configuration, network conditions, and platform support

## Suggested workflow

1. Run a basic scan without ports
2. Review DNS and email security findings
3. Re-run with DKIM selectors if required
4. Re-run with `--ports` for deeper host visibility
5. Compare CSV output over time for change detection

## Example workflow

```bash
python3 recon.py example.com --limit 1000
python3 recon.py example.com --dkim-selector default --dkim-selector google
python3 recon.py example.com --ports --threads 16 --port-threads 32
```

## Repository structure

```text
.
├── recon.py
├── README.md
└── subdomains.txt
```

## Future improvements

Possible future enhancements include:

- banner grabbing for selected services
- configurable port lists
- JSON output
- cached DNS results
- comparison mode for historical recon runs
- improved RISC OS packaging

## License

Add your preferred licence here, for example MIT, BSD, or GPL.

## Contributing

Contributions, fixes, and portability improvements are welcome.

Please keep changes compatible with the project goals:

- RISC OS friendliness
- Linux compatibility
- minimal dependencies
- conservative Python feature usage
