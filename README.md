# .NET Framework / Core / ASP.NET Version Vulnerability Scanner

A reconnaissance tool that fingerprints the **.NET Framework**, **.NET Core**, and **ASP.NET** versions running on a target web server and cross-references them against a built-in database of known CVEs, complete with CVSS scoring and remediation references.

```

    ██████╗  ██████╗ ████████╗███╗   ██╗███████╗████████╗
    ██╔══██╗██╔═══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
    ██║  ██║██║   ██║   ██║   ██╔██╗ ██║█████╗     ██║
    ██║  ██║██║   ██║   ██║   ██║╚██╗██║██╔══╝     ██║
    ██████╔╝╚██████╔╝   ██║   ██║ ╚████║███████╗   ██║
    ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝
     ██████╗██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║     ██║   ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║
    ██║     ╚██╗ ██╔╝██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
    ╚██████╗ ╚████╔╝ ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
     ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

---

## Features

- **Version extraction** for .NET Framework, .NET Core, ASP.NET, ASP.NET Core, MVC, and IIS
- **Multiple detection methods** — response headers, forced error pages, and page-content analysis
- **CVE matching** against a curated database with wildcard and version-range support
- **CVSS scoring** with severity classification (Critical / High / Medium / Low)
- **ASP.NET → .NET Framework mapping** to infer the framework version when only the ASP.NET version is exposed
- **Concurrent scanning** of multiple targets via a thread pool
- **Export** results to JSON or CSV

## Requirements

- Python 3.6+
- Dependencies:

```bash
pip install requests urllib3 colorama
```

## Usage

```bash
# Scan a single target
python3 dotnet_version_cve_scanner.py -t example.com

# Scan a full URL (scheme respected)
python3 dotnet_version_cve_scanner.py -t https://example.com

# Scan a list of targets from a file (one per line)
python3 dotnet_version_cve_scanner.py -f targets.txt

# Export results
python3 dotnet_version_cve_scanner.py -f targets.txt -o results.json --format json
python3 dotnet_version_cve_scanner.py -f targets.txt -o results.csv  --format csv
```

### Options

| Flag | Argument | Description | Default |
|------|----------|-------------|---------|
| `-t`, `--target` | host/URL | Single target to scan | — |
| `-f`, `--file` | path | File containing targets, one per line | — |
| `-o`, `--output` | path | Output file for results | — |
| `--format` | `json` \| `csv` | Output format | `json` |
| `--timeout` | seconds | Per-request timeout | `15` |
| `--threads` | int | Number of concurrent workers | `5` |

## How it works

1. **Connectivity check** — confirms the target port is open before probing.
2. **Probing** — requests a set of common ASP.NET paths (`/Default.aspx`, `/elmah.axd`, `/Trace.axd`, forced 404/500 pages, etc.) to surface version data.
3. **Detection** — inspects `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Powered-By`, and `Server` headers, plus error-page and body content for version strings and .NET indicators.
4. **CVE matching** — compares detected versions against the CVE database using exact, wildcard (`4.8.*`), and range (`6.0.0-6.0.25`) matching.
5. **Reporting** — prints a color-coded, CVSS-sorted report and optionally exports to file.

## Sample output

```
Target: https://example.com
  Status: SUCCESS
  Version Information:
    ASP.NET: 4.0.30319
    IIS: 10.0
  Vulnerabilities Found: 3
    • CVE-2024-0057 - CRITICAL (CVSS 9.8)
      Product: .NET Framework (from ASP.NET version)
      Description: .NET, .NET Framework, and Visual Studio Security Feature Bypass Vulnerability
      Published: 2024-01-09
```

## CVE database

The scanner ships with a curated set of high-impact .NET CVEs (2020–2024), each including description, CVSS score and vector, publish date, affected version ranges, and an MSRC reference URL. Extend it by adding entries to the `cve_database` dictionary in `DotNetVersionCVEScanner.__init__`.

## Disclaimer

This tool is intended for **authorized security testing and educational use only**. Only scan systems you own or have explicit written permission to test. The authors accept no liability for misuse or damage caused by this program.

## Author

**c0d3ninja**
