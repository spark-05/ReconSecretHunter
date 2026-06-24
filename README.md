# ReconSecretHunter

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-blue.svg">
  <img src="https://img.shields.io/badge/Security-Recon-red.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
</p>

**End-to-End Automated JavaScript Secret Discovery Tool**

ReconSecretHunter is a comprehensive security reconnaissance tool that automates the entire workflow of discovering exposed secrets in JavaScript files, JSON endpoints, configuration files, and source maps. It combines multiple open-source recon tools with a custom pattern-based secret scanner to identify 250+ types of sensitive credentials and API keys.

---

## 🎯 Overview

ReconSecretHunter automates the complete secret hunting pipeline:

```
Domain → Subdomain Enumeration → Live Host Discovery → 
Deep Crawling → JavaScript Collection → Secret Detection → JSON Report
```

The tool intelligently combines:
- **Subfinder** - Subdomain enumeration
- **Httpx** - Live host discovery with probe logic
- **Katana** - Web crawler for URL discovery and JavaScript extraction
- **Custom Scanner** - Pattern-based secret detection with entropy analysis
- **250+ Patterns** - Comprehensive secret detection library

---

## ✨ Features

### 🔍 Comprehensive Recon Pipeline
- Automatic subdomain enumeration via multiple sources
- Efficient live host discovery with status code detection
- Deep website crawling with multiple URL sources (live crawl + historical)
- Automatic source map discovery and parsing
- JavaScript endpoint extraction and analysis
- Concurrent processing with configurable thread pools

### 🔐 Advanced Secret Detection
- **Pattern-based matching** with 250+ regex patterns
- **Entropy analysis** to detect high-entropy secrets
- **Context validation** using keyword correlation
- **False positive reduction** through intelligent filtering
- **Duplicate detection** to avoid repetitive findings
- **Confidence scoring** (high/medium/low)

### 📊 Detected Secret Types

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS Keys, Azure Secrets, GCP Credentials |
| **Version Control** | GitHub Tokens, GitLab Tokens, Bitbucket Tokens |
| **Communication** | Slack Tokens, Discord Webhooks, Telegram Tokens |
| **Payment Systems** | Stripe Keys, Twilio Tokens |
| **AI/ML Providers** | OpenAI Keys, Anthropic Keys, HuggingFace Tokens |
| **Authentication** | JWT Tokens, OAuth Tokens, Private Keys |
| **Databases** | Connection Strings, Database Credentials |
| **Generic APIs** | Generic API Keys, Bearer Tokens |

### 📈 Reporting & Output

Organized output with structured files:
- `01_subdomains.txt` - All discovered subdomains
- `02_live_hosts.txt` - Verified live hosts with status codes
- `03_all_urls.txt` - Complete URL list from all sources
- `04_js_urls.txt` - All detected JavaScript file URLs
- `04_js_urls_live.txt` - Live/accessible JavaScript files
- `05_secrets.txt` - Human-readable secret findings
- `05_secrets.json` - Structured JSON report with full details

---

## 🚀 Installation

### Prerequisites
- Python 3.9+
- Go 1.16+ (for installing recon tools)
- Linux/macOS (or WSL on Windows)

### 1. Clone Repository

```bash
git clone https://github.com/spark-05/ReconSecretHunter.git
cd ReconSecretHunter
```

### 2. Install Python Requirements

```bash
pip install -r requirements.txt
```

**Requirements:**
- `requests` - HTTP client library
- `urllib3` - HTTP utilities
- `rich` - Rich terminal formatting (optional, fallback to plain output if missing)

### 3. Install Required Go Tools

Make sure `$HOME/go/bin` is in your `$PATH`:

```bash
export PATH=$PATH:$HOME/go/bin
```

#### Subfinder (Subdomain Enumeration)
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

#### Httpx (Live Host Discovery)
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

#### Katana (Web Crawler)
```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

#### Optional: GAU (Historical URLs)
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

### Verify Installation

```bash
python recon_secret_hunter.py --help
```

---

## 📖 Usage

### Basic Scan
Perform a complete reconnaissance on a single domain:

```bash
python recon_secret_hunter.py -d example.com
```

### Specify Custom Patterns File
Use a custom patterns.json file for secret detection:

```bash
python recon_secret_hunter.py -d example.com --patterns /path/to/patterns.json
```

Increase concurrent operations for faster scanning:

```bash
python recon_secret_hunter.py -d example.com --threads 100
```

### Custom Pattern File

Load custom secret patterns from a specific file:

```bash
python recon_secret_hunter.py -d example.com --patterns custom_patterns.json
```

### Scan All File Types

Include non-JavaScript files in scanning:

```bash
python recon_secret_hunter.py -d example.com --all-files
```

### Advanced Example

Complete scan with all options:

```bash
python recon_secret_hunter.py \
  -d example.com \
  --threads 50 \
  --patterns patterns.json \
  --all-files
```

---

## 📂 Output Structure

After execution, a timestamped directory is created:

```
output_example.com_20260624/
├── 01_subdomains.txt          # All discovered subdomains
├── 02_live_hosts.txt          # Verified live hosts with HTTP status
├── 03_all_urls.txt            # Complete URL list (combined sources)
├── 04_js_urls.txt             # All JavaScript file URLs found
├── 04_js_urls_live.txt        # Verified accessible JavaScript files
├── 05_secrets.txt             # Human-readable secret findings
└── 05_secrets.json            # Structured JSON report
```

### File Descriptions

- **01_subdomains.txt**: One subdomain per line, deduplicated
- **02_live_hosts.txt**: Format: `https://host status_code`
- **03_all_urls.txt**: URLs from live crawling + historical sources
- **04_js_urls.txt**: All detected .js files, including source maps
- **04_js_urls_live.txt**: JavaScript files that returned HTTP 200
- **05_secrets.txt**: Findings with context (URL + secret type)
- **05_secrets.json**: Structured data for integration/automation

---

## 🔧 Configuring Secret Patterns

Patterns are stored in [patterns.json](patterns.json). No code changes needed to add new patterns.

### Pattern Structure

```json
{
  "name": "Service Token Name",
  "regex": "token_pattern_here",
  "confidence": "high|medium|low",
  "keyword": ["optional", "keywords"],
  "entropy": 3.5,
  "group": 1
}
```

### Pattern Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | ✓ | Human-readable secret type name |
| `regex` | ✓ | Regular expression pattern (JSON: double backslashes: `\\d`) |
| `confidence` | ✓ | Confidence level: `high`, `medium`, or `low` |
| `keyword` | ✗ | Keywords that must appear within ±40 chars of match |
| `entropy` | ✗ | Minimum Shannon entropy (bits/char) the secret must have |
| `group` | ✗ | Capture group index containing real secret (0=entire match) |

### Add Custom Pattern

Edit `patterns.json` and add:

```json
{
  "name": "Custom API Token",
  "regex": "cust_[A-Za-z0-9]{40}",
  "confidence": "high",
  "keyword": ["token", "api"]
}
```

### Example: GitHub Token with Keyword Validation

```json
{
  "name": "GitHub Personal Access Token",
  "regex": "\\bghp_[A-Za-z0-9]{36}\\b",
  "confidence": "high",
  "keyword": ["github", "token", "pat"]
}
```

---

## 📊 Output Examples

### JSON Report (05_secrets.json)

```json
[
  {
    "url": "https://example.com/assets/app.js",
    "name": "GitHub Personal Access Token",
    "match": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "confidence": "high",
    "timestamp": "2026-06-24T12:00:00",
    "context": "const token = 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx'"
  },
  {
    "url": "https://api.example.com/config.json",
    "name": "AWS Access Key ID",
    "match": "AKIA2XXXXXXXXXXX",
    "confidence": "high",
    "timestamp": "2026-06-24T12:00:01",
    "context": "\"aws_key\": \"AKIA2XXXXXXXXXXX\""
  }
]
```

### Text Report (05_secrets.txt)

```
GitHub Personal Access Token
└─ https://example.com/assets/app.js
   └─ ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxx

AWS Access Key ID
└─ https://api.example.com/config.json
   └─ AKIA2XXXXXXXXXXX
```

---

## ⚙️ How It Works

### 1. Subdomain Enumeration
Uses Subfinder to discover all subdomains with passive sources (no direct probing).

### 2. Live Host Discovery
Httpx probes all subdomains to identify live hosts and their HTTP status codes.

### 3. URL Discovery
- **Live Crawling**: Katana crawls all live hosts for URLs
- **Historical**: GAU retrieves historical URLs (if installed)
- **Source Maps**: Automatically detects and references `.map` files

### 4. JavaScript Collection
Filters URLs to extract and download JavaScript files (.js, .mjs).

### 5. Secret Detection
For each JavaScript file:
- Load patterns from patterns.json
- Scan for regex matches
- Apply entropy analysis for validation
- Validate keywords in context
- Deduplicate findings

### 6. Reporting
Generate structured reports with findings ranked by confidence.

---

## 🔥 Performance Tips

### Optimize for Speed
- Increase threads for faster crawling (adjust based on CPU):
  ```bash
  python recon_secret_hunter.py -d example.com --threads 100
  ```

- Use timeout to limit per-host scan time:
  ```bash
  python recon_secret_hunter.py -d example.com --timeout 30
  ```

### Optimize for Coverage
- Include non-JavaScript files:
  ```bash
  python recon_secret_hunter.py -d example.com --all-files
  ```

- Increase crawl depth for Katana (may increase runtime)

### Memory Management
- For large scans, process output files progressively
- Use pattern filtering to reduce false positives
- Enable entropy checks to reduce noise

---

## 🐛 Troubleshooting

### Missing Tool Errors
```
[-] 17:30:45 Missing required tools: subfinder, httpx
```

**Solution**: Install missing Go tools. Verify `$HOME/go/bin` is in `$PATH`.

### No Subdomains Found
- Verify domain exists and is not blocked
- Check if subfinder has valid API keys configured (~/.config/subfinder/config.yaml)

### No JavaScript Files Found
- Some sites may block crawlers
- Check 04_js_urls.txt for discovered URLs
- Manually verify site is crawlable: `curl -I https://example.com`

### Pattern Matching Issues
- Validate regex syntax using [regex101.com](https://regex101.com)
- Remember to double-escape in JSON: `\d` becomes `\\d`
- Check keyword requirements don't exclude valid matches

---

## 📚 External Tools

This tool leverages:
- **Subfinder** - https://github.com/projectdiscovery/subfinder
- **Httpx** - https://github.com/projectdiscovery/httpx
- **Katana** - https://github.com/projectdiscovery/katana
- **GAU** - https://github.com/lc/gau

---

## ⚠️ Disclaimer

**Authorized Use Only**

This tool is designed for:
- ✓ Authorized Security Assessments
- ✓ Bug Bounty Programs (with program scope)
- ✓ Internal Security Testing (on your own infrastructure)
- ✓ Asset Discovery (on your own domains)

**Unauthorized Access Warning**

Scanning systems without explicit written permission is illegal under the Computer Fraud and Abuse Act (CFAA) and similar laws in other jurisdictions.

The author assumes no liability for misuse of this software. Users are solely responsible for ensuring compliance with applicable laws and obtaining proper authorization before use.

---

## 👤 Author

**spark**

- Security Researcher
- Container Security Specialist

---

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional secret patterns (patterns.json)
- Performance optimizations
- Additional recon sources
- Documentation improvements

---

## 📞 Support

For issues, questions, or suggestions:
1. Check the troubleshooting section above
2. Review patterns.json for pattern validation
3. Verify all required tools are installed correctly
4. Check GitHub issues for similar problems

---

**Happy Hunting! 🎯**
