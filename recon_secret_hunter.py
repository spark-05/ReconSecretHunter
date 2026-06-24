#!/usr/bin/env python3
"""
ReconSecretHunter - End-to-End Automated JS Secret Discovery
Usage: python recon_secret_hunter.py -d example.com

"""

import re
import sys
import json
import time
import shutil
import argparse
import subprocess
import threading
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn
    )
    from rich import box
    console = Console()
    RICH = True
except ImportError:
    console = None
    RICH = False


# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝██╔════╝██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗█████╗  ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║██╔══╝  ██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║███████╗╚██████╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝╚══════╝ ╚═════╝
██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        End-to-End Automated JS Secret Discovery Tool
"""


def print_banner():
    if RICH:
        console.print(Panel(BANNER, style="bold cyan", border_style="bright_blue"))
    else:
        print(BANNER)


def log(msg, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    if RICH:
        colors = {"info": "blue", "ok": "green", "warn": "yellow", "error": "red", "find": "bright_red"}
        icons  = {"info": "◈", "ok": "✔", "warn": "⚠", "error": "✘", "find": "🔑"}
        color  = colors.get(level, "white")
        icon   = icons.get(level, "◈")
        console.print(f"  [{color}]{icon}[/{color}]  [dim]{ts}[/dim]  {msg}")
    else:
        prefix = {"info": "[*]", "ok": "[+]", "warn": "[!]", "error": "[-]", "find": "[FOUND]"}.get(level, "[*]")
        print(f"{prefix} {ts} {msg}")


# ══════════════════════════════════════════════════════════════════════════════
# SECRET PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# SECRET PATTERNS
#
#  >>> THE COMPLETE PATTERN LIST LIVES IN  patterns.json  <<<
#
# This tool loads patterns.json automatically at startup (see load_pattern_defs).
# To ADD / EDIT / REMOVE secret types, edit patterns.json ONLY — never this file.
#
#   Search order:
#     1. --patterns FILE  (if you pass one on the CLI)
#     2. patterns.json    beside this script  (default)
#     3. patterns.json    in the current working directory
#     4. the small PATTERNS_FALLBACK list below (emergency use only)
#
# Each pattern object in patterns.json:
#   {
#     "name":       "Service Token Name",        (required)
#     "regex":      "the-regular-expression",     (required)
#     "confidence": "high" | "medium" | "low",    (required)
#     "keyword":    ["word1", "word2"],            (optional) must appear within
#                                                  40 chars of the match
#     "entropy":    3.5,                           (optional) min Shannon entropy
#                                                  (bits/char) the value must have
#     "group":      1                              (optional) capture-group index
#                                                  holding the real secret (0=whole)
#   }
#
# JSON regex strings must DOUBLE their backslashes:  \d  ->  "\\d".
#
# The fallback below is intentionally tiny — just enough to catch the most
# critical secret types if patterns.json is ever missing or corrupted.
# ══════════════════════════════════════════════════════════════════════════════

PATTERNS_FALLBACK = [
    {"name": "AWS Access Key ID",
     "regex": r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z2-7]{16}\b",
     "confidence": "high", "entropy": 3.2},
    {"name": "Google API Key",
     "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
     "confidence": "high"},
    {"name": "GitHub Personal Access Token",
     "regex": r"\bghp_[A-Za-z0-9]{36}\b",
     "confidence": "high"},
    {"name": "Stripe Secret Key (live)",
     "regex": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
     "confidence": "high"},
    {"name": "OpenAI API Key (project)",
     "regex": r"\bsk-proj-[A-Za-z0-9_\-]{48,}\b",
     "confidence": "high"},
    {"name": "Slack Token",
     "regex": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
     "confidence": "high"},
    {"name": "Private Key Header",
     "regex": r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)? ?(?:PRIVATE KEY|PRIVATE KEY BLOCK)-----",
     "confidence": "high"},
    {"name": "JWT Token",
     "regex": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
     "confidence": "medium"},
]

# Backward-compatible alias: anything that still references PATTERNS keeps working.
PATTERNS = PATTERNS_FALLBACK


# ══════════════════════════════════════════════════════════════════════════════
# TOOL CHECKER
# ══════════════════════════════════════════════════════════════════════════════

REQUIRED_TOOLS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx":     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "katana":    "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
}


def check_tools():
    missing = []
    for tool in REQUIRED_TOOLS:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        log(f"Missing required tools: {', '.join(missing)}", "error")
        for t in missing:
            log(f"  Install: {REQUIRED_TOOLS[t]}", "info")
        sys.exit(1)
    log("All required tools found (subfinder, httpx, katana)", "ok")


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd, timeout=600):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError as e:
        return "", str(e), -1


def read_file(path):
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return []
    return [l.strip() for l in p.read_text(errors="ignore").splitlines() if l.strip()]


def write_file(path, lines):
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_pattern_defs(patterns_file=None):
    """
    Resolve the list of pattern definitions to use.

    Priority:
      1. --patterns FILE if given
      2. patterns.json next to this script (auto-detected)
      3. built-in PATTERNS list (always available fallback)

    The external file lets you add NEW secret types (2026+ and beyond)
    without editing code — just append objects with:
        {"name": "...", "regex": "...", "confidence": "high|medium|low",
         "keyword": ["..."]   (optional),
         "entropy": 3.5        (optional, min bits/char),
         "group": 1            (optional, capture group index)}
    """
    candidates = []
    if patterns_file:
        candidates.append(Path(patterns_file))
    else:
        candidates.append(Path(__file__).resolve().parent / "patterns.json")
        candidates.append(Path.cwd() / "patterns.json")

    for path in candidates:
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list) and data:
                    log(f"Loaded {len(data)} patterns from {path}", "ok")
                    return data, str(path)
            except (json.JSONDecodeError, OSError) as e:
                log(f"Could not parse {path}: {e} — using built-in patterns", "warn")

    log(f"patterns.json NOT found — using {len(PATTERNS)} built-in FALLBACK "
        f"patterns only. Add patterns.json beside the script for the full set.",
        "warn")
    return PATTERNS, "built-in"


def compile_patterns(pattern_defs=None):
    defs = pattern_defs if pattern_defs is not None else PATTERNS
    compiled = []
    for p in defs:
        try:
            compiled.append({
                "name":       p["name"],
                "regex":      re.compile(p["regex"], re.MULTILINE),
                "confidence": p.get("confidence", "medium"),
                "keyword":    [k.lower() for k in p.get("keyword", [])],
                "entropy":    p.get("entropy", 0.0),
                "group":      p.get("group", 0),
            })
        except (re.error, KeyError) as e:
            log(f"Bad pattern [{p.get('name', '?')}]: {e}", "warn")
    return compiled


CONF_ORDER = {"low": 0, "medium": 1, "high": 2}


def conf_ok(finding_conf, min_conf):
    return CONF_ORDER.get(finding_conf, 0) >= CONF_ORDER.get(min_conf, 0)


# ── False-positive filtering ──────────────────────────────────────────────────

import math as _math

# Substrings that, if present in the matched value, mark it as junk.
# (minified JS identifiers, base64 SVG/data blobs, common library noise)
_FP_SUBSTRINGS = (
    "renderingcontext", "function", "prototype", "stringify", "addeventlistener",
    "queryselector", "createelement", "getelementby", "undefined", "appendchild",
    "constructor", "0000000000", "1111111111", "abcdefabcdef",
    # minified-JS property/method access noise (r.password, s.host, e.tokenKey…)
    ".password", ".host", ".port", ".path", ".secret", ".token", ".key",
    "void ", "=void", "return ", "delete_", "get_all", "_secret=", "=r.", "=s.", "=e.",
)

# Whole values that are obviously not secrets even if they match a regex.
_FP_EXACT = {
    "browser_log_key", "password", "secret", "token", "apikey", "api_key",
}


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character. Random secrets score ~4-5; words ~2-3."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * _math.log2(c / n) for c in freq.values())


def looks_like_base64_text(s: str) -> bool:
    """
    Heuristic: base64-encoded *text* (SVG, data URIs) often starts with known
    sequences. Catches the 'PHN2Zy...' / '6Ly93d3c...' (=> https://www...) noise.
    """
    prefixes = ("6Ly9", "6Lyh", "PHN2", "PD94", "PGc", "iVBOR", "data:")
    return s.startswith(prefixes)


def luhn_valid(number: str) -> bool:
    """Luhn checksum — real credit-card numbers pass; random 16-digit runs don't."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def jwt_is_meaningful(token: str) -> bool:
    """
    Decode a JWT's payload (no signature verification) and require at least one
    real claim (exp/iss/sub/aud/iat). Filters out 'eyJ...'-shaped strings and
    public example tokens that carry no real claims.
    """
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        payload_b64 = parts[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)   # fix padding
        payload = base64.urlsafe_b64decode(payload_b64.encode())
        claims = json.loads(payload)
    except Exception:
        return False
    if not isinstance(claims, dict):
        return False
    return any(c in claims for c in ("exp", "iss", "sub", "aud", "iat", "nbf"))


def is_false_positive(value: str, pat: dict) -> bool:
    low = value.lower()
    name = pat.get("name", "")

    # Type-specific validation first (so a valid card isn't killed by generic rules)
    if "Credit Card" in name:
        return not luhn_valid(value)        # keep only Luhn-valid numbers
    if name == "JWT Token" or (value.startswith("eyJ") and value.count(".") == 2):
        if value.startswith("eyJ") and value.count(".") == 2:
            return not jwt_is_meaningful(value)

    if low in _FP_EXACT:
        return True
    if any(fp in low for fp in _FP_SUBSTRINGS):
        return True
    if looks_like_base64_text(value):
        return True
    # Entropy gate (only when the pattern asks for it)
    min_ent = pat.get("entropy", 0.0)
    if min_ent and shannon_entropy(value) < min_ent:
        return True
    # Reject values that are a single repeated/sequential char run
    if len(set(value)) <= 2:
        return True
    return False


def keyword_nearby(content: str, start: int, end: int, keywords: list) -> bool:
    """True if any keyword appears within 40 chars before/after the match window."""
    if not keywords:
        return True
    lo = max(0, start - 40)
    hi = min(len(content), end + 40)
    window = content[lo:hi].lower()
    return any(k in window for k in keywords)


# ── Generic high-entropy detector (keyword-anchored, low noise) ────────────────
#
# Catches secrets whose FORMAT we don't have a named pattern for — including
# services that don't exist yet. It only fires when a long, high-entropy,
# secret-looking string sits right next to an assignment keyword like
# `api_key=`, `secret:`, `token =`, so random minified-JS blobs are ignored.

# Keyword immediately preceding a value (the "left-hand side" of an assignment).
_GENERIC_KEYWORD_RE = re.compile(
    r"(?i)("
    r"api[_-]?key|apikey|secret[_-]?key|secret|client[_-]?secret|"
    r"access[_-]?token|auth[_-]?token|refresh[_-]?token|bearer[_-]?token|"
    r"private[_-]?key|encryption[_-]?key|signing[_-]?key|app[_-]?secret|"
    r"password|passwd|pwd|credential|token|auth"
    r")[\"'\s]{0,4}[:=][\"'\s]{0,4}([A-Za-z0-9_\-\.+/=]{20,120})"
)


def generic_entropy_findings(content, url, min_entropy, min_conf, already_seen):
    """
    Yield finding dicts for high-entropy values attached to a secret keyword
    that weren't already captured by a named pattern.
    """
    out = []
    # Generic findings are 'medium' confidence; skip if user wants high-only.
    if not conf_ok("medium", min_conf):
        return out

    for m in _GENERIC_KEYWORD_RE.finditer(content):
        kw, val = m.group(1), m.group(2)
        val = val.strip(" \"'")
        if len(val) < 20 or val in already_seen:
            continue
        # Entropy gate — the core of the low-noise guarantee
        if shannon_entropy(val) < min_entropy:
            continue
        # Reuse the same false-positive filters
        if is_false_positive(val, {"entropy": min_entropy}):
            continue
        # Skip obvious non-secrets: URLs, file paths, dotted versions
        if val.count("/") >= 2 or val.count(".") >= 3:
            continue
        # Skip minified-JS code: property access (r.foo), assignments, void/return
        if re.search(r"[=(){}]|\b(?:void|return|function)\b|\.[a-zA-Z_]", val):
            continue
        # A real secret token is mostly one contiguous alnum run; reject if it
        # contains a dot/comma between word chars (e.g. get_all_secret=r.x)
        if re.search(r"[A-Za-z0-9]_?[.,]_?[A-Za-z0-9]", val) and "." in val:
            continue

        already_seen.add(val)
        start = max(0, m.start() - 80)
        end   = min(len(content), m.end() + 80)
        ctx   = content[start:end].replace("\n", " ").replace("\r", "").strip()

        out.append({
            "url":        url,
            "name":       f"Generic High-Entropy Secret (near '{kw}')",
            "match":      val[:400],
            "context":    ctx[:300],
            "confidence": "medium",
            "timestamp":  datetime.now().isoformat(),
        })
    return out


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

class Pipeline:
    def __init__(self, args):
        self.args    = args
        self.domain  = args.domain
        self.ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.outdir  = Path(f"output_{self.domain}_{self.ts}")
        self.outdir.mkdir(parents=True, exist_ok=True)

        self.f_subs    = str(self.outdir / "01_subdomains.txt")
        self.f_live    = str(self.outdir / "02_live_hosts.txt")
        self.f_urls    = str(self.outdir / "03_all_urls.txt")
        self.f_js      = str(self.outdir / "04_js_urls.txt")
        self.f_js_live = str(self.outdir / "04_js_urls_live.txt")
        self.f_secrets = str(self.outdir / "05_secrets.txt")
        self.f_json    = str(self.outdir / "05_secrets.json")

        pattern_defs, src = load_pattern_defs(getattr(self.args, "patterns", None))
        self.patterns      = compile_patterns(pattern_defs)
        self.pattern_src   = src
        self.findings      = []
        self._lock         = threading.Lock()

        # Content-hash cache: skip scanning byte-identical files served from
        # multiple URLs (cdn1/app.js, cdn2/app.js, …). Guarded by its own lock.
        self._seen_hashes  = set()
        self._hash_lock    = threading.Lock()

        # Pooled HTTP session — keepalive + connection reuse + retry/backoff,
        # far fewer TCP/TLS handshakes than bare requests.get per URL.
        self.session = self._build_session()

        log(f"Target domain : {self.domain}", "info")
        log(f"Output dir    : {self.outdir}", "info")
        log(f"Patterns      : {len(self.patterns)} compiled ({src})", "info")
        if not getattr(self.args, "no_entropy", False):
            log(f"Generic entropy detector: ON (min entropy "
                f"{getattr(self.args, 'min_entropy', 3.5)})", "info")

    def _build_session(self):
        from requests.adapters import HTTPAdapter
        try:
            from urllib3.util.retry import Retry
        except ImportError:
            from requests.packages.urllib3.util.retry import Retry  # type: ignore

        sess = requests.Session()
        retry = Retry(
            total=2, connect=2, read=1,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        pool = max(self.args.threads * 2, 50)
        adapter = HTTPAdapter(
            pool_connections=pool,
            pool_maxsize=pool,
            max_retries=retry,
        )
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        if self.args.proxy:
            sess.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        return sess

    # ─── Stage 1: Subfinder ──────────────────────────────────────────────────
    def run_subfinder(self):
        log(f"[1/5] Subdomain enumeration → {self.f_subs}", "info")
        cmd = [
            "subfinder", "-d", self.domain,
            "-o", self.f_subs,
            "-all", "-silent", "-recursive",
            "-t", str(self.args.subfinder_threads),
        ]
        if self.args.resolvers:
            cmd += ["-rL", self.args.resolvers]

        run_cmd(cmd, timeout=900)
        subs = read_file(self.f_subs)

        # Always include root domain
        if self.domain not in subs:
            subs.insert(0, self.domain)
        write_file(self.f_subs, subs)
        log(f"  Subdomains found: {len(subs)}", "ok")
        return subs

    # ─── Stage 2: HTTPX ──────────────────────────────────────────────────────
    def _httpx_probe(self, infile, outfile, label):
        """
        Run httpx over a list of URLs/hosts and return the live ones as clean URLs.
        Reused for both the host-liveness pass and the JS-URL liveness pass.
        """
        cmd = [
            "httpx",
            "-l",       infile,
            "-o",       outfile,
            "-silent",
            "-threads", str(self.args.httpx_threads),
            "-timeout", str(self.args.timeout),
            "-follow-redirects",
        ]
        if self.args.rate_limit:
            cmd += ["-rate-limit", str(self.args.rate_limit)]

        run_cmd(cmd, timeout=1800)

        # httpx may include status/title columns — keep only the clean URL token
        urls = []
        for line in read_file(outfile):
            part = line.split()[0]
            if part.startswith("http"):
                urls.append(part)
        write_file(outfile, urls)
        return urls

    def run_httpx(self):
        log(f"[2/5] Probing live hosts → {self.f_live}", "info")
        urls = self._httpx_probe(self.f_subs, self.f_live, "hosts")
        log(f"  Live hosts found: {len(urls)}", "ok")
        return urls

    # ─── Stage 3: Katana ─────────────────────────────────────────────────────
    def run_katana(self):
        log(f"[3a/5] Crawling with Katana (-jc ) → {self.f_urls}", "info")
        cmd = [
            "katana",
            "-list",    self.f_live,
            "-o",       self.f_urls,
            "-silent",
            "-jc",                    # parse endpoints out of JavaScript files
            "-d",       str(self.args.depth),
            "-c",       str(self.args.concurrency),
            "-p",       str(self.args.parallelism),
            "-timeout", str(self.args.timeout),
            "-ct",      f"{self.args.crawl_time}s",   # -crawl-duration: total crawl time (value needs unit)
            "-fsu",                                   # filter similar-looking URLs (collapses webpack noise)
            "-iqp",                                   # ignore duplicate paths differing only by query param
            "-ef",      "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,css,scss,map",
        ]
        # Hard cap on pages per domain — the precise defense against SPA explosions.
        if self.args.max_domain_pages:
            cmd += ["-mdp", str(self.args.max_domain_pages)]
        # Keep crawl on the root apex domain unless user opts into external hosts.
        if not self.args.include_external:
            cmd += ["-fs", "rdn"]     # field-scope: root-domain name
        if self.args.rate_limit:
            cmd += ["-rl", str(self.args.rate_limit)]
        if self.args.proxy:
            cmd += ["-proxy", self.args.proxy]

        run_cmd(cmd, timeout=self.args.crawl_timeout)

        all_urls = read_file(self.f_urls)
        log(f"  Total URLs discovered by Katana: {len(all_urls)}", "ok")
        return all_urls

    # ─── Stage 3b: GAU historical URLs (optional, on by default) ──────────────
    def run_gau(self):
        if self.args.no_gau:
            return []
        if not shutil.which("gau"):
            log("  gau not installed — skipping historical URLs "
                "(install: go install github.com/lc/gau/v2/cmd/gau@latest)", "warn")
            return []
        log(f"[3b/5] Fetching historical URLs with gau …", "info")
        cmd = ["gau", "--subs", "--threads", str(self.args.gau_threads), self.domain]
        stdout, stderr, rc = run_cmd(cmd, timeout=self.args.gau_timeout)
        urls = [u.strip() for u in stdout.splitlines() if u.strip().startswith("http")]
        log(f"  gau returned {len(urls)} historical URLs", "ok")
        return urls

    # ─── Merge + filter Katana & GAU into the scannable candidate list ────────
    def collect_candidates(self, katana_urls, gau_urls):
        all_urls = list(dict.fromkeys(katana_urls + gau_urls))
        log(f"  Combined unique URLs (katana+gau): {len(all_urls)}", "info")

        # Filter to scannable URLs (js/json/config). With --all-files, keep more.
        js_urls = [u for u in all_urls if self._should_scan(u)]
        log(f"  After file-type filter: {len(js_urls)}", "info")

        # Discover source maps for every .js (probe .js.map alongside each .js)
        if not self.args.no_sourcemaps:
            maps = []
            for u in js_urls:
                base = u.split("?", 1)[0]
                if base.endswith(".js"):
                    maps.append(base + ".map")
            if maps:
                js_urls.extend(maps)
                log(f"  Added {len(maps)} candidate .js.map source maps", "info")

        # Drop off-scope third-party hosts (github.com, vercel.live, nextjs.org…)
        if not self.args.include_external:
            before = len(js_urls)
            js_urls = [u for u in js_urls if self._in_scope(u)]
            dropped = before - len(js_urls)
            if dropped:
                log(f"  Dropped {dropped} off-scope third-party URLs "
                    f"(use --include-external to keep them)", "info")

        # Deduplicate
        before = len(js_urls)
        js_urls = list(dict.fromkeys(js_urls))
        if before != len(js_urls):
            log(f"  Deduplicated {before - len(js_urls)} repeat URLs", "info")

        # Prioritise interesting filenames (config/auth/secret/etc.) first so any
        # findings surface early. Does NOT drop anything — pure ordering.
        js_urls.sort(key=self._priority_score)

        if len(js_urls) > self.args.warn_urls:
            log(f"  NOTE: {len(js_urls)} candidate URLs — larger than usual. "
                f"If this seems too high, lower --depth or --crawl-time. "
                f"Proceeding to scan all of them.", "warn")

        write_file(self.f_js, js_urls)
        log(f"  Candidate JS/JSON/config/map URLs: {len(js_urls)}", "ok")
        return js_urls

    # Lower score = scanned earlier. Interesting keywords float to the top.
    _PRIORITY_WORDS = (
        "config", "env", "auth", "token", "apikey", "api-key", "api_key",
        "secret", "admin", "internal", "prod", "staging", "settings",
        "credential", "key", "private",
    )

    def _priority_score(self, url):
        low = url.lower()
        for i, w in enumerate(self._PRIORITY_WORDS):
            if w in low:
                return i           # earlier keyword = higher priority
        return 999

    # ─── Stage 4: HTTPX liveness on the filtered JS URLs ──────────────────────
    def run_httpx_js(self, js_urls):
        log(f"[4/5] Probing which JS/JSON URLs are live → {self.f_js_live}", "info")
        if not js_urls:
            return []
        # write_file already happened in collect_candidates (self.f_js holds candidates)
        live = self._httpx_probe(self.f_js, self.f_js_live, "js-urls")
        # Keep only in-scope after redirects, unless including external
        if not self.args.include_external:
            live = [u for u in live if self._in_scope(u)]
        live = list(dict.fromkeys(live))
        write_file(self.f_js_live, live)
        dead = len(js_urls) - len(live)
        log(f"  Live JS/JSON URLs: {len(live)}  (dropped {dead} dead/redirected)", "ok")
        return live

    def _in_scope(self, url):
        """True if the URL's host is the target apex domain or a subdomain of it."""
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            return False
        host = host.lower()
        apex = self.domain.lower()
        return host == apex or host.endswith("." + apex)

    def _should_scan(self, url):
        """
        Decide whether a crawled URL is worth fetching for secrets.

        Default (strict): only JS / JSON / config-type files. This is what you
        want for a focused secret hunt and it keeps the scan list small.

        With --all-files: also keep extension-less URLs (API routes, JS served
        without a .js suffix) at the cost of a larger, noisier scan list.
        """
        path = urlparse(url).path.lower()

        # Always-scan: the high-value source/config file types
        scannable = (
            ".js", ".json", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
            ".env", ".config", ".yml", ".yaml", ".toml", ".properties",
            ".txt", ".xml",
        )
        if any(path.endswith(e) for e in scannable):
            return True

        # Never-scan: binaries / styles / fonts / maps
        skip = (
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".pdf",
            ".zip", ".tar", ".gz", ".mp4", ".mp3", ".avi",
            ".css", ".scss", ".less", ".map",
        )
        if any(path.endswith(e) for e in skip):
            return False

        # Unknown / no-extension URLs: only scan these when --all-files is set.
        return bool(getattr(self.args, "all_files", False))

    # ─── Stage 5: Secret Scan ────────────────────────────────────────────────
    def run_scan(self, js_urls):
        log(f"[5/5] Scanning {len(js_urls)} live URLs for secrets …", "info")
        total = len(js_urls)

        if RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=50, style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("{task.completed}/{task.total}", style="magenta"),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as prog:
                task = prog.add_task("Scanning for secrets…", total=total)
                with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                    futures = {ex.submit(self._scan_url, url): url for url in js_urls}
                    for fut in as_completed(futures):
                        result = fut.result()
                        if result:
                            with self._lock:
                                self.findings.extend(result)
                        prog.update(task, advance=1)
        else:
            done = 0
            with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
                futures = {ex.submit(self._scan_url, url): url for url in js_urls}
                for fut in as_completed(futures):
                    result = fut.result()
                    if result:
                        with self._lock:
                            self.findings.extend(result)
                    done += 1
                    if done % 25 == 0:
                        print(f"  [{done}/{total}] scanned | {len(self.findings)} secrets found so far")

        log(f"  Scan complete — raw findings: {len(self.findings)}", "ok")

    def _scan_url(self, url):
        """
        Fetch a URL and scan its content with all compiled patterns.
        """
        try:
            resp = self.session.get(
                url,
                timeout=(self.args.connect_timeout, self.args.timeout),
                verify=False,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/124.0.0.0 Safari/537.36"
                    ),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8",
                    "Accept-Encoding": "gzip",
                },
                allow_redirects=True,
                stream=True,
            )
            if resp.status_code >= 400:
                resp.close()
                return []

            # Content-Type pre-check: skip binary/media before reading the body.
            # Source maps (.map) report as application/json or octet-stream — allow
            # them through since we add them deliberately.
            ctype = resp.headers.get("Content-Type", "").lower()
            allow = ("javascript", "json", "text/plain", "text/html",
                     "application/xml", "text/xml", "octet-stream",
                     "ecmascript", "application/x-yaml", "yaml")
            block = ("image/", "font/", "video/", "audio/", "text/css")
            if ctype:
                if any(b in ctype for b in block):
                    resp.close()
                    return []
                if not any(a in ctype for a in allow) and not url.split("?")[0].endswith(".map"):
                    resp.close()
                    return []

            # Size guard: skip absurdly large bundles to protect memory/time.
            clen = resp.headers.get("Content-Length")
            if clen and clen.isdigit() and int(clen) > self.args.max_size:
                resp.close()
                return []

            # Read with a hard cap even when Content-Length is absent
            raw = resp.raw.read(self.args.max_size + 1, decode_content=True)
            resp.close()
            if len(raw) > self.args.max_size:
                return []
            content = raw.decode("utf-8", errors="ignore")
        except Exception:
            return []

        if not content or len(content) < 10:
            return []

        # Content-hash dedup: identical file bodies served from multiple URLs
        # (cdn1/app.js, cdn2/app.js …) are scanned only once.
        import hashlib
        sha = hashlib.sha256(content.encode("utf-8", "ignore")).hexdigest()
        with self._hash_lock:
            if sha in self._seen_hashes:
                return []
            self._seen_hashes.add(sha)

        results      = []
        min_conf     = self.args.confidence
        all_seen     = set()   # every value captured by named patterns (for generic dedup)

        for pat in self.patterns:
            # Skip patterns below min confidence early
            if not conf_ok(pat["confidence"], min_conf):
                continue

            try:
                matches = list(pat["regex"].finditer(content))
            except Exception:
                continue

            seen_vals = set()
            for m in matches:
                # Pull the actual secret (capture group if defined, else whole match)
                grp = pat["group"]
                try:
                    val = (m.group(grp) if grp else m.group(0)).strip()
                except (IndexError, re.error):
                    continue

                if not val or len(val) < 6 or val in seen_vals:
                    continue

                # Keyword proximity check (SecretFinder-style context requirement)
                if not keyword_nearby(content, m.start(), m.end(), pat["keyword"]):
                    continue

                # False-positive / entropy filtering
                if is_false_positive(val, pat):
                    continue

                seen_vals.add(val)
                all_seen.add(val)

                # Context window (±80 chars)
                start = max(0, m.start() - 80)
                end   = min(len(content), m.end() + 80)
                ctx   = (
                    content[start:end]
                    .replace("\n", " ")
                    .replace("\r", "")
                    .strip()
                )

                results.append({
                    "url":        url,
                    "name":       pat["name"],
                    "match":      val[:400],
                    "context":    ctx[:300],
                    "confidence": pat["confidence"],
                    "timestamp":  datetime.now().isoformat(),
                })

        # Generic keyword-anchored high-entropy detector (catches unknown/future
        # formats). Skipped if disabled via --no-entropy.
        if not getattr(self.args, "no_entropy", False):
            results.extend(
                generic_entropy_findings(
                    content, url,
                    min_entropy=getattr(self.args, "min_entropy", 3.5),
                    min_conf=min_conf,
                    already_seen=all_seen,
                )
            )

        return results

    # ─── Save Results ─────────────────────────────────────────────────────────
    def save_results(self):
        min_conf = self.args.confidence

        # Filter by confidence
        filtered = [f for f in self.findings if conf_ok(f["confidence"], min_conf)]

        # Deduplicate by (url, name, first-100-chars-of-match)
        seen   = set()
        unique = []
        for f in filtered:
            key = (f["url"], f["name"], f["match"][:100])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        # Sort: high confidence first, then alphabetically by URL
        unique.sort(key=lambda x: (-CONF_ORDER.get(x["confidence"], 0), x["url"]))

        # ── JSON output ──
        with open(self.f_json, "w", encoding="utf-8") as fh:
            json.dump(unique, fh, indent=2, ensure_ascii=False)

        # ── Plain text output ──
        conf_label = {"high": "HIGH  ", "medium": "MEDIUM", "low": "LOW   "}
        lines = [
            "=" * 72,
            f"  ReconSecretHunter — Results for: {self.domain}",
            f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Findings  : {len(unique)} unique secrets",
            "=" * 72,
            "",
        ]

        current_url = None
        for f in unique:
            # Group by URL for readability
            if f["url"] != current_url:
                current_url = f["url"]
                lines.append("")
                lines.append(f"  URL: {current_url}")
                lines.append("  " + "-" * 68)

            label = conf_label.get(f["confidence"], f["confidence"].upper())
            lines.append(f"  [{label}] {f['name']}")
            lines.append(f"           Match   : {f['match']}")
            lines.append(f"           Context : {f['context']}")
            lines.append("")

        write_file(self.f_secrets, lines)

        log(f"Unique secrets saved : {len(unique)}", "ok")
        log(f"Text  → {self.f_secrets}", "ok")
        log(f"JSON  → {self.f_json}", "ok")
        return unique

    # ─── Rich Console Summary ──────────────────────────────────────────────────
    def print_summary(self, unique):
        if not unique:
            log("No secrets found.", "info")
            return

        if RICH:
            high   = [f for f in unique if f["confidence"] == "high"]
            medium = [f for f in unique if f["confidence"] == "medium"]
            low    = [f for f in unique if f["confidence"] == "low"]

            console.print(
                f"\n  [bold]Summary[/bold]  "
                f"[red]High: {len(high)}[/red]  "
                f"[yellow]Medium: {len(medium)}[/yellow]  "
                f"[green]Low: {len(low)}[/green]  "
                f"Total: {len(unique)}\n"
            )

            table = Table(
                title="[bold red]Secrets Discovered[/bold red]",
                box=box.ROUNDED,
                border_style="red",
                show_lines=True,
                header_style="bold magenta",
            )
            table.add_column("Conf",        style="bold",   no_wrap=True, width=8)
            table.add_column("Secret Type", style="yellow bold", no_wrap=True, width=35)
            table.add_column("URL",         style="cyan",   max_width=45)
            table.add_column("Match",       style="green",  max_width=55)

            conf_style = {"high": "bold red", "medium": "bold yellow", "low": "bold green"}
            for f in unique[:300]:  # cap terminal output at 300 rows
                cs = conf_style.get(f["confidence"], "white")
                table.add_row(
                    f"[{cs}]{f['confidence'].upper()}[/{cs}]",
                    f["name"],
                    f["url"][-45:] if len(f["url"]) > 45 else f["url"],
                    f["match"][:55],
                )
            console.print(table)

        else:
            print(f"\n[+] Total unique secrets: {len(unique)}")
            for f in unique:
                print(f"  [{f['confidence'].upper()}] {f['name']}")
                print(f"       URL   : {f['url']}")
                print(f"       Match : {f['match'][:80]}")
                print()

    # ─── Full Pipeline ─────────────────────────────────────────────────────────
    def run(self):
        print_banner()
        check_tools()

        log("=" * 60, "info")
        log(f"  Starting pipeline for: {self.domain}", "info")
        log("=" * 60, "info")

        t_start = time.time()

        subs        = self.run_subfinder()
        live        = self.run_httpx()
        katana_urls = self.run_katana()
        gau_urls    = self.run_gau()

        candidates = self.collect_candidates(katana_urls, gau_urls)

        if not candidates:
            log("No JS/JSON/config URLs found — pipeline complete with 0 findings.", "warn")
            return

        js_urls = self.run_httpx_js(candidates)

        if not js_urls:
            log("No live JS/JSON URLs to scan — pipeline complete with 0 findings.", "warn")
            return

        self.run_scan(js_urls)
        unique = self.save_results()
        self.print_summary(unique)

        elapsed = time.time() - t_start
        log("=" * 60, "info")
        log(f"  Domain          : {self.domain}",       "ok")
        log(f"  Subdomains      : {len(subs)}",         "ok")
        log(f"  Live hosts      : {len(live)}",         "ok")
        log(f"  Katana URLs     : {len(katana_urls)}",  "ok")
        log(f"  GAU URLs        : {len(gau_urls)}",      "ok")
        log(f"  JS/JSON candid. : {len(candidates)}",   "ok")
        log(f"  JS/JSON live    : {len(js_urls)}",      "ok")
        log(f"  Secrets found   : {len(unique)}",       "ok")
        log(f"  Elapsed         : {elapsed:.0f}s",      "ok")
        log(f"  Output dir      : {self.outdir}",       "ok")
        log("=" * 60, "info")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="ReconSecretHunter — End-to-End JS Secret Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_secret_hunter.py -d example.com
  python recon_secret_hunter.py -d example.com --confidence high
  python recon_secret_hunter.py -d example.com --depth 5 --threads 30
  python recon_secret_hunter.py -d example.com --proxy http://127.0.0.1:8080
        """
    )

    # Required
    p.add_argument("-d", "--domain",
                   required=True,
                   help="Target domain (e.g. example.com)")

    # Subfinder
    p.add_argument("--resolvers",
                   default=None,
                   help="Custom resolvers file for subfinder")
    p.add_argument("--subfinder-threads",
                   type=int, default=10,
                   help="Subfinder threads (default: 10)")

    # HTTPX
    p.add_argument("--httpx-threads",
                   type=int, default=50,
                   help="HTTPX probing threads (default: 50)")
    p.add_argument("--rate-limit",
                   type=int, default=0,
                   help="Rate limit req/sec across all tools (default: 0 = unlimited)")

    # Katana
    p.add_argument("--depth",
                   type=int, default=2,
                   help="Katana crawl depth (default: 2; depth 3+ on SPAs can "
                        "explode the URL count into the hundreds of thousands)")
    p.add_argument("--concurrency",
                   type=int, default=10,
                   help="Katana concurrency (default: 10)")
    p.add_argument("--parallelism",
                   type=int, default=10,
                   help="Katana parallelism (default: 10)")
    p.add_argument("--crawl-time",
                   type=int, default=180,
                   help="Katana total crawl duration cap in SECONDS "
                        "(-ct/-crawl-duration, default: 180)")
    p.add_argument("--max-domain-pages",
                   type=int, default=2000,
                   help="Katana max pages crawled per domain (-mdp, default: 2000; "
                        "the main hard stop against SPA crawl explosions; 0 = unlimited)")
    p.add_argument("--crawl-timeout",
                   type=int, default=900,
                   help="Overall wall-clock cap for the crawl step in seconds "
                        "(default: 900)")
    p.add_argument("--warn-urls",
                   type=int, default=10000,
                   help="Warn (but do not cap) if the filtered URL count exceeds "
                        "this, signalling a likely crawl explosion (default: 10000)")
    p.add_argument("--no-gau",
                   action="store_true",
                   help="Disable gau historical-URL discovery (default: on if gau "
                        "is installed)")
    p.add_argument("--gau-threads",
                   type=int, default=5,
                   help="gau threads (default: 5)")
    p.add_argument("--gau-timeout",
                   type=int, default=300,
                   help="gau overall timeout in seconds (default: 300)")
    p.add_argument("--no-sourcemaps",
                   action="store_true",
                   help="Do not probe for .js.map source maps alongside each .js "
                        "(default: probe them — they often expose keys/source)")
    p.add_argument("--all-files",
                   action="store_true",
                   help="Also scan extension-less URLs (API routes, JS without a "
                        ".js suffix). Default off = strict js/json/config only.")

    # Secret scanner
    p.add_argument("-t", "--threads",
                   type=int, default=50,
                   help="Secret scan threads — parallel URL fetches (default: 50)")
    p.add_argument("--timeout",
                   type=int, default=15,
                   help="HTTP read timeout in seconds (default: 15)")
    p.add_argument("--connect-timeout",
                   type=int, default=5,
                   help="HTTP connect timeout in seconds (default: 5)")
    p.add_argument("--max-size",
                   type=int, default=20 * 1024 * 1024,
                   help="Max response bytes to scan (default: 20MB; larger files skipped)")
    p.add_argument("--confidence",
                   choices=["low", "medium", "high"],
                   default="medium",
                   help="Minimum confidence level to report (default: medium)")

    # Misc
    p.add_argument("--patterns",
                   default=None,
                   help="Path to external patterns.json (default: auto-detect "
                        "patterns.json beside the script, else built-in)")
    p.add_argument("--no-entropy",
                   action="store_true",
                   help="Disable the generic high-entropy detector "
                        "(named patterns only)")
    p.add_argument("--min-entropy",
                   type=float, default=3.5,
                   help="Min Shannon entropy for generic detector (default: 3.5; "
                        "lower = more catches + more noise)")
    p.add_argument("--include-external",
                   action="store_true",
                   help="Also crawl & scan third-party hosts found in JS "
                        "(default: stay on the target domain only)")
    p.add_argument("--proxy",
                   default=None,
                   help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")

    return p.parse_args()


if __name__ == "__main__":
    Pipeline(parse_args()).run()
