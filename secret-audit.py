#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
secret-audit.py - find tokens, secrets and passwords that are visible on this computer
and write a single-page HTML dashboard with MASKED values and full file paths.

    python3 ~/secret-audit.py                 # scan your home folder, write ~/secret-audit-report.html
    python3 ~/secret-audit.py --open          # ...and open the report in your browser
    python3 ~/secret-audit.py --deep          # also scan most of ~/Library (slower, noisier)
    python3 ~/secret-audit.py --procs         # also read the environment of your running processes
    python3 ~/secret-audit.py --root DIR ...  # scan DIR instead of your home folder (repeatable)
    python3 ~/secret-audit.py --include-cloud # also scan OneDrive / Google Drive / iCloud folders
    python3 ~/secret-audit.py --help

What it looks at
  * environment variables of this process (and, with --procs, of your other processes)
  * every readable text file under your home folder: dotfiles, .env files, shell history,
    cloud/CLI configs, SSH keys, JSON/YAML/INI/plist files, notes, code, logs
  * file permissions and (if the file is in a git repo) whether git tracks it

What it never does
  * It makes NO network connections. The standard library `socket` module is disabled at
    start-up, the report page carries a Content-Security-Policy that forbids every
    request, and the script imports no HTTP code. (Only local helpers `git` and `ps` are run.)
  * It never writes a full secret anywhere. Values are masked in memory the moment they
    are found (e.g. ghp_••••••••abc) and only the masked form, its length and a salted
    fingerprint (to spot the same secret reused in several places) are stored. Before the
    report is saved it is re-scanned for unmasked secrets as a self-check.
  * It does not touch the macOS Keychain, browser password stores or binary databases.

For a hard guarantee you can also run it with the network denied by the OS:
    sandbox-exec -p '(version 1)(allow default)(deny network*)' python3 ~/secret-audit.py
(--procs cannot be combined with sandbox-exec because the sandbox blocks the `ps` helper.)

The report file is created with mode 600 (owner only). Delete it when you are done.
Python 3.8+, standard library only.
"""
import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

# --- belt and braces: no networking from this process, ever -------------------------------
def _network_disabled(*_a, **_k):
    raise RuntimeError("secret-audit: network access is disabled")


socket.socket = _network_disabled
socket.create_connection = _network_disabled
socket.getaddrinfo = _network_disabled
socket.gethostbyname = _network_disabled

HOME = os.path.expanduser("~")
SALT = os.urandom(16)
VERSION = "1.0"

# ------------------------------------------------------------------------------------------
# What to skip
# ------------------------------------------------------------------------------------------
SKIP_DIR_NAMES = {
    "node_modules", ".Trash", "__pycache__", "site-packages", ".cache", ".npm", ".pnpm-store",
    "Pods", "DerivedData", ".gradle", ".terraform", ".next", ".nuxt", ".tox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".sass-cache", "bower_components", ".bundle",
}
SKIP_REL_DIRS = {  # relative to $HOME
    "Movies", "Music", "Pictures", "Parallels", "Applications", "Applications (Parallels)",
    "go/pkg/mod", ".cargo/registry", ".rustup", ".nvm/versions", ".pyenv/versions",
    ".sdkman/candidates", ".vscode/extensions", ".cursor/extensions", ".docker/desktop",
    ".gvm", ".asdf/installs", ".jenv/versions", ".volta", ".bun/install/cache", ".yarn/berry/cache",
    ".local/share/virtualenvs", ".ollama/models", ".lmstudio/models", ".cache",
}
CLOUD_TOP_NAMES = {"My Drive", "Dropbox", "Google Drive", "iCloud Drive", "Box", "Box Sync"}
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".heic", ".tiff", ".bmp", ".ico", ".icns", ".psd",
    ".mp3", ".mp4", ".m4a", ".mov", ".avi", ".mkv", ".wav", ".flac", ".aac",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".dmg", ".iso", ".pkg", ".jar", ".war",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".numbers", ".pages",
    ".class", ".o", ".a", ".so", ".dylib", ".pyc", ".pyo", ".wasm", ".exe", ".dll", ".bin",
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".svg", ".map",
    ".sqlite", ".sqlite3", ".db", ".realm", ".mdb", ".parquet", ".vmdk", ".qcow2", ".pvm", ".hdd",
}
# Keynote ".key" files are zip archives, so the binary check skips them; PEM ".key" files get scanned.
LOCK_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "poetry.lock",
    "Cargo.lock", "go.sum", "composer.lock", "Gemfile.lock", "npm-shrinkwrap.json",
}
HISTORY_NAMES = {
    ".zsh_history", ".bash_history", ".python_history", ".psql_history", ".mysql_history",
    ".node_repl_history", ".rediscli_history", ".sqlite_history", ".lesshst",
}
LIBRARY_ALLOW = [
    "Library/LaunchAgents",
    "Library/Application Support/Code/User",
    "Library/Application Support/Cursor/User",
    "Library/Application Support/Claude",
]
LIBRARY_DEEP_SKIP = {
    "Library/Caches", "Library/CloudStorage", "Library/Mobile Documents", "Library/Developer",
    "Library/Photos", "Library/Containers/com.apple.Safari", "Library/Application Support/MobileSync",
    "Library/Application Support/AddressBook", "Library/Metadata", "Library/Biome",
    "Library/Application Support/Knowledge", "Library/Trial", "Library/Daemon Containers",
}

# ------------------------------------------------------------------------------------------
# Detectors
# ------------------------------------------------------------------------------------------
# (type, severity, cheap-prefilter needles, regex, value group)
PATTERNS = [
    ("AWS access key ID", "critical", ("AKIA", "ASIA"), r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b", 1),
    ("GitHub token", "high", ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
     r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b", 1),
    ("GitLab token", "high", ("glpat-",), r"\b(glpat-[A-Za-z0-9_\-]{20,})", 1),
    ("Slack token", "high", ("xox", "xapp-"),
     r"\b(xox[abeoprs]-[A-Za-z0-9-]{10,}|xapp-\d-[A-Za-z0-9-]{10,})", 1),
    ("Slack webhook URL", "high", ("hooks.slack.com",),
     r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,})", 1),
    ("Discord webhook URL", "high", ("/api/webhooks/",),
     r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{30,})", 1),
    ("Stripe live key", "critical", ("sk_live_", "rk_live_"), r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})", 1),
    ("Stripe test key", "low", ("sk_test_", "rk_test_"), r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})", 1),
    ("Google API key", "high", ("AIza",), r"\b(AIza[0-9A-Za-z_\-]{35})\b", 1),
    ("Anthropic API key", "high", ("sk-ant-",), r"\b(sk-ant-[A-Za-z0-9_\-]{20,})", 1),
    ("OpenAI API key", "high", ("sk-",), r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,})", 1),
    ("xAI API key", "high", ("xai-",), r"\b(xai-[A-Za-z0-9]{40,})", 1),
    ("Firecrawl API key", "high", ("fc-",), r"\b(fc-[a-f0-9]{32})\b", 1),
    ("Hugging Face token", "high", ("hf_",), r"\b(hf_[A-Za-z0-9]{30,})\b", 1),
    ("npm token", "high", ("npm_",), r"\b(npm_[A-Za-z0-9]{36})\b", 1),
    ("PyPI token", "high", ("pypi-",), r"\b(pypi-AgE[A-Za-z0-9_\-]{50,})", 1),
    ("SendGrid key", "high", ("SG.",), r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", 1),
    ("DigitalOcean token", "high", ("dop_v1_", "doo_v1_"), r"\b(do[op]_v1_[a-f0-9]{64})\b", 1),
    ("Atlassian API token", "high", ("ATATT",), r"\b(ATATT[A-Za-z0-9_\-=]{40,})", 1),
    ("Docker access token", "high", ("dckr_pat_",), r"\b(dckr_pat_[A-Za-z0-9_\-]{20,})", 1),
    ("Telegram bot token", "high", (":AA",), r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b", 1),
    ("Shopify token", "high", ("shpat_", "shpss_", "shpca_", "shppa_"), r"\b(shp(?:at|ss|ca|pa)_[a-f0-9]{32})\b", 1),
    ("Vault token", "high", ("hvs.", "hvb."), r"\b(hv[sb]\.[A-Za-z0-9_\-]{20,})", 1),
    ("Linear API key", "high", ("lin_api_",), r"\b(lin_api_[A-Za-z0-9]{30,})", 1),
    ("Notion token", "high", ("ntn_",), r"\b(ntn_[A-Za-z0-9]{30,})", 1),
    ("JSON Web Token", "medium", ("eyJ",),
     r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})", 1),
    ("Bearer token", "medium", ("earer", "EARER"), r"(?i)\bbearer\s+([A-Za-z0-9._~+/=\-]{24,})", 1),
]
PATTERNS = [(t, s, n, re.compile(rx), g) for t, s, n, rx, g in PATTERNS]

URL_RE = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,15})://([^\s:/@'\"<>`]{1,64}):([^\s@/'\"<>`]{3,128})@"
    r"([^\s/'\"<>`:]+(?::\d+)?)"
)
GEN_RE = re.compile(
    r"""(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_.\-]{1,60})["']?\s*[:=]\s*"""
    r"""(?:"([^"\n]{6,400})"|'([^'\n]{6,400})'|([^\s"'`,;#<>(){}\[\]|\\]{6,400}))"""
)
PLIST_RE = re.compile(r"<key>([^<]{2,80})</key>\s*<string>([^<]{6,400})</string>")
PK_RE = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----(.{0,24000}?)-----END ", re.S)
HINTS = ("pass", "pwd", "secret", "token", "key", "auth", "cred", "bearer")

PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|•+|\.+|-+|_+|0+|1+|1234\d*|(?:your|my|the)[-_ ]?[\w-]*|change[-_]?me|example[\w-]*|"
    r"placeholder|redacted|dummy|sample|null|none|nil|true|false|undefined|todo|tbd|secret|password|"
    r"passwd|token|apikey|api[-_]?key|admin|root|test|string|text|value|[\w-]*here|[\w-]*goes[-_]?here)$"
)
EXCL_SEGS = {
    "url", "uri", "endpoint", "type", "expires", "expiry", "expiration", "ttl", "path", "file", "length",
    "count", "size", "format", "header", "prefix", "field", "label", "hint", "placeholder", "policy",
    "required", "enabled", "disabled", "min", "max", "env", "var", "ref", "source", "provider", "mode",
    "algorithm", "alg", "kind", "name", "names", "id", "ids", "regex", "pattern", "example", "help",
    "description", "desc", "message", "msg", "title", "page", "dir", "folder", "store", "manager",
    "helper", "command", "cmd", "flag", "option", "options", "style", "color", "colour", "icon",
    "limit", "usage", "tokens", "secrets", "keys", "version", "status", "state", "scope", "scopes",
    "public", "from", "inject", "annotation", "annotations", "selector", "template", "namespace",
}
PAIRS = {
    ("api", "key"), ("access", "key"), ("private", "key"), ("secret", "key"), ("client", "secret"),
    ("signing", "key"), ("encryption", "key"), ("master", "key"), ("auth", "key"), ("auth", "token"),
    ("key", "data"), ("app", "secret"), ("api", "secret"), ("session", "secret"), ("account", "key"),
}
STRONG_SEGS = {"credential", "credentials", "bearer", "authorization", "apikey", "passphrase"}


def shannon(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def mask(v):
    n = len(v)
    if n >= 24:
        return v[:4] + "•" * 8 + v[-3:]
    if n >= 14:
        return v[:3] + "•" * 6 + v[-2:]
    if n >= 8:
        return v[:1] + "•" * 6 + v[-1:]
    return "•" * 6


def fingerprint(v):
    return hmac.new(SALT, v.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]


def name_kind(name, path="", base=""):
    """Return 'password', 'secret' or None for a variable / key name."""
    n = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    segs = [s for s in re.split(r"[^A-Za-z0-9]+", n.lower()) if s]
    if not segs or any(s in EXCL_SEGS for s in segs):
        return None
    if segs == ["auth"] and (base in (".npmrc", ".dockercfg") or "/.docker/" in path):
        return "secret"
    for s in segs:
        if s in ("password", "passwd", "passphrase", "pass", "pwd") or s.endswith(("password", "passwd")):
            return "password"
    for s in segs:
        if s in STRONG_SEGS or (len(s) > 5 and s.endswith(("token", "secret"))) or s in ("token", "secret"):
            return "secret"
    for a, b in zip(segs, segs[1:]):
        if (a, b) in PAIRS:
            return "secret"
    j = "".join(segs)
    if "apikey" in j or "accesskey" in j or "privatekey" in j or "secretkey" in j:
        return "secret"
    return None


def plausible(v, minlen=8, ent=2.5, wordy=True):
    """Does this value look like a real credential (not a placeholder, path or code)?"""
    v = v.strip().strip(",;")
    if len(v) < minlen or len(v) > 400:
        return False
    if PLACEHOLDER_RE.match(v) or v[0] in "$%<{([@&*!#":
        return False
    if "${" in v or "{{" in v or "$(" in v or "<%" in v or "://" in v:
        return False
    low = v.lower()
    if low.startswith(("process.", "os.", "env.", "env[", "getenv", "config.", "settings.", "secrets.",
                       "vault:", "ref:", "file:", "sm://", "op://", "self.", "this.", "args.", "params.",
                       "request.", "input(", "getpass", "none", "null")):
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", v):
        return False  # dotted attribute access
    if re.fullmatch(r"[a-z_\-]+", v) or re.fullmatch(r"[A-Z]?[a-z]{2,}(?:[A-Z][a-z]{2,})+", v):
        return False  # plain identifier / camelCase
    if re.fullmatch(r"[A-Z][A-Z_]+", v):
        return False  # CONSTANT_NAME
    if v.startswith(("/", "./", "../", "~/")):
        return False
    if wordy and re.fullmatch(r"[a-z0-9_.\-/:]+", v) and ("/" in v or re.search(r"[a-z]{3,}[-_.][a-z]{3,}", v)):
        return False  # lowercase words / k8s refs / paths, e.g. cert-manager/ca-secret
    return shannon(v) >= ent


def sensitive_kind(path, base):
    """Name-based classification of files that usually hold credentials."""
    low = base.lower()
    if base == ".env" or low.endswith(".env") or (low.startswith(".env.") and not low.endswith(
            (".example", ".sample", ".template", ".dist", ".defaults", ".tpl"))):
        return "dotenv file"
    if base in (".netrc", "_netrc"):
        return "netrc credentials"
    if base == ".git-credentials":
        return "git credential store"
    if base in (".pgpass", ".my.cnf", ".pypirc", ".dockercfg", ".htpasswd", ".boto", ".s3cfg"):
        return "credential config (%s)" % base
    if base == ".npmrc":
        return "npm config (may hold auth token)"
    if base == "credentials" and "/.aws/" in path:
        return "AWS credentials file"
    if base == "config" and ("/.kube/" in path or "/.docker/" in path):
        return "kube/docker config"
    if base == "config.json" and "/.docker/" in path:
        return "docker config"
    if re.fullmatch(r"id_(rsa|dsa|ecdsa|ed25519)(_[\w\-]+)?", base) and "/.ssh/" in path:
        return "SSH private key"
    if low.endswith((".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")):
        return "key / certificate file"
    if low in ("terraform.tfstate", "terraform.tfstate.backup") or low.endswith((".tfvars", ".auto.tfvars")):
        return "terraform state / variables"
    if low in ("secrets.yml", "secrets.yaml", "secrets.json", "credentials.json", "token.json", "accesstokens.json",
               "application_default_credentials.json", "claude_desktop_config.json") or \
            re.fullmatch(r"(client_secret|service[-_]?account)[\w\-.]*\.json", low):
        return "credentials JSON"
    if low.endswith(".kdbx"):
        return "password database (encrypted)"
    if base in HISTORY_NAMES:
        return "shell / REPL history"
    return None


# ------------------------------------------------------------------------------------------
# State
# ------------------------------------------------------------------------------------------
FINDINGS = []
SENSITIVE_FILES = {}   # path -> dict
ERRORS = []
STATS = Counter()
SKIPPED_DIRS = []
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_git_root_cache = {}
HAVE_GIT = bool(shutil.which("git"))


def overlaps(claimed, s, e):
    return any(s < ce and e > cs for cs, ce in claimed)


def make_finding(sev, typ, name, value_for_fp, masked, length, path, line, src, meta):
    f = {"s": sev, "t": typ, "n": name, "m": masked, "l": length, "f": fingerprint(value_for_fp),
         "p": path, "ln": line, "src": src}
    f.update(meta or {})
    return f


class FileCtx:
    """Collects findings for one file (or one env source), de-duplicating and capping."""

    CAP = 300

    def __init__(self, path, src, meta):
        self.path, self.src, self.meta = path, src, meta
        self.seen = set()
        self.count = 0
        self.truncated = False

    def add(self, sev, typ, name, value, masked, line):
        key = (line, typ, fingerprint(value))
        if key in self.seen:
            return
        if self.count >= self.CAP:
            self.truncated = True
            return
        self.seen.add(key)
        self.count += 1
        FINDINGS.append(make_finding(sev, typ, name, value, masked, len(value), self.path, line, self.src, self.meta))


def scan_line(line, ln, ctx, path="", base="", plist=False):
    if len(line) > 20000:
        line = line[:20000]
    claimed = []
    for typ, sev, needles, rx, grp in PATTERNS:
        if not any(nd in line for nd in needles):
            continue
        for m in rx.finditer(line):
            s, e = m.span(grp)
            if overlaps(claimed, s, e):
                continue
            v = m.group(grp)
            if "EXAMPLE" in v.upper() or shannon(v) < 2.2:
                continue
            claimed.append((s, e))
            ctx.add(sev, typ, typ, v, mask(v), ln)
    if "://" in line and "@" in line:
        for m in URL_RE.finditer(line):
            pw = m.group(3)
            if overlaps(claimed, *m.span(3)) or not plausible(pw, minlen=3, ent=1.5, wordy=False):
                continue
            claimed.append(m.span(3))
            scheme, user, host = m.group(1), m.group(2), m.group(4)
            ctx.add("high", "Password in URL", scheme + "://" + user + "@" + host, pw,
                    "%s://%s:%s@%s" % (scheme, user, mask(pw), host), ln)
    if len(line) <= 3000 and (":" in line or "=" in line):
        ll = line.lower()
        if any(h in ll for h in HINTS):
            for m in GEN_RE.finditer(line):
                name = m.group(1)
                gi = 2 if m.group(2) is not None else 3 if m.group(3) is not None else 4
                val = m.group(gi)
                if overlaps(claimed, *m.span(gi)):
                    continue
                kind = name_kind(name, path, base)
                if not kind:
                    continue
                if kind == "password":
                    if not plausible(val, minlen=6, ent=2.0, wordy=False):
                        continue
                    sev = "high" if (len(val) >= 12 and shannon(val) >= 3.2) else "medium"
                    typ = "Password"
                else:
                    if not plausible(val):
                        continue
                    ent, n = shannon(val), len(val)
                    sev = "high" if (n >= 20 and ent >= 3.6) else "medium" if (n >= 12 and ent >= 3.0) else "low"
                    typ = "Secret / token"
                claimed.append(m.span(gi))
                ctx.add(sev, typ, name, val, mask(val), ln)


def openssh_encrypted(header, clean):
    if not header.startswith("OPENSSH"):
        return False
    try:
        b = clean[:120]
        raw = base64.b64decode(b[: len(b) // 4 * 4])
        if not raw.startswith(b"openssh-key-v1\x00"):
            return False
        n = int.from_bytes(raw[15:19], "big")
        return raw[19:19 + n] != b"none"
    except Exception:
        return False


def scan_text(text, ctx, path, base):
    for m in PK_RE.finditer(text):
        header, body = m.group(1), m.group(2)
        clean = re.sub(r"(\\n|\\r|\s)+", "", body)
        if len(clean) < 60:
            continue
        line = text.count("\n", 0, m.start()) + 1
        enc = "ENCRYPTED" in header or "ENCRYPTED" in body[:300] or openssh_encrypted(header, clean)
        ctx.add("medium" if enc else "critical",
                "Private key (passphrase-protected)" if enc else "Private key (unencrypted)",
                header, clean, "BEGIN %s  %s  (%d chars)" % (header, mask(clean), len(clean)), line)
    is_plist = base.lower().endswith(".plist")
    for i, line in enumerate(text.split("\n"), 1):
        if len(line) < 6:
            continue
        scan_line(line, i, ctx, path, base)
    if is_plist:
        for m in PLIST_RE.finditer(text):
            kind = name_kind(m.group(1), path, base)
            if kind and plausible(m.group(2), minlen=6 if kind == "password" else 8, wordy=kind != "password"):
                ln = text.count("\n", 0, m.start()) + 1
                ctx.add("medium", "Secret / token (plist)", m.group(1), m.group(2), mask(m.group(2)), ln)


# ------------------------------------------------------------------------------------------
# Sources
# ------------------------------------------------------------------------------------------
def scan_env_items(items, src, path_label):
    ctx = FileCtx(path_label, src, {})
    for name, value in items:
        if not value:
            continue
        hit = False
        for typ, sev, needles, rx, grp in PATTERNS:
            if any(nd in value for nd in needles):
                m = rx.search(value)
                if m and "EXAMPLE" not in m.group(grp).upper():
                    ctx.add(sev, typ, name, m.group(grp), mask(m.group(grp)), 0)
                    hit = True
                    break
        if hit:
            continue
        kind = name_kind(name)
        if kind == "password" and plausible(value, minlen=6, ent=2.0, wordy=False):
            ctx.add("medium", "Password", name, value, mask(value), 0)
        elif kind == "secret" and plausible(value):
            ent, n = shannon(value), len(value)
            sev = "high" if (n >= 20 and ent >= 3.6) else "medium" if (n >= 12 and ent >= 3.0) else "low"
            ctx.add(sev, "Secret / token", name, value, mask(value), 0)
        elif "://" in value and "@" in value:
            for m in URL_RE.finditer(value):
                if plausible(m.group(3), minlen=3, ent=1.5, wordy=False):
                    ctx.add("high", "Password in URL", name, m.group(3),
                            "%s://%s:%s@%s" % (m.group(1), m.group(2), mask(m.group(3)), m.group(4)), 0)
    STATS["env_vars"] += len(items)


def scan_processes():
    """Environment of your own running processes (`ps eww`). Local only; best effort."""
    try:
        out = subprocess.run(["ps", "eww", "-U", str(os.getuid()), "-o", "pid=,command="],
                             capture_output=True, text=True, timeout=30).stdout
    except Exception as exc:  # pragma: no cover
        ERRORS.append({"p": "ps eww", "e": str(exc)})
        return
    seen = {}
    for line in out.splitlines():
        pid_s, _, rest = line.strip().partition(" ")
        for m in re.finditer(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]{2,60})=(\S{6,400})", rest):
            seen.setdefault((m.group(1), m.group(2)), set()).add(pid_s)
    by_proc = {}
    for (name, value), pids in seen.items():
        by_proc.setdefault("process environment (pids %s)" % ",".join(sorted(pids)[:5]), []).append((name, value))
    for label, items in by_proc.items():
        scan_env_items(items, "proc", label)
    STATS["processes_checked"] = len(out.splitlines())


def git_state(path):
    if not HAVE_GIT:
        return None
    d = os.path.dirname(path)
    root = _git_root_cache.get(d, "?")
    if root == "?":
        cur, root = d, None
        while cur and cur != os.path.dirname(cur):
            if os.path.exists(os.path.join(cur, ".git")):
                root = cur
                break
            cur = os.path.dirname(cur)
        _git_root_cache[d] = root
    if not root:
        return None
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        if subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", path], capture_output=True,
                          timeout=10, env=env).returncode == 0:
            return "tracked"
        if subprocess.run(["git", "-C", root, "check-ignore", "-q", "--", path], capture_output=True,
                          timeout=10, env=env).returncode == 0:
            return "ignored"
        return "untracked"
    except Exception:
        return None


def file_meta(st):
    return {"md": "%o" % stat.S_IMODE(st.st_mode), "mt": int(st.st_mtime),
            "perm": bool(st.st_mode & 0o044)}


def process_file(path, base, st, args):
    STATS["files_seen"] += 1
    kind = sensitive_kind(path, base)
    meta = file_meta(st)
    if kind:
        SENSITIVE_FILES[path] = {"p": path, "k": kind, "sz": st.st_size, "n": 0, **meta}
    if base.startswith("secret-audit"):
        return
    low = base.lower()
    ext = os.path.splitext(low)[1]
    if ext in SKIP_EXT or base in LOCK_NAMES or low.endswith(".min.js"):
        STATS["skipped_type"] += 1
        return
    if st.st_size == 0:
        return
    if st.st_size > args.max_mb * 1024 * 1024:
        STATS["skipped_large"] += 1
        return
    try:
        with open(path, "rb") as fh:
            data = fh.read(args.max_mb * 1024 * 1024 + 1)
    except OSError as exc:
        STATS["unreadable"] += 1
        if len(ERRORS) < 200:
            ERRORS.append({"p": path, "e": exc.strerror or str(exc)})
        return
    if b"\0" in data[:8192]:
        STATS["skipped_binary"] += 1
        return
    STATS["files_scanned"] += 1
    STATS["bytes_scanned"] += len(data)
    text = data.decode("utf-8", "replace")
    before = len(FINDINGS)
    ctx = FileCtx(path, "file", meta)
    scan_text(text, ctx, path, base)
    if ctx.truncated:
        STATS["files_truncated"] += 1
    if kind and path in SENSITIVE_FILES:
        SENSITIVE_FILES[path]["n"] = len(FINDINGS) - before


def scan_git_config(git_dir, args):
    for name in ("config", "credentials"):
        p = os.path.join(git_dir, name)
        try:
            st = os.stat(p)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            process_file(p, name, st, args)


def skip_dir(path, name, rel, args):
    if name in SKIP_DIR_NAMES:
        return "excluded by name"
    if name == "testdata" or re.search(r"@v\d", name):
        return "test data / Go module cache"
    if rel in SKIP_REL_DIRS:
        return "excluded (large / low value)"
    if "/" not in rel and not args.include_cloud and (name.startswith("OneDrive") or name in CLOUD_TOP_NAMES):
        return "cloud-synced folder (use --include-cloud)"
    if rel.startswith("Library/") or rel == "Library":
        if rel == "Library":
            return None
        if args.deep:
            return "excluded (Library noise)" if rel in LIBRARY_DEEP_SKIP else None
        for a in LIBRARY_ALLOW:
            if rel == a or rel.startswith(a + "/") or a.startswith(rel + "/"):
                return None
        return "~/Library (use --deep)"
    return None


def walk_root(root, args, progress):
    root_is_home = os.path.abspath(root) == HOME
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError as exc:
            STATS["unreadable_dirs"] += 1
            if len(ERRORS) < 200:
                ERRORS.append({"p": d, "e": exc.strerror or str(exc)})
            continue
        for e in sorted(entries, key=lambda x: x.name, reverse=True):
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    rel = os.path.relpath(e.path, HOME) if (root_is_home or e.path.startswith(HOME + os.sep)) else e.path
                    if e.name == ".git":
                        scan_git_config(e.path, args)
                        continue
                    why = skip_dir(e.path, e.name, rel, args)
                    if why:
                        STATS["skipped_dirs"] += 1
                        if len(SKIPPED_DIRS) < 300:
                            SKIPPED_DIRS.append({"p": e.path, "why": why})
                        continue
                    stack.append(e.path)
                elif e.is_file(follow_symlinks=False):
                    process_file(e.path, e.name, e.stat(follow_symlinks=False), args)
                    progress()
            except OSError as exc:
                STATS["unreadable"] += 1
                if len(ERRORS) < 200:
                    ERRORS.append({"p": e.path, "e": exc.strerror or str(exc)})


# ------------------------------------------------------------------------------------------
# Report
# ------------------------------------------------------------------------------------------
TEMPLATE_PATH_MARK = "/*__DATA__*/"


def build_html(data):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return HTML_TEMPLATE.replace(TEMPLATE_PATH_MARK, payload)


def self_check(text):
    """Re-scan the finished report with the prefix detectors: nothing unmasked may be in it."""
    problems = []
    for typ, sev, needles, rx, grp in PATTERNS:
        if typ in ("JSON Web Token",):
            continue
        for m in rx.finditer(text):
            v = m.group(grp)
            if "EXAMPLE" not in v.upper() and shannon(v) >= 2.2:
                problems.append(typ)
    for m in PK_RE.finditer(text):
        problems.append("private key body")
    return problems


def main():
    ap = argparse.ArgumentParser(description="Local-only audit of visible secrets; writes a masked HTML dashboard.")
    ap.add_argument("--root", action="append", help="directory to scan instead of $HOME (repeatable)")
    ap.add_argument("--out", default=os.path.join(HOME, "secret-audit-report.html"), help="report path")
    ap.add_argument("--deep", action="store_true", help="scan most of ~/Library too")
    ap.add_argument("--procs", action="store_true", help="also read environments of your running processes")
    ap.add_argument("--include-cloud", action="store_true", help="scan OneDrive/Google Drive/iCloud folders (may download files)")
    ap.add_argument("--max-mb", type=int, default=10, help="skip files larger than this (default 10)")
    ap.add_argument("--no-git", action="store_true", help="do not ask git whether files are tracked")
    ap.add_argument("--open", action="store_true", help="open the report in the default browser when done")
    args = ap.parse_args()

    started = time.time()
    interrupted = False
    tty = sys.stderr.isatty()
    last = [0.0]

    def progress():
        now = time.time()
        if tty and now - last[0] > 0.5:
            last[0] = now
            sys.stderr.write("\r  files %d  scanned %d  findings %d   " % (
                STATS["files_seen"], STATS["files_scanned"], len(FINDINGS)))
            sys.stderr.flush()

    print("secret-audit %s - local only, values are masked" % VERSION)
    scan_env_items(sorted(os.environ.items()), "env", "environment of this process")
    if args.procs:
        scan_processes()
    roots = [os.path.abspath(os.path.expanduser(r)) for r in (args.root or [HOME])]
    try:
        for root in roots:
            print("  scanning %s" % root)
            walk_root(root, args, progress)
        if not args.root:
            for extra in ("/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/profile", "/etc/environment"):
                try:
                    st = os.stat(extra)
                    if stat.S_ISREG(st.st_mode):
                        process_file(extra, os.path.basename(extra), st, args)
                except OSError:
                    pass
    except KeyboardInterrupt:
        interrupted = True
        print("\n  interrupted - writing a partial report")
    if tty:
        sys.stderr.write("\r" + " " * 70 + "\r")

    # enrich file findings with git state (once per file)
    per_file = {}
    for f in FINDINGS:
        if f["src"] == "file":
            per_file.setdefault(f["p"], []).append(f)
    if not args.no_git:
        for p, fs in per_file.items():
            g = git_state(p)
            if g:
                for f in fs:
                    f["g"] = g
        for p, info in SENSITIVE_FILES.items():
            g = git_state(p)
            if g:
                info["g"] = g

    FINDINGS.sort(key=lambda f: (SEV_ORDER[f["s"]], f["p"], f["ln"]))
    sev_counts = Counter(f["s"] for f in FINDINGS)
    data = {
        "meta": {
            "version": VERSION, "home": HOME, "host": platform.node(), "user": os.environ.get("USER", ""),
            "os": "%s %s" % (platform.system(), platform.mac_ver()[0] or platform.release()),
            "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
            "seconds": round(time.time() - started, 1), "roots": roots, "interrupted": interrupted,
            "options": {"deep": args.deep, "procs": args.procs, "include_cloud": args.include_cloud,
                        "max_mb": args.max_mb},
            "stats": dict(STATS),
        },
        "findings": FINDINGS,
        "files": sorted(SENSITIVE_FILES.values(), key=lambda x: x["p"]),
        "errors": ERRORS,
        "skipped": SKIPPED_DIRS,
        "notes": [
            "Values are masked at scan time. Full secrets are never written to this report.",
            "Not covered: macOS Keychain, browser password stores and cookies, binary databases (.sqlite/.db), "
            "PDFs and Office files, archives, files larger than %d MB, symlinks, and other users' files." % args.max_mb,
            "~/Library is skipped except LaunchAgents, VS Code/Cursor user settings and Claude Desktop config "
            "unless --deep is used. Cloud-synced folders are skipped unless --include-cloud is used.",
            "Detection is pattern-based: expect some false positives (test fixtures, examples) and some misses "
            "(secrets without a recognisable name or prefix).",
        ],
    }
    html_text = build_html(data)
    problems = self_check(html_text)
    if problems:
        print("SELF-CHECK FAILED: the report would contain unmasked secrets (%s). Not written." % ", ".join(sorted(set(problems))))
        return 2

    out = os.path.abspath(os.path.expanduser(args.out))
    tmp = out + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(html_text)
    os.replace(tmp, out)
    os.chmod(out, 0o600)

    types = Counter(f["t"] for f in FINDINGS)
    print("\n  files scanned: %d of %d seen   env vars checked: %d   time: %.1fs" % (
        STATS["files_scanned"], STATS["files_seen"], STATS["env_vars"], time.time() - started))
    print("  findings: %d  (critical %d, high %d, medium %d, low %d)   distinct secrets: %d" % (
        len(FINDINGS), sev_counts["critical"], sev_counts["high"], sev_counts["medium"], sev_counts["low"],
        len(set(f["f"] for f in FINDINGS))))
    for t, n in types.most_common(8):
        print("    %5d  %s" % (n, t))
    print("  self-check: report contains no unmasked secrets")
    print("  report: %s  (mode 600)" % out)
    if args.open:
        try:
            subprocess.run(["open", out], timeout=15)
        except Exception:
            pass
    return 0


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Secret Exposure Audit</title>
<style>
:root{
  color-scheme: light;
  --page:#f3f2ef; --surface:#fcfcfb; --surface-2:#f6f5f2; --border:#dcdbd6; --grid:#e6e5e0;
  --text:#0b0b0b; --text-2:#52514e; --text-3:#6b6a65;
  --series:#2a78d6; --series-soft:#cde2fb;
  --crit:#d03b3b; --high:#ec835a; --med:#fab219; --low:#8a8984;
  --focus:#2a78d6; --warn-bg:#fdf1dc; --warn-text:#7a4b00;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    color-scheme: dark;
    --page:#121211; --surface:#1a1a19; --surface-2:#222221; --border:#34332f; --grid:#2b2a27;
    --text:#f0efec; --text-2:#c3c2b7; --text-3:#9d9c93;
    --series:#3987e5; --series-soft:#184f95;
    --crit:#d03b3b; --high:#ec835a; --med:#fab219; --low:#9a998f;
    --focus:#6da7ec; --warn-bg:#3a2d12; --warn-text:#f3c97a;
  }
}
:root[data-theme="dark"]{
  color-scheme: dark;
  --page:#121211; --surface:#1a1a19; --surface-2:#222221; --border:#34332f; --grid:#2b2a27;
  --text:#f0efec; --text-2:#c3c2b7; --text-3:#9d9c93;
  --series:#3987e5; --series-soft:#184f95;
  --crit:#d03b3b; --high:#ec835a; --med:#fab219; --low:#9a998f;
  --focus:#6da7ec; --warn-bg:#3a2d12; --warn-text:#f3c97a;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1320px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:22px;line-height:1.2;margin:0 0 4px;font-weight:650}
h2{font-size:14px;margin:0 0 12px;font-weight:650}
.sub{color:var(--text-2);margin:0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
header.top{display:flex;gap:16px;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;margin-bottom:16px}
.badge{display:inline-flex;gap:6px;align-items:center;font-size:12px;color:var(--text-2);border:1px solid var(--border);background:var(--surface);border-radius:999px;padding:3px 10px;margin:8px 8px 0 0}
.badge b{color:var(--text);font-weight:600}
button,select,input[type=search]{font:inherit;color:var(--text)}
.btn{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:6px 12px;cursor:pointer}
.btn:hover{background:var(--surface-2)}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.tile .n{font-size:28px;line-height:1.1;font-weight:650;font-variant-numeric:tabular-nums}
.tile .l{color:var(--text-2);font-size:12.5px;margin-top:4px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
.filters{display:flex;flex-wrap:wrap;gap:10px 12px;align-items:center;margin-bottom:12px}
.filters input[type=search]{flex:1 1 240px;min-width:180px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:7px 10px}
.filters select{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:7px 8px;max-width:220px}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:4px 10px;cursor:pointer;display:inline-flex;gap:6px;align-items:center}
.chip[aria-pressed=true]{background:var(--surface-2);border-color:var(--text-2);font-weight:600}
.chk{display:inline-flex;gap:6px;align-items:center;color:var(--text-2);white-space:nowrap}
.charts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:16px}
@media (max-width:1000px){.charts{grid-template-columns:1fr}}
.bar-row{display:grid;grid-template-columns:minmax(90px,38%) 1fr auto;gap:10px;align-items:center;width:100%;text-align:left;background:none;border:0;padding:4px 2px;cursor:pointer;border-radius:6px}
.bar-row:hover{background:var(--surface-2)}
.bar-row[aria-pressed=true]{background:var(--surface-2);outline:1px solid var(--border)}
.bar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text)}
.bar-track{height:10px;position:relative}
.bar-fill{position:absolute;left:0;top:0;bottom:0;border-radius:0 4px 4px 0}
.bar-count{font-variant-numeric:tabular-nums;color:var(--text-2);min-width:32px;text-align:right}
.sev{display:inline-flex;gap:6px;align-items:center;white-space:nowrap}
.sev i{font-style:normal;font-size:11px;line-height:1}
.sev-critical i{color:var(--crit)}.sev-high i{color:var(--high)}.sev-medium i{color:var(--med)}.sev-low i{color:var(--low)}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;background:var(--surface)}
table{border-collapse:collapse;width:100%;min-width:980px}
th,td{padding:8px 12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--grid)}
th{position:sticky;top:0;background:var(--surface);font-weight:600;color:var(--text-2);font-size:12.5px;white-space:nowrap}
th button{all:unset;cursor:pointer;display:inline-flex;gap:4px;align-items:center}
th button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
tr.row{cursor:pointer}
tr.row:hover td{background:var(--surface-2)}
td.path{word-break:break-all;min-width:260px}
.ln{color:var(--text-3)}
.mask{min-width:150px;overflow-wrap:anywhere}
.tag{display:inline-block;border:1px solid var(--border);border-radius:6px;padding:0 6px;margin:0 4px 2px 0;font-size:12px;color:var(--text-2);white-space:nowrap}
.tag.warn{background:var(--warn-bg);color:var(--warn-text);border-color:transparent}
tr.detail td{background:var(--surface-2);padding:12px 16px}
dl{display:grid;grid-template-columns:150px 1fr;gap:6px 12px;margin:0}
dt{color:var(--text-2)}dd{margin:0;word-break:break-all}
.copy{margin-left:8px;font-size:12px;padding:1px 8px}
.muted{color:var(--text-2)}
.count{margin:0 0 8px;color:var(--text-2)}
details{margin-top:16px}
details>summary{cursor:pointer;font-weight:600;padding:6px 0}
details .tablewrap{margin-top:8px}
ul.notes{margin:8px 0 0;padding-left:20px;color:var(--text-2)}
.more{display:block;margin:12px auto 0}
#tip{position:fixed;z-index:10;pointer-events:none;background:var(--text);color:var(--page);padding:5px 9px;border-radius:6px;font-size:12px;max-width:340px;display:none}
.empty{padding:28px;text-align:center;color:var(--text-2)}
footer{margin-top:24px;color:var(--text-3);font-size:12px}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <h1>Secret Exposure Audit</h1>
    <p class="sub" id="subtitle"></p>
    <div id="badges"></div>
  </div>
  <div><button class="btn" id="theme" type="button" aria-label="Switch colour theme">Theme: auto</button>
  <button class="btn" id="csv" type="button">Export masked CSV</button></div>
</header>

<section class="tiles" id="tiles" aria-label="Summary"></section>

<section class="card" style="margin-bottom:16px" aria-label="Filters">
  <div class="filters">
    <input type="search" id="q" placeholder="Search path, type, name…" aria-label="Search findings">
    <div class="chips" id="sevchips" role="group" aria-label="Severity"></div>
    <select id="type" aria-label="Finding type"></select>
    <select id="src" aria-label="Source"><option value="">All sources</option><option value="file">Files</option><option value="env">Environment</option><option value="proc">Processes</option></select>
    <label class="chk"><input type="checkbox" id="f-reuse"> Reused in 2+ places</label>
    <label class="chk"><input type="checkbox" id="f-git"> Tracked by git</label>
    <label class="chk"><input type="checkbox" id="f-perm"> Group/other-readable file</label>
    <button class="btn" id="clear" type="button">Clear filters</button>
  </div>
</section>

<section class="charts" aria-label="Charts">
  <div class="card"><h2>By severity</h2><div id="c-sev"></div></div>
  <div class="card"><h2>By type <span class="muted" style="font-weight:400">(click to filter)</span></h2><div id="c-type"></div></div>
  <div class="card"><h2>By location <span class="muted" style="font-weight:400">(click to filter)</span></h2><div id="c-loc"></div></div>
</section>

<p class="count" id="count" aria-live="polite"></p>
<div class="tablewrap">
<table id="tbl">
  <thead><tr id="thead"></tr></thead>
  <tbody id="tbody"></tbody>
</table>
</div>
<button class="btn more" id="more" type="button" hidden>Show more</button>

<details id="files-d"><summary id="files-s">Credential-style files</summary>
  <div class="tablewrap"><table style="min-width:760px"><thead><tr><th>Full path</th><th>Kind</th><th>Mode</th><th>Size</th><th>Modified</th><th>Findings</th><th>Git</th></tr></thead><tbody id="files-b"></tbody></table></div>
</details>
<details id="scan-d"><summary>Scan details and limits</summary><div id="scan"></div></details>
<footer>Generated locally by secret-audit.py. No data left this computer; this page cannot make network requests. Delete this file when you are done: it maps where your secrets are.</footer>
</div>
<div id="tip" role="tooltip"></div>
<script id="data" type="application/json">/*__DATA__*/</script>
<script>
(function(){
'use strict';
var D = JSON.parse(document.getElementById('data').textContent);
var F = D.findings, M = D.meta, HOME = M.home;
var SEV = ['critical','high','medium','low'];
var SEVLABEL = {critical:'Critical',high:'High',medium:'Medium',low:'Low'};
var SEVICON = {critical:'◆',high:'▲',medium:'●',low:'○'};
var SEVCOLOR = {critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)'};
var SEVRANK = {critical:0,high:1,medium:2,low:3};
function $(id){return document.getElementById(id);}
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function fmtDate(t){try{return new Date(t*1000).toLocaleString();}catch(e){return '';}}
function fmtBytes(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';return (n/1048576).toFixed(1)+' MB';}
function locOf(f){
  if(f.src==='env')return 'Environment variables';
  if(f.src==='proc')return 'Running processes';
  var p=f.p;
  if(p.indexOf(HOME+'/')===0){
    var parts=p.slice(HOME.length+1).split('/');
    if(parts.length===1)return '~ (files in home folder)';
    if(parts[0]==='Library'&&parts.length>3)return '~/Library/'+parts[1]+'/'+parts[2];
    return '~/'+parts[0];
  }
  var s=p.split('/');return '/'+s.slice(1,3).join('/');
}
var fpLocs={};
F.forEach(function(f,i){
  f.i=i; f.loc=locOf(f);
  var key=f.p+':'+f.ln;
  (fpLocs[f.f]=fpLocs[f.f]||{})[key]=f;
});
F.forEach(function(f){f.reuse=Object.keys(fpLocs[f.f]).length;});

/* ---------- header, tiles ---------- */
$('subtitle').textContent=M.user+'@'+M.host+' · '+M.os+' · scanned '+new Date(M.generated).toLocaleString()+' · '+M.seconds+' s'+(M.interrupted?' · PARTIAL (interrupted)':'');
$('badges').innerHTML=
  '<span class="badge"><b>Masked</b> values only</span>'+
  '<span class="badge"><b>Local</b> no network</span>'+
  '<span class="badge"><b>'+(M.stats.files_scanned||0).toLocaleString()+'</b> files scanned</span>'+
  '<span class="badge"><b>'+(M.stats.env_vars||0)+'</b> env vars checked</span>';
var distinct={},filesAff={},permFiles={},gitFiles={};
F.forEach(function(f){distinct[f.f]=1; if(f.src==='file'){filesAff[f.p]=1; if(f.perm)permFiles[f.p]=1; if(f.g==='tracked')gitFiles[f.p]=1;}});
var reused=0;Object.keys(fpLocs).forEach(function(k){if(Object.keys(fpLocs[k]).length>1)reused++;});
var sevN={critical:0,high:0,medium:0,low:0};F.forEach(function(f){sevN[f.s]++;});
var tiles=[
 [F.length,'findings in total'],
 [sevN.critical+sevN.high,'critical + high'],
 [Object.keys(distinct).length,'distinct secrets'],
 [Object.keys(filesAff).length,'files containing secrets'],
 [reused,'secrets reused in 2+ places'],
 [Object.keys(permFiles).length,'secret files readable by group/other'],
 [Object.keys(gitFiles).length,'secret files tracked by git']
];
$('tiles').innerHTML=tiles.map(function(t){return '<div class="tile"><div class="n">'+t[0].toLocaleString()+'</div><div class="l">'+esc(t[1])+'</div></div>';}).join('');

/* ---------- state ---------- */
var S={q:'',sev:{},type:'',src:'',loc:'',reuse:false,git:false,perm:false,sort:'s',dir:1,shown:200};
function anySev(){for(var k in S.sev)if(S.sev[k])return true;return false;}
function match(f,skip){
  if(skip!=='sev'&&anySev()&&!S.sev[f.s])return false;
  if(skip!=='type'&&S.type&&f.t!==S.type)return false;
  if(skip!=='loc'&&S.loc&&f.loc!==S.loc)return false;
  if(S.src&&f.src!==S.src)return false;
  if(S.reuse&&f.reuse<2)return false;
  if(S.git&&f.g!=='tracked')return false;
  if(S.perm&&!f.perm)return false;
  if(S.q){var h=(f.p+' '+f.t+' '+f.n+' '+f.m).toLowerCase();if(h.indexOf(S.q)<0)return false;}
  return true;
}
function filtered(skip){return F.filter(function(f){return match(f,skip);});}

/* ---------- filter controls ---------- */
var types={};F.forEach(function(f){types[f.t]=(types[f.t]||0)+1;});
$('type').innerHTML='<option value="">All types</option>'+Object.keys(types).sort().map(function(t){return '<option value="'+esc(t)+'">'+esc(t)+' ('+types[t]+')</option>';}).join('');
$('sevchips').innerHTML=SEV.map(function(s){return '<button type="button" class="chip" data-sev="'+s+'" aria-pressed="false"><span class="sev sev-'+s+'"><i>'+SEVICON[s]+'</i>'+SEVLABEL[s]+'</span><span class="muted">'+sevN[s]+'</span></button>';}).join('');
var qt=null;
$('q').addEventListener('input',function(){clearTimeout(qt);var v=this.value;qt=setTimeout(function(){S.q=v.trim().toLowerCase();S.shown=200;render();},120);});
$('sevchips').addEventListener('click',function(e){var b=e.target.closest('.chip');if(!b)return;var s=b.dataset.sev;S.sev[s]=!S.sev[s];b.setAttribute('aria-pressed',S.sev[s]?'true':'false');S.shown=200;render();});
$('type').addEventListener('change',function(){S.type=this.value;S.shown=200;render();});
$('src').addEventListener('change',function(){S.src=this.value;S.shown=200;render();});
['reuse','git','perm'].forEach(function(k){$('f-'+k).addEventListener('change',function(){S[k]=this.checked;S.shown=200;render();});});
$('clear').addEventListener('click',function(){
  S.q='';S.sev={};S.type='';S.src='';S.loc='';S.reuse=S.git=S.perm=false;S.shown=200;
  $('q').value='';$('type').value='';$('src').value='';['reuse','git','perm'].forEach(function(k){$('f-'+k).checked=false;});
  Array.prototype.forEach.call(document.querySelectorAll('.chip'),function(c){c.setAttribute('aria-pressed','false');});
  render();});
$('more').addEventListener('click',function(){S.shown+=300;renderTable();});

/* ---------- charts ---------- */
var tip=$('tip');
function showTip(el,x,y){var t=el.getAttribute('data-tip');if(!t)return;tip.textContent=t;tip.style.display='block';
  var w=tip.offsetWidth,h=tip.offsetHeight;tip.style.left=Math.min(x+14,window.innerWidth-w-8)+'px';tip.style.top=Math.max(8,y-h-10)+'px';}
function hideTip(){tip.style.display='none';}
document.addEventListener('mousemove',function(e){var el=e.target.closest&&e.target.closest('[data-tip]');if(el)showTip(el,e.clientX,e.clientY);else hideTip();});
document.addEventListener('focusin',function(e){var el=e.target.closest&&e.target.closest('[data-tip]');if(el){var r=el.getBoundingClientRect();showTip(el,r.left+r.width/2,r.top);}});
document.addEventListener('focusout',hideTip);
function bars(id,rows,kind,total){
  var max=0;rows.forEach(function(r){if(r.n>max)max=r.n;});
  if(!rows.length){$(id).innerHTML='<div class="muted">Nothing to show.</div>';return;}
  $(id).innerHTML=rows.map(function(r){
    var w=(max&&r.n)?Math.max(2,Math.round(r.n/max*100)):0;
    var pct=total?(r.n/total*100).toFixed(1)+'%':'';
    var pressed=(kind==='type'&&S.type===r.key)||(kind==='loc'&&S.loc===r.key)||(kind==='sev'&&S.sev[r.key]);
    var label=kind==='sev'?'<span class="sev sev-'+r.key+'"><i>'+SEVICON[r.key]+'</i>'+SEVLABEL[r.key]+'</span>':esc(r.label);
    return '<button type="button" class="bar-row" data-kind="'+kind+'" data-key="'+esc(r.key)+'" aria-pressed="'+(pressed?'true':'false')+'" data-tip="'+esc(r.label+': '+r.n.toLocaleString()+' ('+pct+')')+'">'+
      '<span class="bar-label">'+label+'</span><span class="bar-track"><span class="bar-fill" style="width:'+w+'%;background:'+r.color+'"></span></span><span class="bar-count">'+r.n.toLocaleString()+'</span></button>';
  }).join('');
}
function top(list,keyf,n){var c={};list.forEach(function(f){var k=keyf(f);c[k]=(c[k]||0)+1;});
  var arr=Object.keys(c).map(function(k){return {key:k,label:k,n:c[k]};}).sort(function(a,b){return b.n-a.n||a.label.localeCompare(b.label);});
  if(arr.length>n){var rest=arr.slice(n).reduce(function(s,r){return s+r.n;},0);arr=arr.slice(0,n);arr.push({key:'',label:'Other ('+(Object.keys(c).length-n)+' more)',n:rest,other:true});}
  return arr;}
function renderCharts(){
  var a=filtered('sev'),c={critical:0,high:0,medium:0,low:0};a.forEach(function(f){c[f.s]++;});
  bars('c-sev',SEV.map(function(s){return {key:s,label:SEVLABEL[s],n:c[s],color:SEVCOLOR[s]};}),'sev',a.length);
  var t=top(filtered('type'),function(f){return f.t;},10).map(function(r){r.color=r.other?'var(--low)':'var(--series)';return r;});
  bars('c-type',t,'type',filtered('type').length);
  var l=top(filtered('loc'),function(f){return f.loc;},10).map(function(r){r.color=r.other?'var(--low)':'var(--series)';return r;});
  bars('c-loc',l,'loc',filtered('loc').length);
}
['c-sev','c-type','c-loc'].forEach(function(id){$(id).addEventListener('click',function(e){
  var b=e.target.closest('.bar-row');if(!b)return;var k=b.dataset.kind,v=b.dataset.key;
  if(k==='sev'){S.sev[v]=!S.sev[v];Array.prototype.forEach.call(document.querySelectorAll('.chip'),function(c){if(c.dataset.sev===v)c.setAttribute('aria-pressed',S.sev[v]?'true':'false');});}
  else if(k==='type'){if(!v)return;S.type=(S.type===v?'':v);$('type').value=S.type;}
  else if(k==='loc'){if(!v)return;S.loc=(S.loc===v?'':v);}
  S.shown=200;render();});});

/* ---------- table ---------- */
var COLS=[['s','Severity'],['t','Type'],['n','Name / key'],['m','Masked value'],['p','Full path'],['reuse','Flags'],['mt','Modified']];
function renderHead(){$('thead').innerHTML=COLS.map(function(c){var on=S.sort===c[0];return '<th scope="col" aria-sort="'+(on?(S.dir>0?'ascending':'descending'):'none')+'"><button type="button" data-k="'+c[0]+'">'+c[1]+'<span aria-hidden="true">'+(on?(S.dir>0?'▲':'▼'):'')+'</span></button></th>';}).join('');}
$('thead').addEventListener('click',function(e){var b=e.target.closest('button');if(!b)return;var k=b.dataset.k;if(S.sort===k)S.dir=-S.dir;else{S.sort=k;S.dir=1;}renderTable();});
function cmp(a,b){
  var k=S.sort,r;
  if(k==='s')r=SEVRANK[a.s]-SEVRANK[b.s]||a.p.localeCompare(b.p)||a.ln-b.ln;
  else if(k==='reuse'||k==='mt')r=(a[k]||0)-(b[k]||0);
  else r=String(a[k]||'').localeCompare(String(b[k]||''));
  return r*S.dir;}
function flags(f){var o='';
  if(f.reuse>1)o+='<span class="tag warn">reused ×'+f.reuse+'</span>';
  if(f.g==='tracked')o+='<span class="tag warn">git tracked</span>';else if(f.g==='ignored')o+='<span class="tag">git ignored</span>';else if(f.g==='untracked')o+='<span class="tag">in git repo</span>';
  if(f.perm)o+='<span class="tag warn">mode '+esc(f.md)+'</span>';
  return o;}
var rows=[];
function renderTable(){
  rows=filtered().sort(cmp);
  renderHead();
  $('count').textContent='Showing '+Math.min(rows.length,S.shown).toLocaleString()+' of '+rows.length.toLocaleString()+' matching findings ('+F.length.toLocaleString()+' total). Click a row for details.';
  if(!rows.length){$('tbody').innerHTML='<tr><td colspan="7" class="empty">'+(F.length?'No findings match these filters.':'No findings. Nothing secret-looking was found in the scanned locations.')+'</td></tr>';$('more').hidden=true;return;}
  $('tbody').innerHTML=rows.slice(0,S.shown).map(function(f){
    return '<tr class="row" tabindex="0" data-i="'+f.i+'"><td><span class="sev sev-'+f.s+'"><i>'+SEVICON[f.s]+'</i>'+SEVLABEL[f.s]+'</span></td>'+
      '<td>'+esc(f.t)+'</td><td class="mono">'+esc(f.n)+'</td><td class="mono mask">'+esc(f.m)+'</td>'+
      '<td class="path mono">'+esc(f.p)+(f.ln?'<span class="ln">:'+f.ln+'</span>':'')+'</td><td>'+flags(f)+'</td><td class="muted">'+(f.mt?esc(fmtDate(f.mt)):'')+'</td></tr>';}).join('');
  $('more').hidden=rows.length<=S.shown;$('more').textContent='Show '+Math.min(300,rows.length-S.shown)+' more';
}
function detailHtml(f){
  var others=Object.keys(fpLocs[f.f]).map(function(k){return fpLocs[f.f][k];}).filter(function(o){return o!==f;});
  var h='<dl><dt>Full path</dt><dd class="mono">'+esc(f.p)+'<button type="button" class="btn copy" data-copy="'+esc(f.p)+'">Copy path</button></dd>'+
   (f.ln?'<dt>Line</dt><dd>'+f.ln+'</dd>':'')+
   '<dt>Source</dt><dd>'+esc(f.src==='file'?'file':f.src==='env'?'environment variable of the scanning process':'environment of a running process')+'</dd>'+
   '<dt>Length</dt><dd>'+f.l+' characters</dd>'+
   '<dt>Fingerprint</dt><dd class="mono">'+esc(f.f)+' <span class="muted">(salted per scan - equal values share a fingerprint)</span></dd>'+
   (f.md?'<dt>File mode</dt><dd class="mono">'+esc(f.md)+(f.perm?' <span class="tag warn">readable by group/other</span>':'')+'</dd>':'')+
   (f.g?'<dt>Git</dt><dd>'+esc(f.g==='tracked'?'tracked - the secret is in the repository history; rotate it and purge history':f.g==='ignored'?'ignored by git':'inside a git repository, untracked')+'</dd>':'')+
   (others.length?'<dt>Also found in</dt><dd>'+others.slice(0,15).map(function(o){return '<div class="mono">'+esc(o.p)+(o.ln?':'+o.ln:'')+'</div>';}).join('')+(others.length>15?'<div class="muted">… and '+(others.length-15)+' more</div>':'')+'</dd>':'')+
   '</dl>';return h;}
$('tbody').addEventListener('click',function(e){
  var cp=e.target.closest('.copy');
  if(cp){var t=cp.getAttribute('data-copy');try{navigator.clipboard.writeText(t);}catch(x){var ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');}catch(y){}document.body.removeChild(ta);}cp.textContent='Copied';return;}
  var tr=e.target.closest('tr.row');if(!tr)return;
  var nx=tr.nextElementSibling;if(nx&&nx.classList.contains('detail')){nx.remove();return;}
  var f=F[+tr.dataset.i];tr.insertAdjacentHTML('afterend','<tr class="detail"><td colspan="7">'+detailHtml(f)+'</td></tr>');});
$('tbody').addEventListener('keydown',function(e){if((e.key==='Enter'||e.key===' ')&&e.target.classList.contains('row')){e.preventDefault();e.target.click();}});

/* ---------- files + scan details ---------- */
(function(){
  var fl=D.files||[];
  $('files-s').textContent='Credential-style files by name ('+fl.length+')';
  $('files-b').innerHTML=fl.length?fl.map(function(x){return '<tr><td class="path mono">'+esc(x.p)+'</td><td>'+esc(x.k)+'</td><td class="mono">'+esc(x.md)+(x.perm?' <span class="tag warn">group/other</span>':'')+'</td><td>'+fmtBytes(x.sz)+'</td><td class="muted">'+esc(fmtDate(x.mt))+'</td><td>'+(x.n||0)+'</td><td>'+esc(x.g||'')+'</td></tr>';}).join(''):'<tr><td colspan="7" class="empty">None found.</td></tr>';
  var st=M.stats,o=M.options;
  var h='<ul class="notes">'+D.notes.map(function(n){return '<li>'+esc(n)+'</li>';}).join('')+'</ul>';
  h+='<dl style="margin-top:12px"><dt>Roots</dt><dd class="mono">'+M.roots.map(esc).join('<br>')+'</dd>'+
     '<dt>Options</dt><dd class="mono">deep='+o.deep+' procs='+o.procs+' include_cloud='+o.include_cloud+' max_mb='+o.max_mb+'</dd>'+
     '<dt>Files seen / scanned</dt><dd>'+(st.files_seen||0).toLocaleString()+' / '+(st.files_scanned||0).toLocaleString()+' ('+fmtBytes(st.bytes_scanned||0)+')</dd>'+
     '<dt>Skipped</dt><dd>'+(st.skipped_type||0).toLocaleString()+' by type, '+(st.skipped_binary||0).toLocaleString()+' binary, '+(st.skipped_large||0).toLocaleString()+' too large, '+(st.skipped_dirs||0).toLocaleString()+' directories</dd>'+
     '<dt>Unreadable</dt><dd>'+((st.unreadable||0)+(st.unreadable_dirs||0)).toLocaleString()+(M.interrupted?' · scan was interrupted':'')+'</dd></dl>';
  if(D.skipped.length)h+='<details><summary>Skipped directories ('+D.skipped.length+(st.skipped_dirs>D.skipped.length?' shown of '+st.skipped_dirs:'')+')</summary><div class="tablewrap"><table style="min-width:600px"><tbody>'+D.skipped.map(function(s){return '<tr><td class="path mono">'+esc(s.p)+'</td><td class="muted">'+esc(s.why)+'</td></tr>';}).join('')+'</tbody></table></div></details>';
  if(D.errors.length)h+='<details><summary>Errors ('+D.errors.length+')</summary><div class="tablewrap"><table style="min-width:600px"><tbody>'+D.errors.map(function(s){return '<tr><td class="path mono">'+esc(s.p)+'</td><td class="muted">'+esc(s.e)+'</td></tr>';}).join('')+'</tbody></table></div></details>';
  $('scan').innerHTML=h;
})();

/* ---------- theme + csv ---------- */
var themes=['auto','light','dark'],ti=0;
try{var saved=localStorage.getItem('sa-theme');if(saved&&themes.indexOf(saved)>=0)ti=themes.indexOf(saved);}catch(e){}
function applyTheme(){var t=themes[ti];if(t==='auto')document.documentElement.removeAttribute('data-theme');else document.documentElement.setAttribute('data-theme',t);$('theme').textContent='Theme: '+t;try{localStorage.setItem('sa-theme',t);}catch(e){}}
$('theme').addEventListener('click',function(){ti=(ti+1)%3;applyTheme();});applyTheme();
$('csv').addEventListener('click',function(){
  function q(v){v=String(v==null?'':v);return '"'+v.replace(/"/g,'""')+'"';}
  var lines=['severity,type,name,masked_value,length,fingerprint,path,line,source,mode,git,reused_in'];
  rows.forEach(function(f){lines.push([f.s,f.t,f.n,f.m,f.l,f.f,f.p,f.ln,f.src,f.md||'',f.g||'',f.reuse].map(q).join(','));});
  var blob=new Blob([lines.join('\n')],{type:'text/csv'}),a=document.createElement('a');
  a.href=URL.createObjectURL(blob);a.download='secret-audit-masked.csv';document.body.appendChild(a);a.click();document.body.removeChild(a);});

function render(){renderCharts();renderTable();}
render();
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
