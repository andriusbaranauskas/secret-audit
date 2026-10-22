# secret-audit

Local scanner that finds tokens, secrets and passwords visible on your machine and writes a single-page HTML dashboard. Values are masked and file paths are shown in full. **macOS only** (it scans macOS locations such as `~/Library` and iCloud Drive, and uses `sandbox-exec`). Python 3.8+ (Pipfile pins 3.12), standard library only.

## Usage

```sh
python3 secret-audit.py                  # scan $HOME, write ~/secret-audit-report.html
python3 secret-audit.py --open           # ...and open the report in the browser
python3 secret-audit.py --root DIR       # scan DIR instead of $HOME (repeatable)
python3 secret-audit.py --deep           # also scan most of ~/Library (slower, noisier)
python3 secret-audit.py --procs          # also read environments of running processes
python3 secret-audit.py --include-cloud  # also scan OneDrive / Google Drive / iCloud folders
```

Other options: `--out PATH` (report location), `--max-mb N` (skip larger files, default 10), `--no-git` (don't ask git whether files are tracked).

## What it checks

- Environment variables of the scanning process (and of other processes with `--procs`)
- Readable text files: dotfiles, `.env`, shell history, cloud/CLI configs, SSH keys, JSON/YAML/INI/plist, notes, code, logs
- File permissions and whether git tracks the file

It does not touch the macOS Keychain, browser password stores or binary databases.

## Safety

- **No network.** `socket` is disabled at start-up, the report has a CSP that blocks all requests, and no HTTP code is imported. Only local `git` and `ps` are run.
- **No full secrets stored.** Values are masked in memory as soon as they are found (e.g. `ghp_••••••••abc`). Only the masked form, length and a salted fingerprint (to spot reuse) are kept, and the finished report is re-scanned for leaks.
- Report is written with mode `600`. Delete it when done.

For an OS-level guarantee:

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' python3 secret-audit.py
```

(Not compatible with `--procs`, since the sandbox blocks `ps`.)
