<div align="center">

# 🛡️ UnpackGuard

**Extract archives as if somebody is attacking you — a zero-dependency, offline-first archive auditing and policy-driven extraction engine**

[简体中文](./README.md) | [繁體中文](./README.zh-TW.md) | [English](#english)

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./pyproject.toml)
[![Offline](https://img.shields.io/badge/network-none-lightgrey.svg)](#design--roadmap)

</div>

---

## 🎉 Introduction

Somebody sends you an archive. It came from a user upload, a CI artifact, an email attachment, or a fresh repository you have not audited yet. The moment you double-click it, it may be writing a reverse shell into `../../`.

In modern pipelines, "download → extract → run" is one of the most underestimated attack surfaces out there. Zip-Slip traversal, compression bombs, NTFS alternate data streams, executables hiding behind benign extensions, Trojan-Source bidi characters — most extractors default to "do exactly what the archive says" and faithfully replay all of it onto your disk.

**UnpackGuard** is the guard rail for that pipeline. It is not another unzipper — it is an engine that **audits first, extracts second**:

* 🧭 **See everything, without unpacking** — enumerate every member: name, size, compression ratio, mode, timestamp, nesting depth.
* 🚦 **Grade the risk** — 26 built-in rules with CVSS-flavoured severities and a **0–100 safety score**.
* 🧱 **Contain by default** — every dangerous shape has a policy switch, and the defaults never leak outside the destination.
* 🔌 **Plug into CI** — `--json` for scripts, `--sarif` for GitHub code scanning, `--fail-level` for exit codes.
* 📦 **Zero dependencies** — standard library only, nothing leaves your machine.

### 灵感来源与差异化 (Where it differs)

Excellent tools already exist (WinRAR, 7-Zip, `unzip`, and the recent HatchZip), but they mostly answer *"how do I unpack this?"* — HatchZip in particular solves the disk-space problem with in-place extraction. Their default posture is to trust whatever path the archive author wrote.

UnpackGuard answers the other half: *"does this archive deserve my trust, and can unpacking it hurt me?"*

| | Traditional extractors | UnpackGuard |
| --- | --- | --- |
| `../` members | concatenated literally | rejected, or rewritten under a sandboxed root |
| Compression bombs | fill the disk, then fail | ratio and total budget checked up front, streaming abort mid-write |
| Symbolic links | recreated as-is | refused by default; escaping targets flagged critical |
| NTFS ADS / reserved device names | handed to the filesystem | stripped or sanitised before touching disk |
| GBK/Big5 mojibake names | garbage output | codec heuristics restore the readable name |
| Machine-readable output | none | JSON + SARIF 2.1.0 + CI exit codes |
| Dependencies | varied | **zero — pure stdlib** |

> UnpackGuard borrows only the general problem space of archive extraction; every line of code here is written from scratch.✅ No third-party source is copied.

---

## ✨ Features

- 🔍 **26 rules (`UPG001`–`UPG026`)**: traversal, absolute paths, drive letters / UNC, NTFS ADS, symlink escapes, compression bombs, sensitive targets (`.git`, `.ssh`, private keys), setuid bits, double-extension masquerading, invisible bidi control characters, and more.
- 🧮 **0–100 score with A–F grades**. Per-rule scoring is capped so a single noisy rule can never drown out everything else.
- 🧯 **Policy-driven extraction**: `--flat`, `--strip N`, `--encoding`, `--allow-links`, `--no-perms`, `--reject-absolute`, `--reject-traversal`. Safe defaults everywhere.
- 📐 **Capacity planning**: `plan` estimates real disk usage with 4 KiB block alignment plus a worst-case figure and free-space check.
- 🧬 **Nested archive detection** by magic bytes (ZIP/7z/RAR/tar inside tar/zip), with a configurable depth budget.
- 🈶 **Mojibake repair**: GB18030 / Big5 / Shift-JIS / CP437 scoring heuristics turn `╓╨╬─…txt` back into its real name.
- 🔐 **Streaming with a brake**: byte counters are checked while writing, so `--max-total-size` aborts before the disk fills up.
- 🧾 **Three renderers**: text, JSON, and SARIF 2.1.0.
- 🚦 **CI-friendly**: `--fail-level critical|high|medium|low|none`.
- 🧪 **Zero deps, 114 unit tests** written against stdlib `unittest` (no pytest required).

---

## 🚀 Quick start

### Requirements

- Python **3.9+**
- Nothing else. Linux / macOS / Windows.

### Install

```bash
# 1. From PyPI (recommended)
pip install unpackguard

# 2. From source (editable, for hacking on it)
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
pip install -e .

# 3. No install at all — run the package straight from the checkout
python -m unpackguard --help
```

### The five commands you need

```bash
unpackguard sniff download.bin          # what is this really? (magic bytes, not extension)
unpackguard inspect download.zip        # list members, write nothing
unpackguard scan download.zip           # safety audit (the default command)
unpackguard plan huge.tar.gz --dest ./out   # will it fit on disk?
unpackguard extract download.zip --dest ./out --max-total-size 1GiB
```

---

## 📖 Usage guide

| Command | Purpose | Typical use |
| --- | --- | --- |
| `sniff` | identify the real format from magic bytes | the extension lies |
| `inspect` | enumerate member metadata | read the manifest before committing |
| `scan` | safety audit (default) | CI gates, human review |
| `plan` | size / free-space budget | protecting a nearly full disk |
| `extract` | write members out under policy | the actual unpack |

Running `unpackguard <file>` with no subcommand is exactly `unpackguard scan <file>`.

### 1. Read the report

```console
$ unpackguard scan sample.zip
UnpackGuard scan: sample.zip
  format    ZIP archive
  members   19 (19 files)
  expands   262 B

  score     0/100  grade 🔴 F  worst=critical
  findings  🚨 1  🔴 5  🟡 10  🔵 6  ℹ️ 0

Findings
  🚨 CRITICAL
    UPG001 [a/b/../../escape.txt]
      'a/b/../../escape.txt' contains a '..' component
      remedy: drop it with --reject-traversal, or confirm you trust the source
```

### 2. CI gate

```bash
# fail (exit 2) on high or above — the default
unpackguard scan artifact.zip --fail-level high

# only care about the worst stuff
unpackguard scan artifact.zip --fail-level critical --quiet

# never fail the build, let another system decide
unpackguard scan artifact.zip --fail-level none --json > report.json
```

### 3. SARIF for GitHub code scanning

```bash
unpackguard scan artifact.zip --sarif > unpackguard.sarif
```

```yaml
- name: UnpackGuard audit
  run: unpackguard scan artifact.zip --sarif > unpackguard.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: unpackguard.sarif
```

### 4. Repairing legacy filenames

Legacy archives frequently leave the UTF-8 flag unset, so the names come out scrambled. UnpackGuard scores candidate codecs and fixes them automatically:

```console
$ unpackguard inspect legacy.zip
NAME                     TYPE   SIZE     PACKED   NOTE
中文合同.txt              file   8 B      -        gb18030
報告-2026.pdf            file   8 B      -        big5
plain.txt                file   8 B      -        -
```

You can always force the codec: `unpackguard inspect legacy.zip --encoding gbk`.

### 5. Useful combinations

```bash
# flatten everything into one directory, de-duplicating collisions
unpackguard extract drop.zip --dest ./out --flat

# drop the top-level directory (like tar --strip-components=1)
unpackguard extract release.tar.gz --dest ./out --strip 1

# allow links — only for sources you fully trust
unpackguard extract trusted.tar --dest ./out --allow-links

# strict mode: refuse to rewrite, just refuse
unpackguard extract hostile.zip --dest ./out --reject-absolute --reject-traversal

# resource limits
unpackguard extract drop.zip --dest ./out --max-total-size 100MiB --max-files 5000

# see what would be written without writing anything
unpackguard extract drop.zip --dest ./out --dry-run
```

### 6. Library usage

```python
from unpackguard.extract import ExtractConfig, extract_archive
from unpackguard.reader import open_archive
from unpackguard.rules import ScanConfig, scan_archive
from unpackguard.safety import PathPolicy
from unpackguard.sniff import sniff_file

fmt = sniff_file("upload.zip")
archive = open_archive("upload.zip", fmt)

result = scan_archive(archive, ScanConfig(max_ratio=100), PathPolicy())
print(result.score, result.grade, result.worst)
for finding in result.findings:
    print(f"{finding.rule} {finding.severity} {finding.member}: {finding.detail}")

if result.score >= 90:
    outcome = extract_archive(archive, "./out", PathPolicy(),
                              ExtractConfig(max_total_bytes=512 * 1024 * 1024))
    print(outcome.written, outcome.skipped, outcome.aborted)
```

### 7. Exit codes

| Code | Meaning |
| --- | --- |
| `0` | nothing reached `--fail-level` (or `plan` says there is room) |
| `1` | runtime/usage error (including `plan` running out of space) |
| `2` | findings reached `--fail-level` |
| `3` | the archive could not be parsed |

### 8. Rule catalogue

| Rule | Meaning | Severity |
| --- | --- | --- |
| `UPG001` | `..` parent traversal in member path (Zip-Slip) | critical |
| `UPG002` | POSIX absolute path (`/etc/cron.d/...`) | high |
| `UPG003` | Windows drive letter / UNC prefix | high |
| `UPG004` | NTFS alternate data stream | high |
| `UPG005` | symbolic or hard link member | high |
| `UPG006` | link target points outside the destination | critical |
| `UPG007` | reserved Windows device name (NUL / CON / COM1…) | medium |
| `UPG008` | control characters in the name | high |
| `UPG009` | still resolves outside after normalisation | critical |
| `UPG010` | member compression ratio above the threshold (bomb signature) | high |
| `UPG011` | cumulative size / member count over budget | high |
| `UPG012` | nesting deeper than the configured depth | medium |
| `UPG013` | executable or script payload | medium |
| `UPG014` | writes into a sensitive directory (`.git`, `.ssh`, `.aws`…) | high |
| `UPG015` | legacy (non-UTF-8) filename encoding | low |
| `UPG016` | duplicate member names | medium |
| `UPG017` | collision on case-insensitive filesystems | medium |
| `UPG018` | setuid / setgid permission bit | high |
| `UPG019` | world-writable entry | low |
| `UPG020` | encrypted member (contents cannot be audited) | medium |
| `UPG021` | implausible timestamp | low |
| `UPG022` | special file (FIFO / character or block device) | medium |
| `UPG023` | credential-looking filename (`id_rsa`, `.env`, …) | medium |
| `UPG024` | bidi / zero-width / homoglyph characters in the name | high |
| `UPG025` | double extension masquerade (`invoice.pdf.exe`) | medium |
| `UPG026` | trailing dot or space (truncated on Windows) | low |

Machine-readable form: `unpackguard scan --list-rules --json`.

---

## 💡 Design & roadmap

### Principles

1. **Conservative by default.** Anything that could land outside the destination is either rewritten into it or rejected. Loosening always requires an explicit flag.
2. **Reading never writes.** `sniff`, `inspect`, `scan` and `plan` touch nothing on disk, so they are safe to run on hostile input.
3. **Verdict and execution are separate layers.** `safety` decides *whether* a path may be written, `extract` decides *how*; `rules` only observe.
4. **Minimal trust surface.** Standard library only, so the supply-chain surface is effectively zero and it runs in slim containers and air-gapped boxes.
5. **Machines first.** Every result serialises to JSON / SARIF so it slots into existing pipelines.

### Why Python instead of Rust/Go?

The primary home for this tool is CI pipelines and developer laptops, where "pip install and it works" beats binary distribution. Pure Python is also far easier for a security team to audit line by line.

### Roadmap

- [x] ZIP / TAR family auditing + extraction with policy control
- [x] JSON + SARIF renderers and CI-friendly exit codes
- [ ] `--recursive` unpacking of nested archives folded into one score
- [ ] Read-only 7z / RAR parsing without external binaries
- [ ] CVE / CWE mapping fields for compliance reports
- [ ] CycloneDX / SPDX manifest output
- [ ] Interactive TUI for per-member allow/deny decisions
- [ ] YARA-style custom rule files

Ideas welcome in [Issues](https://github.com/gitstq/UnpackGuard/issues) or straight as a PR.

---

## 📦 Build & deploy

Per the project conventions this is a **library / CLI project**, so it ships via PyPI rather than per-platform Release binaries.

### Local development

```bash
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
python -m unittest discover -s tests -t .   # zero-dependency test run
python -m unpackguard --help                # run without installing
```

### Packaging

```bash
pip install build
python -m build          # dist/unpackguard-<ver>-py3-none-any.whl + .tar.gz
```

### Isolated install

```bash
python -m venv .venv && source .venv/bin/activate
pip install dist/unpackguard-1.0.0-py3-none-any.whl
```

### Container

```dockerfile
FROM python:3.12-alpine
COPY dist/unpackguard-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/unpackguard-*.whl
ENTRYPOINT ["unpackguard"]
```

### Compatibility

| Platform | Status | Notes |
| --- | --- | --- |
| Linux | ✅ | fully supported |
| macOS | ✅ | add `--case-insensitive-fs` on APFS/HFS+ volumes |
| Windows | ✅ | reserved设备名 and illegal characters are sanitised automatically |

---

## 🤝 Contributing

Contributions are welcome. Commit messages follow the Angular convention:

```
feat: add rule UPG027 for XYZ
fix: handle边缘 case with control chars
docs: clarify the plan subcommand
refactor: split rules into lazy modules
test: cover ZIP64 relocation
```

**Pull requests**

1. Fork and branch: `git checkout -b feat/my-feature`
2. Keep `python -m unittest discover -s tests -t .` green
3. New behaviour ships with tests
4. Describe the motivation and how you verified it in the PR body

**Issue reports** are most useful with OS, Python version, the exact command, and a minimal reproducer archive (or the script that generates it).

---

## 📄 License

Released under the [MIT License](./LICENSE). Use it, modify it, ship it commercially — just keep the copyright notice. Provided "as is", without warranty of any kind.
