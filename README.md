# ths-SuspiciousStringLocator

A command-line tool that scans files in a directory for strings that match a list of suspicious patterns provided in a patterns file, with options for case-insensitive matching and recursive directory traversal. An optional YARA rules file can be scanned as well when yara-python is installed.

Patterns are regular expressions, not literal strings: each line of the patterns file is compiled as a Python regular expression. Patterns with nested quantifiers (a shape that can hang a scan through catastrophic backtracking) are refused with an error, and each file scan is also bounded by a 5 second timeout; a file that times out fails the run with a non-zero exit.

The CSV report records, for each match, the pattern identifier (pattern_N, meaning line N of the patterns file), the file, the line number and character offsets, and the SHA-256 hash of the matched string. The pattern text itself is not written to the report. Matched text and surrounding lines are never written to the report, so a matched secret does not land in clear in a report file. Findings can be located again from the file, line, and offsets recorded.

A missing patterns file, missing directory, or missing YARA file exits non-zero. An invalid pattern is reported by name and the run exits non-zero; it never reports a silent no-matches result for a scan it aborted.

python-magic and yara-python are optional: a patterns-only scan runs without either installed. python-magic, when present, is used to skip binary files; without it, all files are scanned as text.

## Install
`git clone https://github.com/ShadowGuard-AI/ths-suspiciousstringlocator`

## Usage
`python main.py -p patterns.txt -d /path/to/directory -r -o report.csv`

## Parameters
- `-h`: Show help message and exit
- `-p`: Path to the file containing suspicious patterns (regular expressions, one per line).
- `-d`: Path to the directory to scan.
- `-r`: Scan directories recursively.
- `-i`: Perform case-insensitive matching.
- `-c`: Accepted for compatibility; context lines are no longer written to the report.
- `-o`: File to write the report to.
- `-y`: Path to the YARA rules file (optional, requires yara-python).

## License
Copyright (c) ShadowStrikeHQ
