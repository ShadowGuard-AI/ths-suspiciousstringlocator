# ths-SuspiciousStringLocator
A command-line tool that scans files or directories for strings that match a list of suspicious patterns (e.g., encoded commands, common exploit strings) provided in a configuration file. Includes options for case-insensitive matching, recursive directory traversal, and reporting context around matches. - Focused on Provides a framework and utilities for writing rapid threat hunting scripts. Enables analysts to quickly search through logs, files, and process memory for indicators of compromise (IOCs) using YARA rules and statistical analysis.  Facilitates iterative threat hunting workflows.

## Install
`git clone https://github.com/ShadowStrikeHQ/ths-suspiciousstringlocator`

## Usage
`./ths-suspiciousstringlocator [params]`

## Parameters
- `-h`: Show help message and exit
- `-p`: Path to the file containing suspicious patterns.
- `-d`: Path to the directory to scan.
- `-r`: Scan directories recursively.
- `-i`: Perform case-insensitive matching.
- `-c`: Number of context lines to report around matches.
- `-o`: File to write the report to.
- `-y`: No description provided

## License
Copyright (c) ShadowStrikeHQ
