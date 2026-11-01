import argparse
import hashlib
import os
import re
import signal
import logging
import sys
import pandas as pd

# yara and python-magic are optional and are imported lazily, only when
# the feature that needs them is requested, so a patterns-only scan runs
# without either binding installed.

SCAN_TIMEOUT_SECONDS = 5

CATASTROPHIC_SHAPE = re.compile(r"\([^)]*[+*][^)]*\)\s*(?:\+|\*|\{)")


class ScanTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise ScanTimeout("scan timed out")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SuspiciousStringLocator:
    """
    A tool to scan files and directories for suspicious strings and patterns.
    """

    def __init__(self, patterns_file, directory, recursive, case_insensitive, context_lines, yara_rules_file):
        """
        Initializes the SuspiciousStringLocator object.

        Args:
            patterns_file (str): Path to the file containing suspicious patterns.
            directory (str): Path to the directory to scan.
            recursive (bool): Whether to scan directories recursively.
            case_insensitive (bool): Whether to perform case-insensitive matching.
            context_lines (int): Number of context lines to report around matches.
            yara_rules_file (str): Path to the YARA rules file.
        """

        self.patterns_file = patterns_file
        self.directory = directory
        self.recursive = recursive
        self.case_insensitive = case_insensitive
        self.context_lines = context_lines
        self.yara_rules_file = yara_rules_file
        self.patterns = self.load_patterns()
        self.compiled_patterns = []
        self.pattern_error = None
        self.timed_out_files = []
        self.files_scanned = 0
        for pattern in self.patterns:
            if CATASTROPHIC_SHAPE.search(pattern):
                self.pattern_error = (
                    f"Pattern refused (nested quantifiers can hang the scan): {pattern}")
                break
            try:
                flags = re.IGNORECASE if self.case_insensitive else 0
                label = f"pattern_{len(self.compiled_patterns) + 1}"
                self.compiled_patterns.append((label, re.compile(pattern, flags)))
            except re.error as e:
                self.pattern_error = f"Invalid pattern {pattern!r}: {e}"
                break
        self.yara_rules = self.load_yara_rules()
        self.mime = None
        try:
            import magic
            self.mime = magic.Magic(mime=True)
        except ImportError:
            logging.warning("python-magic not available: scanning all files as text.")

    def load_patterns(self):
        """
        Loads suspicious patterns from the patterns file.

        Returns:
            list: A list of suspicious patterns.  Returns an empty list on error.
        """
        try:
            with open(self.patterns_file, 'r') as f:
                patterns = [line.strip() for line in f if line.strip()] # Remove empty lines
            logging.info(f"Loaded {len(patterns)} patterns from {self.patterns_file}")
            return patterns
        except FileNotFoundError:
            logging.error(f"Patterns file not found: {self.patterns_file}")
            return [] # Return empty list on error
        except Exception as e:
            logging.error(f"Error reading patterns file: {e}")
            return [] # Return empty list on error

    def load_yara_rules(self):
        """
        Loads YARA rules from the specified file.

        Returns:
            yara.Rules: Compiled YARA rules, or None if an error occurred.
        """
        if self.yara_rules_file:
            try:
                import yara
            except ImportError:
                logging.error("YARA rules were requested but yara-python is not installed.")
                raise SystemExit(1)
            try:
                rules = yara.compile(filepath=self.yara_rules_file)
                logging.info(f"Successfully loaded YARA rules from {self.yara_rules_file}")
                return rules
            except yara.Error as e:
                logging.error(f"Error compiling YARA rules: {e}")
                return None
            except FileNotFoundError:
                logging.error(f"YARA rules file not found: {self.yara_rules_file}")
                return None
            except Exception as e:
                logging.error(f"An unexpected error occurred while loading YARA rules: {e}")
                return None
        else:
            logging.info("No YARA rules file specified.")
            return None
        

    def scan_file(self, filepath):
        """
        Scans a single file for suspicious patterns and YARA rules.

        Args:
            filepath (str): Path to the file to scan.

        Returns:
            list: A list of dictionaries, where each dictionary represents a match
                  and contains information about the match. Returns an empty list if no matches found, or an error occurred.
        """
        matches = []

        try:
            # Decoding with errors ignored means the offsets in my match records
            # count decoded characters, not file bytes, and YARA below is fed the
            # decoded text rather than the bytes on disk. A pattern spanning a
            # dropped byte sequence can never match.
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Scan for suspicious strings. Only a hash of each
                # matched string is recorded: matched text and the
                # surrounding lines are never written to the report.
                for pattern, compiled in self.compiled_patterns:
                    for match in compiled.finditer(content):
                        match_start = match.start()
                        match_end = match.end()
                        line_number = content.count("\n", 0, match_start) + 1
                        match_data = {
                            'file': filepath,
                            'pattern': pattern,
                            'line': line_number,
                            'start': match_start,
                            'end': match_end,
                            'match_sha256': hashlib.sha256(match.group(0).encode("utf-8", "ignore")).hexdigest(),
                            'type': 'string'
                        }
                        matches.append(match_data)
                        logging.debug(f"String Match found in {filepath}: {pattern}")

                # Scan with YARA rules
                if self.yara_rules:
                    try:
                        yara_matches = self.yara_rules.match(data=content)
                        for yara_match in yara_matches:
                            match_data = {
                                'file': filepath,
                                'pattern': yara_match.rule,
                                'line': '',
                                'start': '',
                                'end': '',
                                'match_sha256': hashlib.sha256(repr(yara_match.strings).encode("utf-8", "ignore")).hexdigest(),
                                'type': 'yara'
                            }
                            matches.append(match_data)
                            logging.debug(f"YARA match found in {filepath}: {yara_match.rule}")
                    except Exception as e:
                        logging.error(f"YARA error during file scan: {filepath} - {e}")

            return matches

        except FileNotFoundError:
            logging.error(f"File not found: {filepath}")
            return [] # Return empty list on error
        except Exception as e:
            logging.error(f"Error reading file: {filepath} - {e}")
            return [] # Return empty list on error


    def scan_directory(self):
        """
        Scans a directory for suspicious patterns.

        Returns:
            list: A list of dictionaries, where each dictionary represents a match
                  and contains information about the match.
        """
        all_matches = []
        try:
            for root, _, files in os.walk(self.directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    mime_type = self.mime.from_file(filepath) if self.mime is not None else "text/plain" 
                    # This mime gate skips more than binaries: JSON, scripts served as
                    # application types, and anything libmagic names without the word
                    # text are never opened. The skip is logged at debug level only, so
                    # a default run gives no sign whole file classes were passed over.
                    if 'text' in mime_type or 'application/x-empty' in mime_type: #only scan text files and empty file
                        self.files_scanned += 1
                        try:
                            if hasattr(signal, "SIGALRM"):
                                old_handler = signal.signal(signal.SIGALRM, _alarm_handler)
                                signal.setitimer(signal.ITIMER_REAL, SCAN_TIMEOUT_SECONDS)
                            try:
                                all_matches.extend(self.scan_file(filepath))
                            finally:
                                if hasattr(signal, "SIGALRM"):
                                    signal.setitimer(signal.ITIMER_REAL, 0)
                                    signal.signal(signal.SIGALRM, old_handler)
                        except ScanTimeout:
                            logging.error(f"Scan of {filepath} exceeded {SCAN_TIMEOUT_SECONDS}s and was stopped.")
                            self.timed_out_files.append(filepath)
                    else:
                        logging.debug(f"Skipping binary file {filepath} (MIME Type: {mime_type})") #Log skipped binary files
                if not self.recursive:
                    break
            return all_matches
        except Exception as e:
            logging.error(f"Error during directory scan: {e}")
            return []

    def generate_report(self, matches, output_file):
        """
        Generates a report from the matches.

        Args:
            matches (list): A list of match dictionaries.
            output_file (str): The file to write the report to.
        """

        try:
            df = pd.DataFrame(matches)
            if not df.empty:
                df.to_csv(output_file, index=False)
                logging.info(f"Report generated successfully: {output_file}")
            else:
                # No report file is written, which leaves a report.csv from an
                # earlier run in place under the default output name. Anyone reading
                # that file afterwards is reading a previous scan.
                logging.info("No matches found. Report not generated.")
        except Exception as e:
            logging.error(f"Error generating report: {e}")



def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Scan files or directories for suspicious strings and patterns.')
    parser.add_argument('-p', '--patterns', dest='patterns_file', required=True,
                        help='Path to the file containing suspicious patterns.')
    parser.add_argument('-d', '--directory', dest='directory', required=True,
                        help='Path to the directory to scan.')
    parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                        help='Scan directories recursively.')
    parser.add_argument('-i', '--case-insensitive', dest='case_insensitive', action='store_true',
                        help='Perform case-insensitive matching.')
    parser.add_argument('-c', '--context', dest='context_lines', type=int, default=3,
                        help='Number of context lines to report around matches.')
    parser.add_argument('-o', '--output', dest='output_file', default='report.csv',
                        help='File to write the report to.')
    parser.add_argument('-y', '--yara', dest='yara_rules_file',
                        help='Path to the YARA rules file (optional).')
    return parser

def main():
    """
    Main function to execute the suspicious string locator tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    # These validation failures return from main with no exit code, so
    # the process ends 0. A missing patterns file and a completed scan
    # are indistinguishable to anything watching the exit status.
    if not os.path.exists(args.patterns_file):
        logging.error(f"Patterns file not found: {args.patterns_file}")
        sys.exit(1)

    if not os.path.exists(args.directory):
        logging.error(f"Directory not found: {args.directory}")
        sys.exit(1)

    if args.yara_rules_file and not os.path.exists(args.yara_rules_file):
         logging.error(f"YARA rules file not found: {args.yara_rules_file}")
         sys.exit(1)

    if args.context_lines < 0:
        logging.error("Context lines must be a non-negative integer.")
        sys.exit(1)

    locator = SuspiciousStringLocator(
        args.patterns_file,
        args.directory,
        args.recursive,
        args.case_insensitive,
        args.context_lines,
        args.yara_rules_file
    )

    if locator.pattern_error:
        logging.error(locator.pattern_error)
        sys.exit(1)

    matches = locator.scan_directory()
    if locator.timed_out_files:
        logging.error(f"Scan did not complete for {len(locator.timed_out_files)} file(s) (timeout).")
        sys.exit(1)
    if locator.files_scanned == 0:
        logging.error("No files were scanned. No verdict was produced.")
        sys.exit(1)
    locator.generate_report(matches, args.output_file)


if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Scan a directory for suspicious strings using a patterns file, recursively, and generate a report:
#    python ths-SuspiciousStringLocator.py -p patterns.txt -d /path/to/directory -r -o output.csv
#
# 2. Scan a directory for suspicious strings case-insensitively:
#    python ths-SuspiciousStringLocator.py -p patterns.txt -d /path/to/directory -i -o output.csv
#
# 3. Scan a directory and include 5 lines of context around each match:
#    python ths-SuspiciousStringLocator.py -p patterns.txt -d /path/to/directory -c 5 -o output.csv
#
# 4. Scan a directory using YARA rules and suspicious string patterns:
#    python ths-SuspiciousStringLocator.py -p patterns.txt -d /path/to/directory -y yara_rules.yar -o output.csv
#
# 5.  Non-recursive Scan of current directory
#    python ths-SuspiciousStringLocator.py -p patterns.txt -d . -o output.csv