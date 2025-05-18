import argparse
import os
import re
import logging
import yara
import magic
import pandas as pd

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
        self.yara_rules = self.load_yara_rules()
        self.mime = magic.Magic(mime=True) #Initialize libmagic

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
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

                # Scan for suspicious strings
                for pattern in self.patterns:
                    flags = re.IGNORECASE if self.case_insensitive else 0
                    for match in re.finditer(pattern, content, flags=flags):
                        match_start = match.start()
                        match_end = match.end()

                        start_line = content.rfind('\n', 0, match_start) + 1
                        end_line = content.find('\n', match_end)
                        if end_line == -1:
                            end_line = len(content)

                        # Extract context lines
                        context_start = content.rfind('\n', 0, start_line) + 1
                        for _ in range(self.context_lines - 1): # Extract previous context lines.
                            context_start = content.rfind('\n', 0, context_start -1) + 1 # Subtract 1 because the find starts at the index
                            if context_start < 1 :
                                context_start = 0
                                break
                        
                        context_end = content.find('\n', end_line)
                        for _ in range(self.context_lines - 1): # Extract following context lines.
                            context_end = content.find('\n', context_end + 1)
                            if context_end == -1:
                                context_end = len(content)
                                break
                        
                        context = content[context_start:context_end] #Grab the context surrounding the matching line
                        match_data = {
                            'file': filepath,
                            'pattern': pattern,
                            'match': match.group(0),
                            'start': match_start,
                            'end': match_end,
                            'context': context.strip(),
                            'type': 'string' #Added type
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
                                'rule': yara_match.rule,
                                'namespace': yara_match.namespace,
                                'matches': yara_match.strings, #added the matches from YARA
                                'type': 'yara' #Added Type
                            }
                            matches.append(match_data)
                            logging.debug(f"YARA match found in {filepath}: {yara_match.rule}")
                    except yara.Error as e:
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
                    mime_type = self.mime.from_file(filepath) #check mime type to avoid binary file scan
                    if 'text' in mime_type or 'application/x-empty' in mime_type: #only scan text files and empty file
                        all_matches.extend(self.scan_file(filepath))
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
    if not os.path.exists(args.patterns_file):
        logging.error(f"Patterns file not found: {args.patterns_file}")
        return

    if not os.path.exists(args.directory):
        logging.error(f"Directory not found: {args.directory}")
        return
    
    if args.yara_rules_file and not os.path.exists(args.yara_rules_file):
         logging.error(f"YARA rules file not found: {args.yara_rules_file}")
         return

    if args.context_lines < 0:
        logging.error("Context lines must be a non-negative integer.")
        return

    locator = SuspiciousStringLocator(
        args.patterns_file,
        args.directory,
        args.recursive,
        args.case_insensitive,
        args.context_lines,
        args.yara_rules_file
    )

    matches = locator.scan_directory()
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