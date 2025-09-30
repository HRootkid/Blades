import re
import os
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

console = Console()

# --- Regular Expressions for Sensitive Data ---
# These are examples, you'll want to expand and refine them.
# Use raw strings (r"...") for regex patterns to avoid issues with backslashes.

SENSITIVE_PATTERNS = {
    "API Key": [
        r"(?i)(?:api_key|secret_key|access_token|auth_token|bearer_token|private_key|client_secret)[\s\"']*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,64})['\"]?",
        r"sk-[a-zA-Z0-9]{32,64}",  # Common OpenAI API key pattern
        r"AKIA[0-9A-Z]{16}",      # AWS Access Key ID
        r"arn:aws:iam::\d{12}:access-key/[A-Za-z0-9+/=]{40}", # AWS ARN for access key
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", # Slack Bot User OAuth Access Token
        r"[sS]ecret(?:[Kk]ey)?\s*=\s*['\"]?[a-zA-Z0-9!@#$%^&*()_+-=]{20,64}['\"]?"
    ],
    "Password/Credential": [
        r"(?i)(?:password|passwd|pwd|passphrase|secret|credential|token)[\s\"']*[=:]\s*['\"]?([a-zA-Z0-9!@#$%^&*()_+-=,./?<>~;:]+?)['\"]?",
        r"jdbc:.*:\/\/.*user=([a-zA-Z0-9_-]+);password=([a-zA-Z0-9!@#$%^&*()_+-=,./?<>~;:]+)", # Database connection strings
        r"ftp:\/\/[a-zA-Z0-9_-]+:([a-zA-Z0-9!@#$%^&*()_+-=,./?<>~;:]+)@", # FTP credentials
        r"sshpass -p\s*['\"]?([a-zA-Z0-9!@#$%^&*()_+-=,./?<>~;:]+)['\"]?" # sshpass
    ],
    "SQL Query": [
        r"(?i)(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|ALTER TABLE|DROP TABLE|GRANT|REVOKE|TRUNCATE TABLE)\s+[a-zA-Z0-9_.,\s*`\"'-]+(?:FROM|INTO|SET|WHERE|VALUES|JOIN|ON|GROUP BY|ORDER BY|HAVING|LIMIT|OFFSET)\s+[a-zA-Z0-9_.,\s*`\"'-]+",
        r"(?i)EXEC\s+(sp_executesql|xp_cmdshell|sp_send_dbmail)", # Common SQL Server stored procedures
        r"(?i)(['\"]?UNION\s+SELECT\s+.*--)" # Basic SQL Injection pattern
    ],
    "IP Address": [
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IPv4
        r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", # IPv6 (full form)
        r"\b(?:[A-F0-9]{1,4}:){1,7}:[A-F0-9]{1,4}\b", # IPv6 (shortened form)
    ],
    "System Internal Path (Windows)": [
        r"(?i)(C:\\(?:Windows|Program Files|Program Files \(x86\)|Users|Documents and Settings)\\[^\\\/:*?\"<>|\r\n]*)+",
        r"(?i)(%APPDATA%|%LOCALAPPDATA%|%TEMP%|%USERPROFILE%)",
        r"(?i)C:\\Users\\[a-zA-Z0-9_.-]+\\AppData\\(?:Roaming|Local|LocalLow)\\"
    ],
    "System Internal Path (Linux/Unix)": [
        r"(/etc/(?:passwd|shadow|fstab|hosts)|/var/(?:log|www)|/home/[a-zA-Z0-9_.-]+|/root|/usr/local/bin|/opt/[^/\s]+)",
        r"/proc/\d+/(?:cmdline|environ|status)", # Linux procfs sensitive paths
        r"~/(?:.ssh|.)", # Home directory sensitive files
    ],
    "Email Address": [
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    ]
}

def extract_strings_from_binary(filepath, min_len=4):
    """
    Extracts printable strings from a binary file.
    Similar to the 'strings' utility.
    """
    with open(filepath, 'rb') as f:
        # Read the entire file as bytes
        binary_data = f.read()

    # Use regex to find sequences of printable ASCII characters
    # \x20-\x7E covers standard printable ASCII
    # + to match one or more characters
    # {min_len,} to ensure a minimum length
    # This might miss Unicode strings, for which more complex decoding would be needed.
    # For now, focusing on common ASCII strings which contain most sensitive data.
    strings = re.findall(rb'[ -~]{%d,}' % min_len, binary_data)
    
    decoded_strings = []
    for s in strings:
        try:
            decoded_strings.append(s.decode('utf-8'))
        except UnicodeDecodeError:
            try:
                decoded_strings.append(s.decode('latin-1'))
            except UnicodeDecodeError:
                # Fallback or ignore if decoding fails
                pass
    return decoded_strings

def scan_file(filepath):
    """
    Scans a given file for sensitive information using defined regex patterns.
    Handles both text and binary files.
    """
    sensitive_findings = {}

    try:
        # Attempt to read as text first
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        # If text reading fails (e.g., truly binary file), extract strings
        console.print(f"[yellow]Attempting to extract strings from binary file: {filepath}[/yellow]")
        extracted_strings = extract_strings_from_binary(filepath)
        content = "\n".join(extracted_strings) # Join extracted strings for scanning

    # Iterate through each category of sensitive patterns
    for category, patterns in SENSITIVE_PATTERNS.items():
        findings_in_category = []
        for pattern in patterns:
            # Use re.DOTALL to allow '.' to match newlines
            matches = re.finditer(pattern, content)
            for match in matches:
                found_string = match.group(0) # The entire matched string
                # Optionally, if your regex uses capture groups for the sensitive part
                # e.g., r"key=(\w+)" then match.group(1) would give just the key.
                # For simplicity, we're taking the whole match for now.

                # Basic de-duplication and context addition
                if found_string not in [f['value'] for f in findings_in_category]:
                    # Find line number (approximate for binary files)
                    line_number = content.count('\n', 0, match.start()) + 1
                    findings_in_category.append({
                        "value": found_string,
                        "line": line_number
                    })
        if findings_in_category:
            sensitive_findings[category] = findings_in_category
            
    return sensitive_findings

def main():
    parser = argparse.ArgumentParser(
        description="Scan files for sensitive information (keys, SQL, IPs, paths)."
    )
    parser.add_argument(
        "path",
        help="Path to the file or directory to scan."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Display all details of findings."
    )
    parser.add_argument(
        "-e", "--exclude",
        nargs="+",
        help="File or directory names to exclude from scanning (e.g., .git, .vscode, node_modules)."
    )

    args = parser.parse_args()

    target_path = args.path
    exclude_items = set(args.exclude) if args.exclude else set()

    console.print(Panel(f"[bold blue]Starting Sensitive Data Scan for: {target_path}[/bold blue]", border_style="blue"))
    console.print(f"[cyan]Excluding: {', '.join(exclude_items) if exclude_items else 'None'}[/cyan]\n")

    if os.path.isfile(target_path):
        console.print(f"[bold green]Scanning file: {target_path}[/bold green]")
        results = scan_file(target_path)
        if results:
            console.print(f"\n[bold red]--- Sensitive Data Found in {target_path} ---[/bold red]")
            display_results(results, args.verbose)
        else:
            console.print(f"[green]No sensitive data found in {target_path}.[/green]")
    elif os.path.isdir(target_path):
        console.print(f"[bold green]Scanning directory: {target_path}[/bold green]")
        for root, dirs, files in os.walk(target_path):
            # Modify dirs in-place to prune directories
            dirs[:] = [d for d in dirs if d not in exclude_items]

            for file in files:
                if file in exclude_items:
                    continue
                
                filepath = os.path.join(root, file)
                console.print(f"[bright_black]Scanning: {filepath}[/bright_black]")
                
                results = scan_file(filepath)
                if results:
                    console.print(f"\n[bold red]--- Sensitive Data Found in {filepath} ---[/bold red]")
                    display_results(results, args.verbose)
                # else:
                    # console.print(f"[green]No sensitive data found in {filepath}.[/green]") # Too noisy for directory scan

    else:
        console.print(f"[red]Error: Path not found or not a valid file/directory: {target_path}[/red]")

def display_results(results, verbose):
    """
    Displays the scan results in a formatted way.
    """
    for category, findings in results.items():
        console.print(Panel(f"[bold yellow]{category}[/bold yellow]", border_style="yellow"))
        for finding in findings:
            value = finding['value']
            line = finding['line'] if 'line' in finding else 'N/A'
            if verbose:
                rprint(f"  [magenta]Line {line}:[/magenta] [white]'{value}'[/white]")
            else:
                # Truncate for non-verbose output to keep it concise
                truncated_value = (value[:80] + '...') if len(value) > 80 else value
                rprint(f"  [magenta]Found:[/magenta] [white]'{truncated_value}'[/white]")
        console.print("") # Add a newline for spacing

if __name__ == "__main__":
    main()