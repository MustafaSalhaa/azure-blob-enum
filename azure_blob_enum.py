#!/usr/bin/env python3
"""
Azure Blob Storage Enumerator
Author  : Mustafa Salha
Purpose : Enumerate Azure Blob Storage containers during authorized security assessments
License : MIT
"""

import sys
import time
import argparse
import datetime
import re
import fnmatch
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import ConnectionError, Timeout, RequestException

requests.packages.urllib3.disable_warnings()

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"

# -------------------------------------------------
#  COLORS
# -------------------------------------------------
class C:
    RED    = "\033[91m"
    ORANGE = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# -------------------------------------------------
#  BANNER
# -------------------------------------------------
def print_banner():
    print(f"""{C.CYAN}{C.BOLD}
+----------------------------------------------------------------+
|         AZURE BLOB STORAGE ENUMERATOR - RED TEAM TOOL         |
|              Public Container & Blob Discovery                 |
+----------------------------------------------------------------+{C.RESET}
    Author  : Mustafa Salha
    Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Warning : For authorized engagements only
""")

# -------------------------------------------------
#  WORDLISTS
# -------------------------------------------------
ACCOUNT_SUFFIXES = [
    "", "storage", "store", "data", "backup", "bak", "dev", "prod",
    "staging", "test", "uat", "assets", "media", "files", "docs",
    "documents", "images", "img", "uploads", "archive", "logs",
    "reports", "dump", "db", "database", "config", "configs",
    "secrets", "keys", "certs", "web", "app", "api", "cdn",
    "static", "public", "private", "internal", "admin", "portal",
    "client", "customers", "users", "temp", "tmp", "cache",
    "export", "import", "share", "shared", "infra", "platform",
    "core", "main", "primary", "global", "common",
]

CONTAINER_NAMES = [
    "$web", "public", "private", "data", "backup", "backups", "bak",
    "dev", "prod", "staging", "test", "uat", "assets", "media",
    "files", "docs", "documents", "images", "img", "pictures",
    "photos", "thumbnails", "uploads", "upload", "downloads",
    "archive", "archives", "logs", "log", "reports", "dump",
    "dumps", "db", "database", "config", "configs", "secrets",
    "keys", "certs", "certificates", "web", "app", "api", "cdn",
    "static", "content", "admin", "portal", "internal", "external",
    "clients", "customers", "users", "temp", "tmp", "cache",
    "exports", "imports", "shared", "raw", "processed", "finance",
    "legal", "hr", "engineering", "source", "src", "artifacts",
    "builds", "releases", "deploy", "terraform", "ansible",
    "kubernetes", "k8s", "monitoring", "analytics",
    "$logs", "azure-webjobs-hosts", "azure-webjobs-secrets",
    "insights-logs", "insights-metrics", "boot-diagnostics",
    "networkwatcher", "flowlogs",
]

SENSITIVE_PATTERNS = [
    ".env", ".env.*", "*.env", "config.json", "appsettings*.json",
    "web.config", "app.config", "credentials*", "secrets*",
    "key.json", "serviceaccount.json", "terraform.tfstate*",
    "terraform.tfvars", "*.pem", "*.key", "*.pfx", "*.p12",
    "*.jks", "id_rsa", "id_ed25519", "id_ecdsa", "dump.sql",
    "backup.sql", "database.sql", "*.sql", "*.bak", "*.dump",
    "passwords*", "password*", "*.sqlite", "*.sqlite3",
    "kubeconfig", ".kube/config", "docker-compose.yml",
    "ansible.cfg", "inventory", "*.tfstate", "*.tfvars",
    "firebase*.json", "gcp*.json", "google-credentials*",
    "aws-credentials*", ".aws/credentials", "stripe*.txt",
    "github-token*", "gitlab-token*",
]

# -------------------------------------------------
#  CHECK IF STORAGE ACCOUNT EXISTS
#  Non-existent accounts fail DNS resolution (ConnectionError)
#  Existing accounts return 400 (bad request - expected without params)
#  Public accounts return 200 or 403
# -------------------------------------------------
def check_account_exists(account_name, timeout=5):
    url = f"https://{account_name}.blob.core.windows.net"
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": UA})
        # Any HTTP response means the account exists
        return True, r.status_code
    except ConnectionError:
        # DNS resolution failure = account does not exist
        return False, 0
    except Timeout:
        return False, -1
    except RequestException:
        return False, -2

# -------------------------------------------------
#  CHECK CONTAINER ACCESS
# -------------------------------------------------
def check_container(account_name, container, timeout=5):
    url = f"https://{account_name}.blob.core.windows.net/{container}?restype=container&comp=list"
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": UA})

        if r.status_code == 200:
            blobs = parse_blob_list(r.text)
            return "PUBLIC", blobs

        elif r.status_code == 403:
            body = r.text
            if "PublicAccessNotPermitted" in body:
                return "PRIVATE", []
            elif "AuthenticationRequired" in body:
                return "AUTH_REQUIRED", []
            return "FORBIDDEN", []

        elif r.status_code == 404:
            return "NOT_FOUND", []

        elif r.status_code == 400:
            # Container may exist but listing not permitted
            return "EXISTS_NO_LIST", []

        return "UNKNOWN", []

    except (ConnectionError, Timeout, RequestException):
        return "ERROR", []

# -------------------------------------------------
#  PARSE BLOB NAMES FROM AZURE XML RESPONSE
# -------------------------------------------------
def parse_blob_list(xml_text):
    return re.findall(r"<Name>(.*?)</Name>", xml_text, re.IGNORECASE)

# -------------------------------------------------
#  FLAG SENSITIVE FILES
#  Checks both full path and filename only
# -------------------------------------------------
def flag_sensitive(blobs):
    flagged = []
    for blob in blobs:
        filename = blob.split("/")[-1]
        for pattern in SENSITIVE_PATTERNS:
            if (fnmatch.fnmatch(blob.lower(), pattern.lower()) or
                    fnmatch.fnmatch(filename.lower(), pattern.lower())):
                flagged.append(blob)
                break
    return flagged

# -------------------------------------------------
#  CHECK WRITE ACCESS ON OPEN CONTAINER
# -------------------------------------------------
def check_write_access(account_name, container, timeout=5):
    test_blob = f"pentest-write-check-{int(time.time())}.txt"
    url = f"https://{account_name}.blob.core.windows.net/{container}/{test_blob}"
    try:
        r = requests.put(
            url,
            data=b"pentest-write-check-delete-me",
            headers={
                "x-ms-blob-type": "BlockBlob",
                "Content-Type": "text/plain",
                "User-Agent": UA,
            },
            timeout=timeout,
            verify=False,
        )
        if r.status_code in [200, 201]:
            # Clean up immediately
            requests.delete(url, timeout=timeout, verify=False,
                            headers={"User-Agent": UA})
            return True
        return False
    except (ConnectionError, Timeout, RequestException):
        return False

# -------------------------------------------------
#  ENUMERATE A SINGLE ACCOUNT
# -------------------------------------------------
def enumerate_account(account_name, containers, check_write, timeout, verbose):
    results = {
        "account": account_name,
        "exists": False,
        "public_containers": [],
        "private_containers": [],
        "writable_containers": [],
        "total_blobs": 0,
        "sensitive_files": [],
    }

    exists, status = check_account_exists(account_name, timeout)
    if not exists:
        if verbose:
            print(f"  {C.DIM}[-] {account_name:<40} does not exist{C.RESET}")
        return results

    results["exists"] = True
    print(f"\n  {C.GREEN}[+] FOUND{C.RESET} {C.BOLD}{account_name}.blob.core.windows.net{C.RESET}  (HTTP {status})")

    for container in containers:
        access, blobs = check_container(account_name, container, timeout)

        if access == "PUBLIC":
            sensitive = flag_sensitive(blobs)
            results["public_containers"].append({
                "name": container,
                "blobs": blobs,
                "sensitive": sensitive,
            })
            results["total_blobs"] += len(blobs)
            results["sensitive_files"].extend(sensitive)

            print(f"    {C.RED}{C.BOLD}[OPEN]{C.RESET}     /{container} - {len(blobs)} blob(s) listed")

            if sensitive:
                for sf in sensitive:
                    print(f"      {C.RED}[!] SENSITIVE: {sf}{C.RESET}")

            if check_write:
                writable = check_write_access(account_name, container, timeout)
                if writable:
                    results["writable_containers"].append(container)
                    print(f"      {C.RED}{C.BOLD}[WRITABLE] Accepts unauthenticated writes - CRITICAL{C.RESET}")

        elif access in ["AUTH_REQUIRED", "FORBIDDEN", "EXISTS_NO_LIST"]:
            results["private_containers"].append(container)
            if verbose:
                print(f"    {C.ORANGE}[PRIVATE]{C.RESET}  /{container} - exists, access denied ({access})")

        elif access == "NOT_FOUND":
            if verbose:
                print(f"    {C.DIM}[-]{C.RESET}        /{container} - not found")

        elif access == "ERROR":
            if verbose:
                print(f"    {C.DIM}[ERR]{C.RESET}       /{container} - request error")

    return results

# -------------------------------------------------
#  GENERATE ACCOUNT NAME VARIATIONS FROM KEYWORD
# -------------------------------------------------
def generate_account_names(keywords):
    names = set()
    for keyword in keywords:
        # Normalize: lowercase, strip non-alphanumeric except hyphens
        kw = re.sub(r"[^a-z0-9]", "", keyword.lower())
        names.add(kw)
        for suffix in ACCOUNT_SUFFIXES:
            if suffix:
                names.add(f"{kw}{suffix}")
                names.add(f"{kw}-{suffix}")
                names.add(f"{suffix}{kw}")
    # Azure rules: 3-24 chars, lowercase letters and numbers only (hyphens allowed)
    valid = [n for n in names if 3 <= len(n) <= 24 and re.match(r"^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$", n)]
    return sorted(set(valid))

# -------------------------------------------------
#  EXPORT RESULTS TO FILE
# -------------------------------------------------
def export_results(all_results, output_file):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    found = [r for r in all_results if r["exists"]]

    with open(output_file, "w") as f:
        f.write("Azure Blob Storage Enumeration Results\n")
        f.write(f"Generated : {timestamp}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Accounts Found    : {len(found)}\n")
        f.write(f"Public Containers : {sum(len(r['public_containers']) for r in found)}\n")
        f.write(f"Sensitive Files   : {sum(len(r['sensitive_files']) for r in found)}\n\n")

        for r in found:
            f.write(f"Account : {r['account']}.blob.core.windows.net\n")
            for c in r["public_containers"]:
                f.write(f"  [OPEN] /{c['name']} - {len(c['blobs'])} blob(s)\n")
                for blob in c["blobs"]:
                    f.write(f"    https://{r['account']}.blob.core.windows.net/{c['name']}/{blob}\n")
                if c["sensitive"]:
                    f.write(f"  [!] Sensitive: {', '.join(c['sensitive'])}\n")
            for c in r["writable_containers"]:
                f.write(f"  [WRITABLE] /{c} - unauthenticated write confirmed\n")
            f.write("\n")

    print(f"\n  {C.GREEN}[+] Results saved to {output_file}{C.RESET}")

# -------------------------------------------------
#  PRINT SUMMARY
# -------------------------------------------------
def print_summary(all_results):
    found           = [r for r in all_results if r["exists"]]
    total_public    = sum(len(r["public_containers"]) for r in found)
    total_writable  = sum(len(r["writable_containers"]) for r in found)
    total_blobs     = sum(r["total_blobs"] for r in found)
    total_sensitive = sum(len(r["sensitive_files"]) for r in found)

    print(f"""
{C.BOLD}{C.CYAN}
+--------------------------------------+
|             SCAN SUMMARY             |
+--------------------------------------+
{C.RESET}
  Accounts Found        : {len(found)}
  {C.RED}Open Containers       : {total_public}{C.RESET}
  {C.RED}Writable Containers   : {total_writable}{C.RESET}
  {C.ORANGE}Total Blobs Listed    : {total_blobs}{C.RESET}
  {C.RED}Sensitive Files Found : {total_sensitive}{C.RESET}
""")

    public_results = [r for r in found if r["public_containers"]]
    if public_results:
        print(f"  {C.RED}{C.BOLD}[!] PUBLIC CONTAINERS:{C.RESET}")
        for r in public_results:
            for c in r["public_containers"]:
                url = f"https://{r['account']}.blob.core.windows.net/{c['name']}"
                print(f"      {url}  ({len(c['blobs'])} blobs)")

    writable_results = [r for r in found if r["writable_containers"]]
    if writable_results:
        print(f"\n  {C.RED}{C.BOLD}[!!] WRITABLE CONTAINERS (CRITICAL):{C.RESET}")
        for r in writable_results:
            for c in r["writable_containers"]:
                print(f"      https://{r['account']}.blob.core.windows.net/{c}")

# -------------------------------------------------
#  ARGUMENT PARSER
# -------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Azure Blob Storage Enumerator - Find public and misconfigured containers",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 azure_blob_enum.py -k companyname
  python3 azure_blob_enum.py -k acme corp acmecorp
  python3 azure_blob_enum.py -a storageaccountname
  python3 azure_blob_enum.py -f accounts.txt
  python3 azure_blob_enum.py -k target --containers wordlists/containers.txt
  python3 azure_blob_enum.py -k target --write-check
  python3 azure_blob_enum.py -k target -o results.txt -v
"""
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-k", "--keywords",  nargs="+", metavar="KEYWORD",
                       help="Target keywords - auto-generates account name variations")
    group.add_argument("-a", "--accounts",  nargs="+", metavar="ACCOUNT",
                       help="Known storage account names to target directly")
    group.add_argument("-f", "--file",      metavar="FILE",
                       help="File with storage account names (one per line)")

    parser.add_argument("--containers",  metavar="FILE",
                        help="Custom container wordlist (default: built-in list)")
    parser.add_argument("--write-check", action="store_true",
                        help="Test unauthenticated write access on open containers")
    parser.add_argument("-o", "--output",   metavar="FILE", default="",
                        help="Save results to file")
    parser.add_argument("-t", "--threads",  type=int, default=20,
                        help="Thread count (default: 20)")
    parser.add_argument("--timeout",        type=int, default=5,
                        help="Request timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose",  action="store_true",
                        help="Show all results including not-found containers")

    return parser.parse_args()

# -------------------------------------------------
#  MAIN
# -------------------------------------------------
def main():
    print_banner()
    args = parse_args()

    # Load account names
    if args.keywords:
        accounts = generate_account_names(args.keywords)
        print(f"  {C.CYAN}[*] Generated {len(accounts)} account name variations from {len(args.keywords)} keyword(s){C.RESET}")
    elif args.accounts:
        accounts = [a.lower().strip() for a in args.accounts]
        print(f"  {C.CYAN}[*] Targeting {len(accounts)} account(s) directly{C.RESET}")
    else:
        try:
            with open(args.file) as f:
                accounts = [l.strip().lower() for l in f
                            if l.strip() and not l.startswith("#")]
            print(f"  {C.CYAN}[*] Loaded {len(accounts)} account(s) from {args.file}{C.RESET}")
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {args.file}{C.RESET}")
            sys.exit(1)

    # Load container list
    if args.containers:
        try:
            with open(args.containers) as f:
                containers = [l.strip() for l in f
                              if l.strip() and not l.startswith("#")]
            print(f"  {C.CYAN}[*] Loaded {len(containers)} container names from {args.containers}{C.RESET}")
        except FileNotFoundError:
            print(f"{C.RED}[!] Container wordlist not found: {args.containers}{C.RESET}")
            sys.exit(1)
    else:
        containers = CONTAINER_NAMES
        print(f"  {C.CYAN}[*] Using built-in container wordlist ({len(containers)} names){C.RESET}")

    if args.write_check:
        print(f"  {C.ORANGE}[*] Write-check enabled{C.RESET}")

    print(f"  {C.CYAN}[*] Threads: {args.threads} | Timeout: {args.timeout}s{C.RESET}")
    print(f"\n  {'─' * 70}")

    # Run enumeration
    all_results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                enumerate_account,
                account,
                containers,
                args.write_check,
                args.timeout,
                args.verbose,
            ): account for account in accounts
        }
        for future in as_completed(futures):
            all_results.append(future.result())

    print_summary(all_results)

    # Export
    if args.output:
        export_results(all_results, args.output)
    elif any(r["public_containers"] for r in all_results):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        export_results(all_results, f"azure_enum_{ts}.txt")

if __name__ == "__main__":
    main()
