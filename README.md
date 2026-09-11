# Azure Blob Storage Enumerator

A Python tool for discovering publicly accessible Azure Blob Storage containers and misconfigured storage accounts during authorized cloud security assessments. Built for pentesters and red teamers who need fast, reliable Azure storage recon without relying on heavy frameworks.

---

## What It Does

Azure Blob Storage misconfigurations are one of the most common findings in cloud engagements. Companies often spin up storage accounts with public containers - exposing backups, config files, credentials, and internal documents to anyone who knows where to look.

This tool automates that discovery:

- Generates storage account name variations from a company keyword (e.g. `acme` becomes `acmestorage`, `acmebackup`, `acmeprod`, and 50+ more)
- Checks which accounts actually exist
- Enumerates common container names against each found account
- Lists all blobs inside open (public) containers
- Flags sensitive files like `.env`, `terraform.tfstate`, `*.pem`, `dump.sql`, and more
- Optionally tests write access on open containers
- Exports full results with direct URLs to every blob found

---

## Who Should Use This

- **Pentesters** - cloud recon during external assessments and assumed-breach scenarios
- **Red teamers** - passive reconnaissance against a target's Azure footprint
- **Bug bounty hunters** - quick check for exposed storage on in-scope domains
- **Cloud security engineers** - audit your own organization's storage accounts before someone else does

---

## Installation

```bash
git clone https://github.com/MustafaSalhaa/azure-blob-enum.git
cd azure-blob-enum
pip3 install -r requirements.txt
```

**Requirements:** Python 3.7+ and `requests`. Nothing else.

```
requests
urllib3
```

---

## Usage

**Enumerate by keyword - generates name variations automatically:**
```bash
python3 azure_blob_enum.py -k companyname
```

**Multiple keywords:**
```bash
python3 azure_blob_enum.py -k acme corp acmecorp
```

**Target a known account name directly:**
```bash
python3 azure_blob_enum.py -a storageaccountname
```

**Load account names from a file:**
```bash
python3 azure_blob_enum.py -f accounts.txt
```

**Use a custom container wordlist:**
```bash
python3 azure_blob_enum.py -k target --containers mylist.txt
```

**Check write access on open containers:**
```bash
python3 azure_blob_enum.py -k target --write-check
```

**Save results to file:**
```bash
python3 azure_blob_enum.py -k target -o results.txt
```

**Full options:**
```bash
python3 azure_blob_enum.py -k target --write-check -t 30 --timeout 8 -v -o results.txt
```

---

## Options

| Flag | Description |
|------|-------------|
| `-k`, `--keywords` | Target keywords - generates account name variations |
| `-a`, `--accounts` | Known storage account names to target directly |
| `-f`, `--file` | File with account names (one per line) |
| `--containers` | Custom container wordlist file |
| `--write-check` | Test unauthenticated write access on open containers |
| `-o`, `--output` | Save results to a file |
| `-t`, `--threads` | Number of threads (default: 20) |
| `--timeout` | Request timeout in seconds (default: 5) |
| `-v`, `--verbose` | Show all results including not-found containers |

---

## Output Example

```
+----------------------------------------------------------------+
|         AZURE BLOB STORAGE ENUMERATOR - RED TEAM TOOL         |
|              Public Container & Blob Discovery                 |
+----------------------------------------------------------------+
    Started : 2026-09-10 09:15:42

  [*] Generated 54 account name variations from 1 keyword(s)
  [*] Using built-in container wordlist (60 names)
  [*] Threads: 20 | Timeout: 5s

  [+] FOUND  acmebackup.blob.core.windows.net
    [OPEN]    /backup - 14 blobs listed
      [!] SENSITIVE: database_prod_2025.sql
      [!] SENSITIVE: .env
    [PRIVATE]  /config - exists but access denied

  [+] FOUND  acmestorage.blob.core.windows.net
    [OPEN]    /public - 3 blobs listed
    [OPEN]    /assets - 41 blobs listed

+--------------------------------------+
|             SCAN SUMMARY             |
+--------------------------------------+

  Accounts Found        : 2
  Open Containers       : 3
  Writable Containers   : 0
  Total Blobs Listed    : 58
  Sensitive Files Found : 2

  [!] PUBLIC CONTAINERS:
      https://acmebackup.blob.core.windows.net/backup  (14 blobs)
      https://acmestorage.blob.core.windows.net/public  (3 blobs)
      https://acmestorage.blob.core.windows.net/assets  (41 blobs)

  [+] Results saved to azure_enum_20260910_091600.txt
```

---

## What Gets Flagged as Sensitive

The tool checks every blob name against a list of patterns that commonly indicate high-value or dangerous files:

- Environment files - `.env`, `appsettings.json`, `web.config`
- Infrastructure state - `terraform.tfstate`
- Credentials and keys - `*.pem`, `*.key`, `*.pfx`, `id_rsa`, `serviceaccount.json`
- Database dumps - `dump.sql`, `backup.sql`, `*.bak`
- Secret stores - `secrets.json`, `credentials`, `passwords.txt`

---

## Account Name Generation

When you pass a keyword, the tool generates variations based on real naming patterns seen across Azure environments:

```
acme
acmestorage
acmestore
acmedata
acmebackup
acmeprod
acmestaging
acmedev
acmeassets
acmemedia
... and 40+ more
```

All names are validated against Azure's naming rules (3-24 chars, lowercase alphanumeric) before being tested.

---

## Write Check

When `--write-check` is enabled, the tool attempts to upload a small test blob to each open container to confirm if anonymous writes are allowed. If successful, it immediately deletes the test blob and flags the container as writable - a critical finding in any engagement.

This is one of the most impactful misconfigurations in Azure: open read access is bad, open write access can lead to supply chain attacks, data poisoning, and backdoor injection depending on what the storage is used for.

---

## Accounts File Format

Plain text, one account name per line. Lines starting with `#` are ignored.

```
# Known accounts from recon
acmecorpstorage
acmeproddata
acmebackup01
```

---

## Legal Notice

This tool is for authorized security assessments only. Only use it against Azure storage accounts you own or have explicit written permission to test. Unauthorized access to cloud storage is illegal under computer fraud laws in most jurisdictions.

---

## Author

**Mustafa Salha**  
Penetration Tester | Abu Dhabi, UAE  
GitHub: [MustafaSalhaa](https://github.com/MustafaSalhaa)

---

## Wordlists

Three wordlists are included in the `wordlists/` folder. You can use them directly with this tool or drop them into any other blob enumeration tool you use.

---

### wordlists/containers.txt

**620+ container names** covering every realistic naming pattern seen in real Azure environments.

Categories covered:

- Generic and common names (`public`, `private`, `data`, `files`, `assets`)
- Backup and archive names (`backup`, `bak`, `snapshot`, `archive`, `cold-storage`)
- Database related (`db`, `dump`, `sql-dump`, `database-backup`, `raw-data`)
- Environment names (`dev`, `prod`, `staging`, `uat`, `sandbox`, `canary`)
- Log and audit names (`logs`, `audit-logs`, `access-log`, `security-log`, `telemetry`)
- Config and secrets (`config`, `secrets`, `credentials`, `tokens`, `vault`, `ssh-keys`)
- DevOps and infrastructure (`terraform`, `k8s`, `helm`, `ansible`, `dockerfile`, `ci`, `cd`)
- Business and departments (`finance`, `hr`, `legal`, `payroll`, `contracts`, `crm`)
- Client and customer data (`clients`, `pii`, `kyc`, `personal-data`, `gdpr`)
- Media and content (`videos`, `recordings`, `transcripts`, `pdfs`)
- Azure-specific containers (`$web`, `azure-webjobs-hosts`, `insights-logs`, `boot-diagnostics`)
- Numbered and dated variants (`backup-2024`, `archive-2025`, `v1`, `v2`, `legacy`)

```bash
python3 azure_blob_enum.py -k target --containers wordlists/containers.txt
```

---

### wordlists/sensitive_blobs.txt

**370+ sensitive file and blob names** to look for inside open containers. These are the files that actually matter when you find an open bucket.

Categories covered:

- Environment and config files (`.env`, `appsettings.json`, `web.config`, `docker-compose.yml`)
- Credentials and secrets (`credentials.json`, `secrets.yaml`, `passwords.txt`, `tokens.json`)
- SSH and cryptographic keys (`id_rsa`, `*.pem`, `*.key`, `*.pfx`, `server.crt`, `ca.key`)
- Database dumps (`dump.sql`, `backup.sql`, `pg_dump.sql`, `database.db`, `backup.tar.gz`)
- Infrastructure state (`terraform.tfstate`, `terraform.tfvars`, `kubeconfig`, `ansible.cfg`)
- Source code archives (`.git/config`, `source.zip`, `repo.zip`, `backup-source.zip`)
- PII and personal data (`users.csv`, `customers.json`, `kyc.csv`, `ssn.csv`, `passport.csv`)
- Financial data (`invoices.csv`, `payroll.xlsx`, `transactions.json`, `credit-card-data.csv`)
- Cloud provider credentials (`.aws/credentials`, `gcloud.json`, `firebase-adminsdk.json`, `stripe-keys.txt`)
- Log files (`access.log`, `auth.log`, `payment.log`, `security.log`)

This list is useful for manually checking open containers or automating a second-pass scan after discovery.

---

### wordlists/storage_accounts.txt

A list of **generic storage account names** not tied to any specific company. Useful when you want to fuzz for accounts that follow common naming conventions without a keyword - or as a reference for suffix patterns to apply manually.

---

### Using the wordlists with other tools

These wordlists work with any tool that accepts a wordlist input:

```bash
# With ffuf
ffuf -u https://FUZZ.blob.core.windows.net -w wordlists/storage_accounts.txt

# Manual curl check
while read name; do
  curl -s -o /dev/null -w "%{http_code} $name\n" https://$name.blob.core.windows.net
done < wordlists/storage_accounts.txt

# With gobuster (container enumeration on a known account)
gobuster dir -u https://TARGET.blob.core.windows.net -w wordlists/containers.txt
```
