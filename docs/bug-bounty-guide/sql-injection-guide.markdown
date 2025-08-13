# SQL Injection

[Relative Cheat Sheet](./sqli-cheat.md)  
[Relative Cheat Sheet](./sqlmap-cheat.md)

## Step-by-Step Guide for Testing and Exploiting SQL Injection Vulnerabilities

### 1. Understand SQL Injection and Its Types
   - **Explanation**: SQL injection (SQLi) occurs when user input is concatenated into SQL queries without sanitization, allowing attackers to alter query logic. Types include union-based (retrieve data via UNION), blind (no direct output, use boolean/time-based), second-order (stored input used later), and error-based (trigger errors for info).
   - **Why It's Done**: Knowing types helps choose testing methods; union for data dump, blind for hidden vulns. This step prevents blind testing.
   - **Example**: Query `SELECT * FROM products WHERE category = 'Gifts'` becomes `SELECT * FROM products WHERE category = 'Gifts' OR 1=1--'` to return all products.

### 2. Identify Entry Points for Injection
   - **Explanation**: Scan for inputs feeding SQL queries, like search fields, logins, or filters. Use proxies like Burp to map params.
   - **Why It's Done**: SQLi needs an injection point; identifying them focuses testing on high-risk areas.
   - **Example**: URL param `?id=1` in `SELECT * FROM users WHERE id = '1'`.

### 3. Test for Vulnerability with Basic Payloads
   - **Explanation**: Inject `'` to break query and observe errors or behavior changes. Use `--` or `#` to comment out rest.
   - **Why It's Done**: Triggers syntax errors if vulnerable, confirming unsanitized input.
   - **Example**: `id=1'` causes error like "Syntax error near ''".

### 4. Determine Database Type and Columns
   - **Explanation**: Use database-specific payloads (e.g., `@@version` for MySQL) and `ORDER BY n--` to find column count.
   - **Why It's Done**: Tailors payloads; column count needed for union attacks.
   - **Example**: `ORDER BY 3--` works, `ORDER BY 4--` errors, so 3 columns.

### 5. Exploit Union-Based SQLi
   - **Explanation**: Append `UNION SELECT NULL,NULL--` (match columns), then extract data like `UNION SELECT username,password FROM users--`.
   - **Why It's Done**: Dumps data directly in response for quick exploitation.
   - **Example**: `id=-1' UNION SELECT table_name,NULL FROM information_schema.tables--` to list tables.

### 6. Test and Exploit Blind SQLi
   - **Explanation**: Use boolean (`AND 1=1` vs `AND 1=2`) for response differences, time delays (`SLEEP(5)`), or OAST for exfil.
   - **Why It's Done**: When no data in response, blind methods infer info bit-by-bit.
   - **Example**: `id=1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a`—check response change.

### 7. Enumerate Database Structure
   - **Explanation**: Query schema tables (e.g., `information_schema.tables` for MySQL) to list databases, tables, columns.
   - **Why It's Done**: Maps DB for targeted data extraction.
   - **Example**: `UNION SELECT table_name,NULL FROM information_schema.tables--`.

### 8. Extract Sensitive Data
   - **Explanation**: Dump users, passwords, or files (LOAD_FILE for MySQL).
   - **Why It's Done**: Core exploitation goal; leads to account takeover or escalation.
   - **Example**: `UNION SELECT LOAD_FILE('/etc/passwd'),NULL--` for file read.

### 9. Use SQLMap for Automation
   - **Explanation**: Scan with `sqlmap -u URL --batch`, enumerate (`--tables`, `--dump`), exploit (`--os-shell` for RCE).
   - **Why It's Done**: Automates tedious manual steps, handles blind/ complex cases.
   - **Example**: `sqlmap -u "http://example/vuln.php?id=1" --dump -T users`.

### 10. Escalate to RCE or Other Impacts
   - **Explanation**: Use OUTFILE to write files (`SELECT 'shell' INTO OUTFILE '/var/www/shell.php'`), or chain with other vulns.
   - **Why It's Done**: Beyond data leak, achieve shell access.
   - **Example**: Write PHP shell for web access.

### 11. Assess Prevention Measures
   - **Explanation**: Check for prepared statements or parametrization to block injection.
   - **Why It's Done**: Recommends fixes like using PDO in reports.
   - **Example**: Vulnerable if concatenation used; secure if bound params.

This guide, based on PortSwigger Web Security Academy, equips hunters to find and exploit SQLi ethically. Always scope and report responsibly.