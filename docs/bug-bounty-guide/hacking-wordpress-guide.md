# Hacking WordPress

[Relative Cheat Sheet](./wordpress-cheat.md)

## Step-by-Step Guide for Testing and Exploiting WordPress Vulnerabilities

### 1. Understand WordPress Structure
   - **Explanation**: WordPress is a CMS with a core, plugins, themes, and user roles (admin, editor, subscriber). Vulnerabilities often stem from outdated components, misconfigurations, or weak authentication.
   - **Why It's Done**: Mapping the structure (e.g., directories, user roles) identifies attack surfaces like vulnerable plugins or exposed admin panels.
   - **Example**: Use `tree -L 1` to list directories like `/wp-content/plugins/`.

### 2. Enumerate WordPress Version and Components
   - **Explanation**: Check the `<meta name="generator">` tag, README files, or HTTP headers for core, plugin, and theme versions. Use `wpscan --url site -e vp,vt` for automated enumeration.
   - **Why It's Done**: Outdated versions often have known CVEs, making them prime targets.
   - **Example**: `<meta name="generator" content="WordPress 5.4.2">` indicates an old, potentially vulnerable version.

### 3. Enumerate Users
   - **Explanation**: Use `wpscan --url site -e u` or check `/author/1` or `/wp-json/wp/v2/users` to list usernames.
   - **Why It's Done**: Valid usernames enable targeted brute forcing or social engineering.
   - **Example**: Accessing `/author/admin` reveals the username `admin`.

### 4. Brute Force Login Credentials
   - **Explanation**: Use `wpscan --url site --usernames users.txt --passwords pass.txt` or Hydra to brute force `/wp-login.php` or `/xmlrpc.php`.
   - **Why It's Done**: Weak passwords or default credentials (e.g., admin:admin) grant access.
   - **Example**: `hydra -l admin -P passwords.txt http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect"`.

### 5. Exploit Vulnerable Plugins or Themes
   - **Explanation**: Search Exploit-DB or WPScan Vulnerability Database for CVEs in enumerated plugins/themes, then test exploits like SQLi or file upload.
   - **Why It's Done**: Plugins/themes are common entry points for RCE or data leaks.
   - **Example**: Exploit a file upload vuln in an outdated slider plugin to upload a shell.

### 6. Test XML-RPC Vulnerabilities
   - **Explanation**: Target `/xmlrpc.php` for methods like `wp.getUsersBlogs` or `pingback.ping`, which can enable brute forcing or DDoS.
   - **Why It's Done**: XML-RPC is often enabled and poorly secured, allowing attacks.
   - **Example**: Use Metasploit’s `wordpress_xmlrpc_login` to brute force credentials.

### 7. Gain RCE via Theme Editor
   - **Explanation**: If admin access is gained, edit theme files (Appearance > Theme Editor) to insert malicious code (e.g., `<?php system($_GET['cmd']); ?>`).
   - **Why It's Done**: Provides persistent RCE without relying on plugins.
   - **Example**: Add PHP shell to `404.php` and access `/wp-content/themes/theme/404.php?cmd=id`.

### 8. Use Metasploit for Automated Exploits
   - **Explanation**: Load Metasploit modules like `wordpress_xmlrpc_brute` or `wordpress_plugin_upload` to automate attacks.
   - **Why It's Done**: Simplifies complex exploits like multi-step RCE.
   - **Example**: `msfconsole -x "use wordpress_xmlrpc_login; set RHOSTS site; run"`.

### 9. Test Directory Indexing and Misconfigurations
   - **Explanation**: Check for directory listing (`/wp-content/uploads/`) or exposed configs (`wp-config.php`).
   - **Why It's Done**: Reveals sensitive files or database credentials.
   - **Example**: Access `/wp-content/plugins/` to find misconfigured plugins.

### 10. Assess Prevention Measures
   - **Explanation**: Check for security plugins (e.g., Wordfence), disabled XML-RPC, updated components, and strong passwords.
   - **Why It's Done**: Informs remediation, like disabling XML-RPC or enforcing updates.
   - **Example**: Secure app uses `.htaccess` to block `/xmlrpc.php` access.

This guide, based on HackTricks, OWASP, and the provided cheat sheet, equips hunters to test WordPress vulnerabilities effectively. Always test within program scope.