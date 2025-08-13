# Login Brute Forcing

[Relative Cheat Sheet](./brute-forcing-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Login Brute Forcing Vulnerabilities

### 1. Understand Brute Forcing in Authentication Contexts
   - **Explanation**: Brute forcing involves systematically guessing credentials, tokens, or PINs to bypass authentication, exploiting weak passwords, predictable tokens, or absent rate limits. It can target logins, password resets, or "remember me" features.
   - **Why It's Done**: Understanding the attack surface (e.g., login forms, reset tokens) helps identify weak points where brute forcing is feasible.
   - **Example**: A login form with no CAPTCHA or lockout allows unlimited password guesses.

### 2. Identify Target Authentication Points
   - **Explanation**: Locate login forms, password reset endpoints, 2FA fields, or "remember me" cookies using Burp Suite or browser DevTools.
   - **Why It's Done**: These are the entry points for brute force attacks; missing them limits testing scope.
   - **Example**: A login page at `/login` or a reset token field at `/reset?token=abc`.

### 3. Analyze "Remember Me" for Predictability
   - **Explanation**: Decode "remember me" cookies to check for predictable patterns (e.g., username+timestamp or weak hashes).
   - **Why It's Done**: Predictable cookies can be forged, bypassing login entirely.
   - **Example**: Cookie `remember=base64(username:timestamp)` can be recreated for another user.

### 4. Enumerate Valid Usernames
   - **Explanation**: Test usernames with invalid passwords to detect response differences (e.g., timing, error messages) that confirm valid users.
   - **Why It's Done**: Valid usernames focus brute force efforts, increasing efficiency.
   - **Example**: `/login?user=admin&pass=wrong` returns "Invalid password" vs "User not found" for invalid users.

### 5. Brute Force Passwords or Tokens
   - **Explanation**: Use tools like Hydra (`hydra -l user -P pass.txt http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"`) or Medusa to try password lists or token combinations.
   - **Why It's Done**: Weak passwords or tokens allow unauthorized access.
   - **Example**: Brute force `/login` with common passwords like `password123`.

### 6. Use Custom Wordlists
   - **Explanation**: Generate targeted wordlists with tools like `username-anarchy` for usernames or `cupp` for passwords based on target info.
   - **Why It's Done**: Personalized lists increase success rates over generic ones.
   - **Example**: `cupp -i` to create passwords based on user’s name or interests.

### 7. Bypass Rate Limits or CAPTCHAs
   - **Explanation**: Rotate IPs (via proxies) to evade rate limits, or check for CAPTCHA solutions in HTML or weak validation (e.g., reusable tokens).
   - **Why It's Done**: Bypassing protections allows unlimited attempts.
   - **Example**: Use `X-Forwarded-For: 1.2.3.4` to spoof IP in Burp.

### 8. Test Credential Stuffing or Spraying
   - **Explanation**: Try leaked credentials from breaches (credential stuffing) or common passwords across multiple accounts (spraying).
   - **Why It's Done**: Exploits password reuse or weak defaults.
   - **Example**: Test `admin:admin` across multiple accounts.

### 9. Exploit Successful Guesses
   - **Explanation**: Use valid credentials or tokens to access the application, escalate privileges, or extract data.
   - **Why It's Done**: Demonstrates impact, like account takeover or sensitive data access.
   - **Example**: Use guessed password to log in as admin and access `/admin`.

### 10. Assess Prevention Measures
   - **Explanation**: Check for rate limiting, lockouts, strong password policies, or 2FA.
   - **Why It's Done**: Informs remediation, like enforcing CAPTCHAs or minimum password complexity.
   - **Example**: Secure apps lock accounts after 5 failed attempts.

This guide, based on PortSwigger Web Security Academy and the provided cheat sheet, equips hunters to test brute forcing vulnerabilities ethically. Always respect program scope.