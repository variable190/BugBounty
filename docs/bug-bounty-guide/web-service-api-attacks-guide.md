# Web Service & API Attacks

## Overview
Web service and API attacks target vulnerabilities in application programming interfaces (APIs), which are critical for modern web applications using REST, SOAP, or XML-RPC protocols. These attacks exploit weaknesses in authentication, input validation, and data handling, potentially leading to data breaches, remote code execution (RCE), or unauthorized access. APIs are often exposed to external users, making them a prime target in bug bounty hunting.

## Common Vulnerabilities
- **Injection Attacks**: SQL injection or command injection in API parameters can manipulate backend queries or execute system commands. For example, an API endpoint `/api/users?id=1` might allow `id=1' OR '1'='1` to bypass authentication.
- **Authentication Bypass**: Weak or missing authentication (e.g., no API key, predictable tokens) allows unauthorized access to sensitive endpoints.
- **Server-Side Request Forgery (SSRF)**: APIs accepting URLs (e.g., `/api/fetch?url=http://target`) can be tricked into accessing internal resources like `http://localhost:8080/admin`.
- **XML External Entity (XXE)**: SOAP or XML-based APIs processing unvalidated XML can read files or perform SSRF via entities like `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.

## XMLRPC (e.g., WordPress)
- **Description**: XML-RPC, commonly enabled in WordPress via `/xmlrpc.php`, allows remote procedure calls. It’s often misconfigured, enabling brute force attacks, information leaks, or denial-of-service (DoS) via pingback methods.
- **Examples**: Brute forcing credentials with `wp.getUsersBlogs` or flooding with `pingback.ping` requests.
- **Mitigation**: Disable XML-RPC unless required, restrict methods with `.htaccess`, or use authentication plugins.

## Rate Limiting and Business Logic Flaws
- **Rate Limiting**: APIs without rate limits are susceptible to brute force or DoS. Check for headers like `X-Rate-Limit-Limit`.
- **Business Logic Flaws**: Misconfigured workflows (e.g., bypassing payment verification) can be exploited if inputs aren’t validated.

## Prevention Strategies
- **Strong Authentication**: Implement OAuth 2.0, API keys, or JWT with signature validation to secure access.
- **Input Validation**: Sanitize and validate all API inputs to prevent injection or SSRF.
- **Disable External Entities**: Configure XML parsers to reject external entities (XXE) and restrict URL schemes.
- **Rate Limiting**: Enforce API quotas (e.g., 100 requests/hour) and monitor usage.
- **Secure Coding**: Follow OWASP API Security Top 10 guidelines to avoid logic flaws.

## Tools and Resources
- **Postman** ([https://www.postman.com/](https://www.postman.com/)): Test API endpoints and payloads.
- **Burp Suite** ([https://portswigger.net/burp](https://portswigger.net/burp)): Intercept and manipulate API requests.
- **OWASP API Security** ([https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)): Best practices and vulnerabilities.

This guide offers a detailed insight into API attack surfaces, leveraging web security standards and the provided cheat sheet. Explore further with OWASP resources for advanced techniques.