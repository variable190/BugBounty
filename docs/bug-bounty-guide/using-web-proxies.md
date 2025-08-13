# Using Web Proxies

[Relative Cheat Sheet](./web-proxies-cheat.markdown)

## Overview
Web proxies intercept and manipulate HTTP/HTTPS traffic between client and server, aiding in security testing.

## Setting Up
- **Burp Suite**: Configure proxy on 127.0.0.1:8080, install certificate in browser.
- **ZAP**: Set up similarly, enable proxy on default port.

## Intercepting Web Requests
- Capture requests in real-time, modify parameters or headers for testing.

## Intercepting Responses
- Alter server responses to simulate vulnerabilities or test client behavior.

## Automatic Modification
- Use tools to automate changes (e.g., Burp Repeater) for repetitive tests.

## Repeating Requests
- Resend modified requests to analyze different outcomes.

## Encoding/Decoding
- Convert data (URL encode/decode) to bypass filters or inspect encoded inputs.

## Proxying Tools
- **Burp Intruder**: Fuzz parameters.
- **ZAP Fuzzer**: Test input variations.
- **Burp Scanner**: Automated vulnerability scanning.
- **ZAP Scanner**: Similar automated scans.
- **Extensions**: Add custom scripts (e.g., for CSRF testing).

## Tools
- Burp Suite ([https://portswigger.net/burp](https://portswigger.net/burp)).
- OWASP ZAP ([https://www.zaproxy.org/](https://www.zaproxy.org/)).