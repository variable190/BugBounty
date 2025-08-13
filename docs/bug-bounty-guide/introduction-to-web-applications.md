# Introduction to Web Applications

## Overview
Web applications are software programs accessed via a web browser, typically built with a client-server architecture.

## Web Application Layout
- **Front-End**: Includes HTML for structure, CSS for styling, and JavaScript for interactivity, running in the browser.
- **Back-End**: Comprises servers (e.g., Apache, Nginx), databases (e.g., MySQL, MongoDB), and APIs handling logic and data.

## Front-End vs. Back-End
- **Front-End**: User-facing, dynamic with JavaScript (e.g., React, Vue). Vulnerable to XSS or client-side injection.
- **Back-End**: Server-side, manages data and requests. Susceptible to SQLi or server misconfigs.

## Key Technologies
- **HTML**: Defines content and structure.
- **CSS**: Controls presentation.
- **JavaScript**: Adds interactivity (e.g., form validation).

## Sensitive Data Exposure
Risk of leaking credentials or keys if not encrypted or if source code is exposed.

## Common Vulnerabilities
- **HTML Injection**: Unsanitized input renders as HTML.
- **XSS**: Malicious scripts execute in users’ browsers.
- **CSRF**: Unauthorized actions via forged requests.
- **Back-End Issues**: Misconfigured servers or vulnerable APIs.

## Tools
- Browser DevTools ([CTRL+SHIFT+I]) for front-end analysis.
- Burp Suite for backend traffic inspection.