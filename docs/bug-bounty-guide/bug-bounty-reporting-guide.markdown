# Bug Bounty Reporting

## Step-by-Step Guide for Writing Effective Bug Bounty Reports

### 1. Understand the Importance of a Good Report
   - **Explanation**: A well-crafted bug bounty report communicates the vulnerability clearly to the program’s triage team, increasing the likelihood of acceptance and appropriate bounty rewards. It should be concise, professional, and demonstrate the issue’s severity and impact.
   - **Why It's Done**: A clear report ensures the organization understands the vulnerability, can reproduce it, and prioritizes fixing it. Poor reports may be rejected or misunderstood.
   - **Example**: A vague XSS report might be ignored, while a detailed one with a proof of concept (PoC) gets attention.

### 2. Craft a Descriptive Vulnerability Title
   - **Explanation**: Create a title that summarizes the vulnerability, including its type, affected component (e.g., domain, endpoint, parameter), and potential impact. Be specific but concise to grab attention.
   - **Why It's Done**: The title is the first thing triagers see; it sets expectations and helps categorize the issue.
   - **Example**: “Stored XSS in Comment Section of example.com/blog Allowing Cookie Theft” clearly states the vuln type, location, and impact.

### 3. Include CWE and CVSS Score
   - **Explanation**: Reference the Common Weakness Enumeration (CWE) to categorize the vulnerability type (e.g., CWE-79 for XSS). Calculate the Common Vulnerability Scoring System (CVSS) score to quantify severity (using tools like [CVSS Calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)).
   - **Why It's Done**: CWE provides a standard classification, while CVSS communicates severity (e.g., Low, Medium, High, Critical), aiding prioritization.
   - **Example**: For XSS, use CWE-79 and CVSS 6.1 (Medium) if it allows session hijacking without user interaction.

### 4. Write a Clear Vulnerability Description
   - **Explanation**: Explain the vulnerability’s cause, how it occurs, and the affected component. Include technical details like the endpoint, parameter, or misconfiguration, avoiding overly complex jargon.
   - **Why It's Done**: Helps triagers understand the root cause and context, making it easier to validate and fix.
   - **Example**: “The comment input on /blog/post/123 lacks output encoding, allowing injection of arbitrary JavaScript that executes in other users’ browsers.”

### 5. Provide a Proof of Concept (PoC)
   - **Explanation**: Detail step-by-step instructions to reproduce the vulnerability, including tools, payloads, or requests. Use screenshots, videos, or logs for clarity, ensuring the PoC is non-destructive.
   - **Why It's Done**: A reproducible PoC proves the vulnerability exists and helps developers verify it quickly.
   - **Example**: For stored XSS: “1. Navigate to /blog/post/123. 2. Submit comment `<script>alert('XSS')</script>`. 3. Reload page to see alert.”

### 6. Elaborate on Impact
   - **Explanation**: Describe what an attacker could achieve, focusing on business impact (e.g., data theft, account takeover) and maximum damage (e.g., chained exploits). Quantify affected users or systems if possible.
   - **Why It's Done**: Demonstrates severity to justify bounty and prioritize fixes.
   - **Example**: “Stored XSS allows stealing user cookies, leading to account takeover for all blog visitors, potentially exposing sensitive user data.”

### 7. Suggest Remediation (Optional)
   - **Explanation**: Recommend fixes, like input validation, output encoding, or configuration changes. Reference standards like OWASP guidelines.
   - **Why It's Done**: Shows goodwill and helps developers address the issue, though not always required in bug bounty programs.
   - **Example**: For XSS: “Implement output encoding with a library like OWASP ESAPI and enforce a strict Content Security Policy (CSP).”

### 8. Reference Example Reports
   - **Explanation**: Study high-quality report templates to structure your submission. Use examples like those from Hack The Box Academy for stored XSS, CSRF, or RCE.
   - **Why It's Done**: Well-structured reports increase acceptance rates and clarity.
   - **Example**: Review the example reports listed below for formatting.

### 9. Submit Through the Program’s Platform
   - **Explanation**: Use the bug bounty platform (e.g., HackerOne, Bugcrowd) to submit the report, following their guidelines for format and required fields.
   - **Why It's Done**: Ensures the report reaches the right team and complies with program rules, avoiding delays or rejections.
   - **Example**: Submit via HackerOne’s form, attaching PoC screenshots or a video.

### 10. Interact Professionally with Triagers
   - **Explanation**: Respond promptly to triage team requests for clarification or additional details. Be polite and provide further PoCs if needed.
   - **Why It's Done**: Builds trust and increases likelihood of bounty approval.
   - **Example**: If asked for more details, provide additional steps or a video demonstrating the vuln.

### 11. Monitor for Fixes and Retest
   - **Explanation**: After submission, check if the program allows retesting post-fix. Verify if the vulnerability is resolved.
   - **Why It's Done**: Ensures the fix is effective and may lead to additional rewards for follow-up reports.
   - **Example**: Retest XSS payload post-fix to confirm it’s escaped.

## Example Reports
- [Reporting Stored XSS](https://academy.hackthebox.com/module/161/section/1507)
- [Reporting CSRF](https://academy.hackthebox.com/module/161/section/1510)
- [Reporting RCE](https://academy.hackthebox.com/module/161/section/1511)

This guide, inspired by Hack The Box Academy and aligned with OWASP best practices, equips hunters to craft effective bug bounty reports. Always adhere to program scope and ethical guidelines.