# JavaScript Deobfuscation

[Relative Cheat Sheet](./js-deobfuscation-cheat.md)

## Overview
JavaScript deobfuscation involves reversing the process of making code unreadable to uncover its original logic, often used to identify vulnerabilities like XSS or hidden API calls.

## Source Code
- **Types**: Minified, encoded (base64, hex), or packed with tools like UglifyJS.
- **Purpose**: Protects intellectual property but can hide malicious intent.

## Code Obfuscation
- **Basic**: Renaming variables, removing whitespace.
- **Advanced**: String encryption, control flow flattening.

## Deobfuscation Process
- **Manual**: Analyze with browser DevTools (Ctrl+Shift+I).
- **Automated**: Use online tools to beautify and decode.

## Tools and Websites
- **Prettier** ([https://prettier.io/](https://prettier.io/)): Formats code for readability.
- **Beautifier** ([http://jsbeautifier.org/](http://jsbeautifier.org/)): Unminifies JavaScript.
- **JSNice** ([http://jsnice.org/](http://jsnice.org/)): Infers variable names.
- **JS Console**: Built-in browser tool for step-through debugging.

## Code Analysis
- **Focus**: Look for DOM manipulation (e.g., `innerHTML` for XSS), HTTP requests (e.g., `fetch` for SSRF), or eval() usage.
- **Technique**: Step through with breakpoints to observe execution.

## HTTP Requests
- **Inspection**: Decode requests in obfuscated code to find endpoints or parameters.
- **Exploit**: Modify requests to test for injection or bypass.

## Decoding Techniques
- **Base64**: Use `echo "encoded" | base64 -d`.
- **Hex**: Convert with `xxd -r -p`.
- **Rot13**: Apply `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.

This guide leverages knowledge from JavaScript security practices and online resources, aiding in vulnerability discovery.