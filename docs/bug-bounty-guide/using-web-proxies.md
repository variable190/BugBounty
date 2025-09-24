# Using Web Proxies

## Tools

- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Foxy Proxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/)
- [Proxychains](https://github.com/haad/proxychains)

## Setup

- Configure proxy settings/install and configure foxy proxy
- Add certificate

## Tool Functions 

| Function                  | Burp                                      | ZAP                                      |
|---------------------------|-------------------------------------------|------------------------------------------|
| Intercepting Requests     | Proxy tab, Intercept sub-tab, toggle on   | Toggle green button or [Ctrl+B]          |
| Intercept Response        | Proxy > Options, enable Intercept Response | Automatically enabled with intercept     |
| Automatic Modification    | Proxy > Options > Match and Replace, add rule | [Ctrl+R] or Replacer in Options          |
| Repeating Requests        | [Ctrl+R] or right-click, send to Repeater | Right-click, select Open/Resend          |
| URL Encoding              | Right-click, Convert Selection > URL Encode, or [Ctrl+U] | Auto-encodes request data before sending |
| Decoding                  | Decoder tab                              | [Ctrl+E]                                 |
| Fuzzing                   | [https://academy.hackthebox.com/module/110/section/1054](https://academy.hackthebox.com/module/110/section/1054) | [https://academy.hackthebox.com/module/110/section/1056](https://academy.hackthebox.com/module/110/section/1056) |
| Web Scanner               | [https://academy.hackthebox.com/module/110/section/1084](https://academy.hackthebox.com/module/110/section/1084) | [https://academy.hackthebox.com/module/110/section/1086](https://academy.hackthebox.com/module/110/section/1086) |
| Extensions                | [https://portswigger.net/bappstore](https://portswigger.net/bappstore) | [https://www.zaproxy.org/addons/](https://www.zaproxy.org/addons/) |

## Burp Shortcuts

| Shortcut      | Description         |
|---------------|---------------------|
| [CTRL+R]      | Send to repeater    |
| [CTRL+SHIFT+R]| Go to repeater      |
| [CTRL+I]      | Send to intruder    |
| [CTRL+SHIFT+I]| Go to intruder      |
| [CTRL+U]      | URL encode          |
| [CTRL+SHIFT+U]| URL decode          |

## ZAP Shortcuts

| Shortcut      | Description             |
|---------------|-------------------------|
| [CTRL+B]      | Toggle intercept on/off |
| [CTRL+R]      | Go to replacer          |
| [CTRL+E]      | Go to encode/decode/hash|

## Firefox Shortcuts

| Shortcut      | Description           |
|---------------|-----------------------|
| [CTRL+SHIFT+R]| Force Refresh Page    |
| [F12]         | Open Developer Tools  |
| [CTRL+SHIFT+I]| Open Inspector        |
| [CTRL+SHIFT+E]| Open Network Panel    |
| [CTRL+SHIFT+J]| Open Console          |
| [CTRL+U]      | View Page Source      |

