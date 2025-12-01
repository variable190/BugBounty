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

