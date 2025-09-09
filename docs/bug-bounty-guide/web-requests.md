# Web Requests 

## HTTP Response Codes

### Classes

| Class | Description |
|-------|-------------|
| 1xx | Provides information, does not affect request processing |
| 2xx | Indicates a successful request |
| 3xx | Indicates server redirection of the client |
| 4xx | Signifies improper client requests (e.g., nonexistent resource or bad format) |
| 5xx | Indicates an issue with the HTTP server |

### Specific Codes

| Code | Name | Description |
|------|------|-------------|
| 100 | Continue | Request can continue |
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 204 | No Content | Request successful, no content |
| 301 | Moved Permanently | Resource moved permanently |
| 302 | Found | Resource temporarily moved |
| 400 | Bad Request | Invalid request |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 500 | Internal Server Error | Server error |
| 502 | Bad Gateway | Invalid gateway response |
| 503 | Service Unavailable | Server temporarily unavailable |

## HTTP Headers

[Complete list of standard headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers)

### Request Headers
Contain more information about the resource to be fetched, or about the client requesting the resource.

| Header | Example | Description |
|--------|---------|-------------|
| Accept | `text/html,application/xhtml+xml` | Media types acceptable for the response |
| Authorization | `Bearer eyJhbGciOiJIUzI1NiJ9...` | Credentials for authentication |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | Client software details |
| Host | `developer.mozilla.org` | Domain name of the server |
| Referer | `https://example.com/page` | URL of the page that initiated the request |
| Cookie | `sessionId=abc123; user=john` | Cookies previously set by the server, sent with the request |

[Full list of request headers][https://datatracker.ietf.org/doc/html/rfc7231#section-5]

### Response Headers
Hold additional information about the response, like its location or about the server providing it.

| Header | Example | Description |
|--------|---------|-------------|
| Location | `https://developer.mozilla.org/` | URL for redirection |
| Server | `Apache/2.4.41 (Unix)` | Server software information |
| Allow | `GET, POST, HEAD` | Allowed HTTP methods |
| Date | `Tue, 09 Sep 2025 09:09:00 GMT` | Date and time of the response |
| Set-Cookie | `sessionId=abc123; Path=/; HttpOnly` | Defines a cookie to be stored by the client |
| WWW-Authenticate |     | Authentication method and realm for access |

[Full list of response headers](https://datatracker.ietf.org/doc/html/rfc7231#section-7)

### Security Headers
Response headers that enforce browser security policies to protect websites from attacks.

| Header | Example | Description |
|--------|---------|-------------|
| Content-Security-Policy | `script-src 'self'` | Sets rules for allowed resource sources, preventing XSS by restricting scripts to trusted domains. |
| Strict-Transport-Security | `max-age=31536000` | Forces HTTPS connections, blocking plaintext HTTP to prevent traffic sniffing. |
| Referrer-Policy | `origin` | Controls `Referer` header, limiting sensitive URL exposure during navigation. |

[OWASP secure response headers](https://owasp.org/www-project-secure-headers/)

### Representation/Entity Headers
Contain information about the body of the resource, like its MIME type, or encoding/compression applied. Common to both request and response.

| Header | Example | Description |
|--------|---------|-------------|
| Content-Type | `text/html; charset=UTF-8` | MIME type and character encoding of the body |
| Content-Encoding | `gzip` | Compression method applied to the body |
| Content-Language | `en-US` | Language of the resource content |
| Content-Location | `/documents/foo.json` | Alternate location for the returned data |
| Boundary | `----WebKitFormBoundary7MA4YWxkTrZu0gW` | Delimiter for separating parts in multipart messages, e.g., form data or file uploads |
| Media-Type | `multipart/form-data` | Specifies the MIME type of the message body, often used with multipart data |

### Payload Headers
Contain representation-independent information about payload data, including content length and the encoding used for transport.

| Header | Example | Description |
|--------|---------|-------------|
| Content-Length | `348` | Size of the response body in bytes |
| Transfer-Encoding | `chunked` | Encoding used for data transfer |
| Trailer | `Expires` | Headers sent after the chunked response |

## HTTP Request Methods

| Method | Description |
|--------|-------------|
| GET | Requests a resource |
| POST | Submits data to create/update a resource |
| PUT | Updates a resource with provided data |
| DELETE | Removes a specified resource |
| HEAD | Requests headers only, no body |
| OPTIONS | Lists allowed methods for a resource |
| PATCH | Partially updates a resource |
| TRACE | Echoes the received request for debugging |

## cURL
| Command | Description |
|---------|-------------|
| `curl -h` | cURL help menu |
| `curl inlanefreight.com` | Basic GET request |
| `curl -s -O inlanefreight.com/index.html` | Download file |
| `curl -k https://inlanefreight.com` | Skip HTTPS (SSL) certificate validation |
| `curl inlanefreight.com -v` | Print full HTTP request/response details |
| `curl -I https://www.inlanefreight.com` | Send HEAD request (only prints response headers) |
| `curl -i https://www.inlanefreight.com` | Print response headers and response body |
| `curl https://www.inlanefreight.com -A 'Mozilla/5.0'` | Set User-Agent header |
| `curl -u admin:admin http://<SERVER_IP>:<PORT>/` | Set HTTP basic authorization credentials |
| `curl http://admin:admin@<SERVER_IP>:<PORT>/` | Pass HTTP basic authorization credentials in the URL |
| `curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://<SERVER_IP>:<PORT>/` | Set request header |
| `curl 'http://<SERVER_IP>:<PORT>/search.php?search=le'` | Pass GET parameters |
| `curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/` | Send POST request with POST data |
| `curl -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/` | Set request cookies |
| `curl -X POST -d '{"search":"london"}' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php` | Send POST request with JSON data |

## APIs
| Command | Description |
|---------|-------------|
| `curl http://<SERVER_IP>:<PORT>/api.php/city/london` | Read entry |
| `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` | Read all entries |
| `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Create (add) entry |
| `curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'` | Update (modify) entry |
| `curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City` | Delete entry |

## Browser DevTools
| Shortcut | Description |
|----------|-------------|
| `[CTRL+SHIFT+I]` or `[F12]` | Show devtools |
| `[CTRL+SHIFT+E]` | Show Network tab |
| `[CTRL+SHIFT+K]` | Show Console tab |

**Tip:** Use the network tab to observe dynaic content in action