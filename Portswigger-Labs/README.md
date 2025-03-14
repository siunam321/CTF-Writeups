All my Portswigger Labs writeups will be here.

Date          | Category                       | Directory Name     | Lab Title
--------------|--------------------------------|--------------------|----------------------
Dec 3, 2022   | SQL Injection                  | SQLi-1             | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
Dec 3, 2022   | SQL Injection                  | SQLi-2             | SQL injection vulnerability allowing login bypass
Dec 4, 2022   | SQL Injection                  | SQLi-3             | SQL injection UNION attack, determining the number of columns returned by the query
Dec 4, 2022   | SQL Injection                  | SQLi-4             | SQL injection UNION attack, finding a column containing text
Dec 4, 2022   | SQL Injection                  | SQLi-5             | SQL injection UNION attack, retrieving data from other tables
Dec 4, 2022   | SQL Injection                  | SQLi-6             | SQL injection UNION attack, retrieving multiple values in a single column
Dec 4, 2022   | SQL Injection                  | SQLi-7             | SQL injection attack, querying the database type and version on Oracle
Dec 5, 2022   | SQL Injection                  | SQLi-8             | SQL injection attack, querying the database type and version on MySQL and Microsoft
Dec 5, 2022   | SQL Injection                  | SQLi-9             | SQL injection attack, listing the database contents on non-Oracle databases
Dec 5, 2022   | SQL Injection                  | SQLi-10            | SQL injection attack, listing the database contents on Oracle
Dec 6, 2022   | SQL Injection                  | SQLi-11            | Blind SQL injection with conditional responses
Dec 7, 2022   | SQL Injection                  | SQLi-12            | Blind SQL injection with conditional errors
May 19, 2023  | SQL Injection                  | SQLi-13            | Visible error-based SQL injection
Dec 9, 2022   | SQL Injection                  | SQLi-14            | Blind SQL injection with time delays
Dec 8, 2022   | SQL Injection                  | SQLi-15            | Blind SQL injection with time delays and information retrieval
Mar 1, 2023   | SQL Injection                  | SQLi-16            | Blind SQL injection with out-of-band interaction
Mar 1, 2023   | SQL Injection                  | SQLi-17            | Blind SQL injection with out-of-band data exfiltration
Dec 11, 2022  | SQL Injection                  | SQLi-18            | SQL injection with filter bypass via XML encoding
Dec 12, 2022  | Directory Traversal            | DT-1               | File path traversal, simple case
Dec 12, 2022  | Directory Traversal            | DT-2               | File path traversal, traversal sequences blocked with absolute path bypass
Dec 12, 2022  | Directory Traversal            | DT-3               | File path traversal, traversal sequences stripped non-recursively
Dec 12, 2022  | Directory Traversal            | DT-4               | File path traversal, traversal sequences stripped with superfluous URL-decode
Dec 12, 2022  | Directory Traversal            | DT-5               | File path traversal, validation of start of path
Dec 12, 2022  | Directory Traversal            | DT-6               | File path traversal, validation of file extension with null byte bypass
Dec 12, 2022  | Access Control                 | AC-1               | Unprotected admin functionality
Dec 12, 2022  | Access Control                 | AC-2               | Unprotected admin functionality with unpredictable URL
Dec 12, 2022  | Access Control                 | AC-3               | User role controlled by request parameter
Dec 12, 2022  | Access Control                 | AC-4               | User role can be modified in user profile
Dec 14, 2022  | Access Control                 | AC-5               | User ID controlled by request parameter
Dec 14, 2022  | Access Control                 | AC-6               | User ID controlled by request parameter, with unpredictable user IDs
Dec 14, 2022  | Access Control                 | AC-7               | User ID controlled by request parameter with data leakage in redirect
Dec 14, 2022  | Access Control                 | AC-8               | User ID controlled by request parameter with password disclosure
Dec 14, 2022  | Access Control                 | AC-9               | Insecure direct object references
Dec 14, 2022  | Access Control                 | AC-10              | URL-based access control can be circumvented
Dec 14, 2022  | Access Control                 | AC-11              | Method-based access control can be circumvented
Dec 14, 2022  | Access Control                 | AC-12              | Multi-step process with no access control on one step
Dec 14, 2022  | Access Control                 | AC-13              | Referer-based access control
Dec 15, 2022  | CSRF                           | CSRF-1             | CSRF vulnerability with no defenses
Dec 15, 2022  | CSRF                           | CSRF-2             | CSRF where token validation depends on request method
Dec 15, 2022  | CSRF                           | CSRF-3             | CSRF where token validation depends on token being present
Dec 15, 2022  | CSRF                           | CSRF-4             | CSRF where token is not tied to user session
Dec 15, 2022  | CSRF                           | CSRF-5             | CSRF where token is tied to non-session cookie
Dec 15, 2022  | CSRF                           | CSRF-6             | CSRF where token is duplicated in cookie
Jan 13, 2023  | CSRF                           | CSRF-7             | SameSite Lax bypass via method override
Jan 13, 2023  | CSRF                           | CSRF-8             | SameSite Strict bypass via client-side redirect
Jan 13, 2023  | CSRF                           | CSRF-9             | SameSite Strict bypass via sibling domain
Jan 13, 2023  | CSRF                           | CSRF-10            | SameSite Lax bypass via cookie refresh
Dec 15, 2022  | CSRF                           | CSRF-11            | CSRF where Referer validation depends on header being present
Dec 15, 2022  | CSRF                           | CSRF-12            | CSRF with broken Referer validation
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-1              | Remote code execution via web shell upload
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-2              | Web shell upload via Content-Type restriction bypass
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-3              | Web shell upload via path traversal
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-4              | Web shell upload via extension blacklist bypass
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-5              | Web shell upload via obfuscated file extension
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-6              | Remote code execution via polyglot web shell upload
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-7              | Web shell upload via race condition
Dec 16, 2022  | Information Disclosure         | ID-1               | Information disclosure in error messages
Dec 16, 2022  | Information Disclosure         | ID-2               | Information disclosure on debug page
Dec 16, 2022  | Information Disclosure         | ID-3               | Source code disclosure via backup files
Dec 16, 2022  | Information Disclosure         | ID-4               | Authentication bypass via information disclosure
Dec 16, 2022  | Information Disclosure         | ID-5               | Information disclosure in version control history
Dec 19, 2022  | WebSockets                     | WS-1               | Manipulating WebSocket messages to exploit vulnerabilities
Dec 19, 2022  | WebSockets                     | WS-2               | Manipulating the WebSocket handshake to exploit vulnerabilities
Dec 19, 2022  | WebSockets                     | WS-3               | Cross-site WebSocket hijacking
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-1              | Excessive trust in client-side controls
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-2              | High-level logic vulnerability
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-3              | Inconsistent security controls
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-4              | Flawed enforcement of business rules
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-5              | Low-level logic flaw
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-6              | Inconsistent handling of exceptional input
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-7              | Weak isolation on dual-use endpoint
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-8              | Insufficient workflow validation
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-9              | Authentication bypass via flawed state machine
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-10             | Infinite money logic flaw
Dec 21, 2022  | Business Logic Vulnerabilities | BLV-11             | Authentication bypass via encryption oracle
Dec 3, 2024   | Business Logic Vulnerabilities | BLV-12             | Bypassing access controls using email address parsing discrepancies
Dec 21, 2022  | Authentication                 | Auth-1             | Username enumeration via different responses
Dec 21, 2022  | Authentication                 | Auth-2             | 2FA simple bypass
Dec 21, 2022  | Authentication                 | Auth-3             | Password reset broken logic
Dec 21, 2022  | Authentication                 | Auth-4             | Username enumeration via subtly different responses
Dec 21, 2022  | Authentication                 | Auth-5             | Username enumeration via response timing
Dec 21, 2022  | Authentication                 | Auth-6             | Broken brute-force protection, IP block
Dec 22, 2022  | Authentication                 | Auth-7             | Username enumeration via account lock
Dec 22, 2022  | Authentication                 | Auth-8             | 2FA broken logic
Dec 22, 2022  | Authentication                 | Auth-9             | Brute-forcing a stay-logged-in cookie
Dec 22, 2022  | Authentication                 | Auth-10            | Offline password cracking
Dec 22, 2022  | Authentication                 | Auth-11            | Password reset poisoning via middleware
Dec 22, 2022  | Authentication                 | Auth-12            | Password brute-force via password change
Dec 22, 2022  | Authentication                 | Auth-13            | Broken brute-force protection, multiple credentials per request
Dec 22, 2022  | Authentication                 | Auth-14            | 2FA bypass using a brute-force attack
Dec 23, 2022  | OS Command Injection           | OSCI-1             | OS command injection, simple case
Dec 23, 2022  | OS Command Injection           | OSCI-2             | Blind OS command injection with time delays
Dec 23, 2022  | OS Command Injection           | OSCI-3             | Blind OS command injection with output redirection
Mar 1, 2023   | OS Command Injection           | OSCI-4             | Blind OS command injection with out-of-band interaction
Mar 1, 2023   | OS Command Injection           | OSCI-5             | Blind OS command injection with out-of-band data exfiltration
Dec 23, 2022  | Server-Side Template Injection | SSTI-1             | Basic server-side template injection
Dec 23, 2022  | Server-Side Template Injection | SSTI-2             | Basic server-side template injection (code context)
Dec 23, 2022  | Server-Side Template Injection | SSTI-3             | Server-side template injection using documentation
Dec 23, 2022  | Server-Side Template Injection | SSTI-4             | Server-side template injection in an unknown language with a documented exploit
Dec 23, 2022  | Server-Side Template Injection | SSTI-5             | Server-side template injection with information disclosure via user-supplied objects
Dec 23, 2022  | Server-Side Template Injection | SSTI-6             | Server-side template injection in a sandboxed environment
Dec 24, 2022  | Server-Side Template Injection | SSTI-7             | Server-side template injection with a custom exploit
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-1             | Basic SSRF against the local server
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-2             | Basic SSRF against another back-end system
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-3             | SSRF with blacklist-based input filter
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-4             | SSRF with filter bypass via open redirection vulnerability
Mar 1, 2023   | Server-Side Request Forgery    | SSRF-5             | Blind SSRF with out-of-band detection
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-6             | SSRF with whitelist-based input filter
Mar 1, 2023   | Server-Side Request Forgery    | SSRF-7             | Blind SSRF with Shellshock exploitation
Dec 25, 2022  | XXE Injection                  | XXE-1              | Exploiting XXE using external entities to retrieve files
Dec 25, 2022  | XXE Injection                  | XXE-2              | Exploiting XXE to perform SSRF attacks
Mar 1, 2023   | XXE Injection                  | XXE-3              | Blind XXE with out-of-band interaction
Mar 1, 2023   | XXE Injection                  | XXE-4              | Blind XXE with out-of-band interaction via XML parameter entities
Dec 25, 2022  | XXE Injection                  | XXE-5              | Exploiting blind XXE to exfiltrate data using a malicious external DTD
Dec 25, 2022  | XXE Injection                  | XXE-6              | Exploiting blind XXE to retrieve data via error messages
Dec 25, 2022  | XXE Injection                  | XXE-7              | Exploiting XInclude to retrieve files
Dec 25, 2022  | XXE Injection                  | XXE-8              | Exploiting XXE via image file upload
Dec 25, 2022  | XXE Injection                  | XXE-9              | Exploiting XXE to retrieve data by repurposing a local DTD
Dec 26, 2022  | JWT                            | JWT-1              | JWT authentication bypass via unverified signature
Dec 26, 2022  | JWT                            | JWT-2              | JWT authentication bypass via flawed signature verification
Dec 26, 2022  | JWT                            | JWT-3              | JWT authentication bypass via weak signing key
Dec 26, 2022  | JWT                            | JWT-4              | JWT authentication bypass via jwk header injection
Dec 26, 2022  | JWT                            | JWT-5              | JWT authentication bypass via jku header injection
Dec 26, 2022  | JWT                            | JWT-6              | JWT authentication bypass via kid header path traversal
Dec 26, 2022  | JWT                            | JWT-7              | JWT authentication bypass via algorithm confusion
Dec 26, 2022  | JWT                            | JWT-8              | JWT authentication bypass via algorithm confusion with no exposed key
Dec 26, 2022  | JWT                            | JWT-8              | JWT authentication bypass via algorithm confusion with no exposed key
Dec 27, 2022  | Cross-Origin Resource Sharing  | CORS-1             | CORS vulnerability with basic origin reflection
Dec 27, 2022  | Cross-Origin Resource Sharing  | CORS-2             | CORS vulnerability with trusted null origin
Dec 27, 2022  | Cross-Origin Resource Sharing  | CORS-3             | CORS vulnerability with trusted insecure protocols
Dec 27, 2022  | Cross-Origin Resource Sharing  | CORS-4             | CORS vulnerability with internal network pivot attack
Dec 28, 2022  | HTTP Host Header Attacks       | HTTP-Host-Header-1 | Basic password reset poisoning
Dec 28, 2022  | HTTP Host Header Attacks       | HTTP-Host-Header-2 | Host header authentication bypass
Dec 28, 2022  | HTTP Host Header Attacks       | HTTP-Host-Header-3 | Web cache poisoning via ambiguous requests
Mar 1, 2023   | HTTP Host Header Attacks       | HTTP-Host-Header-4 | Routing-based SSRF
Mar 1, 2023   | HTTP Host Header Attacks       | HTTP-Host-Header-5 | SSRF via flawed request parsing
Dec 28, 2022  | HTTP Host Header Attacks       | HTTP-Host-Header-6 | Host validation bypass via connection state attack
Dec 28, 2022  | HTTP Host Header Attacks       | HTTP-Host-Header-7 | Password reset poisoning via dangling markup
Dec 29, 2022  | Cross-Site Scripting           | XSS-1              | Reflected XSS into HTML context with nothing encoded
Dec 29, 2022  | Cross-Site Scripting           | XSS-2              | Stored XSS into HTML context with nothing encoded
Dec 29, 2022  | Cross-Site Scripting           | XSS-3              | DOM XSS in `document.write` sink using source `location.search`
Dec 29, 2022  | Cross-Site Scripting           | XSS-4              | DOM XSS in `innerHTML` sink using source `location.search`
Dec 29, 2022  | Cross-Site Scripting           | XSS-5              | DOM XSS in jQuery anchor `href` attribute sink using `location.search` source
Dec 29, 2022  | Cross-Site Scripting           | XSS-6              | DOM XSS in jQuery selector sink using a hashchange event
Dec 29, 2022  | Cross-Site Scripting           | XSS-7              | Reflected XSS into attribute with angle brackets HTML-encoded
Dec 29, 2022  | Cross-Site Scripting           | XSS-8              | Stored XSS into anchor `href` attribute with double quotes HTML-encoded
Dec 29, 2022  | Cross-Site Scripting           | XSS-9              | Reflected XSS into a JavaScript string with angle brackets HTML encoded
Dec 29, 2022  | Cross-Site Scripting           | XSS-10             | DOM XSS in `document.write` sink using source `location.search` inside a select element
Dec 30, 2022  | Cross-Site Scripting           | XSS-11             | DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
Dec 30, 2022  | Cross-Site Scripting           | XSS-12             | Reflected DOM XSS
Dec 30, 2022  | Cross-Site Scripting           | XSS-13             | Stored DOM XSS
Dec 30, 2022  | Cross-Site Scripting           | XSS-14             | Exploiting cross-site scripting to steal cookies
Dec 31, 2022  | Cross-Site Scripting           | XSS-15             | Exploiting cross-site scripting to capture passwords
Dec 31, 2022  | Cross-Site Scripting           | XSS-16             | Exploiting XSS to perform CSRF
Dec 31, 2022  | Cross-Site Scripting           | XSS-17             | Reflected XSS into HTML context with most tags and attributes blocked
Dec 31, 2022  | Cross-Site Scripting           | XSS-18             | Reflected XSS into HTML context with all tags blocked except custom ones
Dec 31, 2022  | Cross-Site Scripting           | XSS-19             | Reflected XSS with some SVG markup allowed
Dec 31, 2022  | Cross-Site Scripting           | XSS-20             | Reflected XSS in canonical link tag
Jan 1, 2023   | Cross-Site Scripting           | XSS-21             | Reflected XSS into a JavaScript string with single quote and backslash escaped
Jan 1, 2023   | Cross-Site Scripting           | XSS-22             | Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
Jan 1, 2023   | Cross-Site Scripting           | XSS-23             | Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
Jan 1, 2023   | Cross-Site Scripting           | XSS-24             | Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
Jan 1, 2023   | Cross-Site Scripting           | XSS-25             | Reflected XSS with event handlers and `href` attributes blocked
Jan 1, 2023   | Cross-Site Scripting           | XSS-26             | Reflected XSS in a JavaScript URL with some characters blocked
Jan 1, 2023   | Cross-Site Scripting           | XSS-27             | Reflected XSS with AngularJS sandbox escape without strings
Jan 1, 2023   | Cross-Site Scripting           | XSS-28             | Reflected XSS with AngularJS sandbox escape and CSP
Jan 2, 2023   | Cross-Site Scripting           | XSS-29             | Reflected XSS protected by very strict CSP, with dangling markup attack
Jan 2, 2023   | Cross-Site Scripting           | XSS-30             | Reflected XSS protected by CSP, with CSP bypass
Jan 2, 2023   | Clickjacking                   | Clickjacking-1     | Basic clickjacking with CSRF token protection
Jan 2, 2023   | Clickjacking                   | Clickjacking-2     | Clickjacking with form input data prefilled from a URL parameter
Jan 2, 2023   | Clickjacking                   | Clickjacking-3     | Clickjacking with a frame buster script
Jan 2, 2023   | Clickjacking                   | Clickjacking-4     | Exploiting clickjacking vulnerability to trigger DOM-based XSS
Jan 2, 2023   | Clickjacking                   | Clickjacking-5     | Multistep clickjacking
Jan 3, 2023   | OAuth Authentication           | OAuth-1            | Authentication bypass via OAuth implicit flow
Jan 7, 2023   | OAuth Authentication           | OAuth-2            | Forced OAuth profile linking
Jan 7, 2023   | OAuth Authentication           | OAuth-3            | OAuth account hijacking via redirect_uri
Jan 7, 2023   | OAuth Authentication           | OAuth-4            | Stealing OAuth access tokens via an open redirect
Mar 1, 2023   | OAuth Authentication           | OAuth-5            | SSRF via OpenID dynamic client registration
Jan 7, 2023   | OAuth Authentication           | OAuth-6            | Stealing OAuth access tokens via a proxy page
Jan 10, 2023  | Insecure Deserialization       | Deserial-1         | Modifying serialized objects
Jan 10, 2023  | Insecure Deserialization       | Deserial-2         | Modifying serialized data types
Jan 10, 2023  | Insecure Deserialization       | Deserial-3         | Using application functionality to exploit insecure deserialization
Jan 10, 2023  | Insecure Deserialization       | Deserial-4         | Arbitrary object injection in PHP
Jan 10, 2023  | Insecure Deserialization       | Deserial-5         | Exploiting Java deserialization with Apache Commons
Jan 11, 2023  | Insecure Deserialization       | Deserial-6         | Exploiting PHP deserialization with a pre-built gadget chain
Jan 12, 2023  | Insecure Deserialization       | Deserial-7         | Exploiting Ruby deserialization using a documented gadget chain
Jan 12, 2023  | Insecure Deserialization       | Deserial-8         | Developing a custom gadget chain for Java deserialization
Jan 12, 2023  | Insecure Deserialization       | Deserial-9         | Developing a custom gadget chain for PHP deserialization
Jan 13, 2023  | Insecure Deserialization       | Deserial-10        | Using PHAR deserialization to deploy a custom gadget chain
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-1              | DOM XSS using web messages
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-2              | DOM XSS using web messages and a JavaScript URL
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-3              | DOM XSS using web messages and `JSON.parse`
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-4              | DOM-based open redirection
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-5              | DOM-based cookie manipulation
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-6              | Exploiting DOM clobbering to enable XSS
Jan 14, 2023  | DOM-Based Vulnerabilities      | DOM-7              | Clobbering DOM attributes to bypass HTML filters
Jan 15, 2023  | Prototype Pollution            | Prototype-1        | DOM XSS via client-side prototype pollution
Jan 18, 2023  | Prototype Pollution            | Prototype-2        | DOM XSS via an alternative prototype pollution vector
Jan 18, 2023  | Prototype Pollution            | Prototype-3        | Client-side prototype pollution in third-party libraries
Jan 22, 2023  | Prototype Pollution            | Prototype-4        | Client-side prototype pollution via browser APIs
Jan 22, 2023  | Prototype Pollution            | Prototype-5        | Client-side prototype pollution via flawed sanitization
Feb 22, 2023  | Prototype Pollution            | Prototype-6        | Privilege escalation via server-side prototype pollution
Feb 22, 2023  | Prototype Pollution            | Prototype-7        | Detecting server-side prototype pollution without polluted property reflection
Feb 22, 2023  | Prototype Pollution            | Prototype-8        | Bypassing flawed input filters for server-side prototype pollution
Feb 22, 2023  | Prototype Pollution            | Prototype-9        | Remote code execution via server-side prototype pollution
Feb 28, 2023  | Prototype Pollution            | Prototype-10       | Exfiltrating sensitive data via server-side prototype pollution
Jan 22, 2023  | Web Cache Poisoning            | Cache-1            | Web cache poisoning with an unkeyed header
Jan 23, 2023  | Web Cache Poisoning            | Cache-2            | Web cache poisoning with an unkeyed cookie
Jan 23, 2023  | Web Cache Poisoning            | Cache-3            | Web cache poisoning with multiple headers
Jan 23, 2023  | Web Cache Poisoning            | Cache-4            | Targeted web cache poisoning using an unknown header
Jan 24, 2023  | Web Cache Poisoning            | Cache-5            | Web cache poisoning via an unkeyed query string
Jan 24, 2023  | Web Cache Poisoning            | Cache-6            | Web cache poisoning via an unkeyed query parameter
Jan 24, 2023  | Web Cache Poisoning            | Cache-7            | Parameter cloaking
Jan 25, 2023  | Web Cache Poisoning            | Cache-8            | Web cache poisoning via a fat GET request
Jan 25, 2023  | Web Cache Poisoning            | Cache-9            | URL normalization
Jan 25, 2023  | Web Cache Poisoning            | Cache-10           | Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
Jan 26, 2023  | Web Cache Poisoning            | Cache-11           | Combining web cache poisoning vulnerabilities
Jan 26, 2023  | Web Cache Poisoning            | Cache-12           | Cache key injection
Jan 26, 2023  | Web Cache Poisoning            | Cache-13           | Internal cache poisoning
Jan 27, 2023  | HTTP Request Smuggling         | Smuggling-1        | HTTP request smuggling, basic CL.TE vulnerability
Jan 27, 2023  | HTTP Request Smuggling         | Smuggling-2        | HTTP request smuggling, basic TE.CL vulnerability
Jan 28, 2023  | HTTP Request Smuggling         | Smuggling-3        | HTTP request smuggling, obfuscating the TE header
Jan 28, 2023  | HTTP Request Smuggling         | Smuggling-4        | HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
Jan 28, 2023  | HTTP Request Smuggling         | Smuggling-5        | HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
Feb 1, 2023   | HTTP Request Smuggling         | Smuggling-6        | Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
Feb 1, 2023   | HTTP Request Smuggling         | Smuggling-7        | Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
Feb 1, 2023   | HTTP Request Smuggling         | Smuggling-8        | Exploiting HTTP request smuggling to reveal front-end request rewriting
Feb 1, 2023   | HTTP Request Smuggling         | Smuggling-9        | Exploiting HTTP request smuggling to capture other users' requests
Feb 1, 2023   | HTTP Request Smuggling         | Smuggling-10       | Exploiting HTTP request smuggling to deliver reflected XSS
Feb 13, 2023  | HTTP Request Smuggling         | Smuggling-11       | Response queue poisoning via H2.TE request smuggling
Feb 14, 2023  | HTTP Request Smuggling         | Smuggling-12       | H2.CL request smuggling
Feb 15, 2023  | HTTP Request Smuggling         | Smuggling-13       | HTTP/2 request smuggling via CRLF injection
Feb 15, 2023  | HTTP Request Smuggling         | Smuggling-14       | HTTP/2 request splitting via CRLF injection
Feb 15, 2023  | HTTP Request Smuggling         | Smuggling-15       | CL.0 request smuggling
Feb 24, 2023  | HTTP Request Smuggling         | Smuggling-16       | Exploiting HTTP request smuggling to perform web cache poisoning
Feb 24, 2023  | HTTP Request Smuggling         | Smuggling-17       | Exploiting HTTP request smuggling to perform web cache deception
Feb 25, 2023  | HTTP Request Smuggling         | Smuggling-18       | Bypassing access controls via HTTP/2 request tunnelling
Feb 26, 2023  | HTTP Request Smuggling         | Smuggling-19       | Web cache poisoning via HTTP/2 request tunnelling
Feb 26, 2023  | HTTP Request Smuggling         | Smuggling-20       | Client-side desync
Feb 26, 2023  | HTTP Request Smuggling         | Smuggling-21       | Browser cache poisoning via client-side desync
Feb 26, 2023  | HTTP Request Smuggling         | Smuggling-22       | Server-side pause-based request smuggling
Mar 1, 2023   | Essential Skills               | Essential-Skills-1 | Discovering vulnerabilities quickly with targeted scanning
Jul 5, 2023   | Testing GraphQL APIs           | GraphQL-1          | Accessing private GraphQL posts
Jul 5, 2023   | Testing GraphQL APIs           | GraphQL-2          | Accidental exposure of private GraphQL fields
Jul 7, 2023   | Testing GraphQL APIs           | GraphQL-3          | Finding a hidden GraphQL endpoint
Jul 7, 2023   | Testing GraphQL APIs           | GraphQL-4          | Bypassing GraphQL brute force protections
Jul 7, 2023   | Testing GraphQL APIs           | GraphQL-5          | Performing CSRF exploits over GraphQL
Aug 31, 2023  | Race Conditions                | Race-Conditions-1  | Limit overrun race conditions
Aug 31, 2023  | Race Conditions                | Race-Conditions-2  | Bypassing rate limits via race conditions
Aug 31, 2023  | Race Conditions                | Race-Conditions-3  | Multi-endpoint race conditions
Sept 8, 2023  | Race Conditions                | Race-Conditions-4  | Single-endpoint race conditions
Sept 19, 2023 | Race Conditions                | Race-Conditions-5  | Partial construction race conditions
Sept 25, 2023 | Race Conditions                | Race-Conditions-6  | Exploiting time-sensitive vulnerabilities
Oct 3, 2023   | NoSQL Injection                | NoSQLi-1           | Detecting NoSQL injection
Oct 9, 2023   | NoSQL Injection                | NoSQLi-2           | Exploiting NoSQL operator injection to bypass authentication
Oct 9, 2023   | NoSQL Injection                | NoSQLi-3           | Exploiting NoSQL injection to extract data
Oct 10, 2023  | NoSQL Injection                | NoSQLi-4           | Exploiting NoSQL operator injection to extract unknown fields
May 10, 2024  | API Testing                    | API-1              | Exploiting an API endpoint using documentation
May 10, 2024  | API Testing                    | API-2              | Finding and exploiting an unused API endpoint
May 10, 2024  | API Testing                    | API-3              | Exploiting a mass assignment vulnerability
May 10, 2024  | API Testing                    | API-4              | Exploiting server-side parameter pollution in a query string
May 10, 2024  | API Testing                    | API-5              | Exploiting server-side parameter pollution in a REST URL
May 15, 2024  | Web LLM Attacks                | LLM-1              | Exploiting LLM APIs with excessive agency
May 15, 2024  | Web LLM Attacks                | LLM-2              | Exploiting vulnerabilities in LLM APIs
May 15, 2024  | Web LLM Attacks                | LLM-3              | Indirect prompt injection
May 15, 2024  | Web LLM Attacks                | LLM-4              | Exploiting insecure output handling in LLMs
August 10, 2024 | Web Cache Deception          | WCD-1              | Exploiting path mapping for web cache deception
August 10, 2024 | Web Cache Deception          | WCD-2              | Exploiting path delimiters for web cache deception
August 10, 2024 | Web Cache Deception          | WCD-3              | Exploiting origin server normalization for web cache deception
August 10, 2024 | Web Cache Deception          | WCD-4              | Exploiting cache server normalization for web cache deception
August 15, 2024 | Web Cache Deception          | WCD-5              | Exploiting exact-match cache rules for web cache deception