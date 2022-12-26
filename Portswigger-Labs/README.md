All my Portswigger Labs writeups will be here.

Date          | Category                       | Directory Name | Lab Title
--------------|--------------------------------|----------------|----------------------
Dec 3, 2022   | SQL Injection                  | SQLi-1         | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
Dec 3, 2022   | SQL Injection                  | SQLi-2         | SQL injection vulnerability allowing login bypass
Dec 4, 2022   | SQL Injection                  | SQLi-3         | SQL injection UNION attack, determining the number of columns returned by the query
Dec 4, 2022   | SQL Injection                  | SQLi-4         | SQL injection UNION attack, finding a column containing text
Dec 4, 2022   | SQL Injection                  | SQLi-5         | SQL injection UNION attack, retrieving data from other tables
Dec 4, 2022   | SQL Injection                  | SQLi-6         | SQL injection UNION attack, retrieving multiple values in a single column
Dec 4, 2022   | SQL Injection                  | SQLi-7         | SQL injection attack, querying the database type and version on Oracle
Dec 5, 2022   | SQL Injection                  | SQLi-8         | SQL injection attack, querying the database type and version on MySQL and Microsoft
Dec 5, 2022   | SQL Injection                  | SQLi-9         | SQL injection attack, listing the database contents on non-Oracle databases
Dec 5, 2022   | SQL Injection                  | SQLi-10        | SQL injection attack, listing the database contents on Oracle
Dec 6, 2022   | SQL Injection                  | SQLi-11        | Blind SQL injection with conditional responses
Dec 7, 2022   | SQL Injection                  | SQLi-12        | Blind SQL injection with conditional errors
Dec 9, 2022   | SQL Injection                  | SQLi-13        | Blind SQL injection with time delays
Dec 8, 2022   | SQL Injection                  | SQLi-14        | Blind SQL injection with time delays and information retrieval
Dec 11, 2022  | SQL Injection                  | SQLi-17        | SQL injection with filter bypass via XML encoding
Dec 12, 2022  | Directory Traversal            | DT-1           | File path traversal, simple case
Dec 12, 2022  | Directory Traversal            | DT-2           | File path traversal, traversal sequences blocked with absolute path bypass
Dec 12, 2022  | Directory Traversal            | DT-3           | File path traversal, traversal sequences stripped non-recursively
Dec 12, 2022  | Directory Traversal            | DT-4           | File path traversal, traversal sequences stripped with superfluous URL-decode
Dec 12, 2022  | Directory Traversal            | DT-5           | File path traversal, validation of start of path
Dec 12, 2022  | Directory Traversal            | DT-6           | File path traversal, validation of file extension with null byte bypass
Dec 12, 2022  | Access Control                 | AC-1           | Unprotected admin functionality
Dec 12, 2022  | Access Control                 | AC-2           | Unprotected admin functionality with unpredictable URL
Dec 12, 2022  | Access Control                 | AC-3           | User role controlled by request parameter
Dec 12, 2022  | Access Control                 | AC-4           | User role can be modified in user profile
Dec 14, 2022  | Access Control                 | AC-5           | User ID controlled by request parameter
Dec 14, 2022  | Access Control                 | AC-6           | User ID controlled by request parameter, with unpredictable user IDs
Dec 14, 2022  | Access Control                 | AC-7           | User ID controlled by request parameter with data leakage in redirect
Dec 14, 2022  | Access Control                 | AC-8           | User ID controlled by request parameter with password disclosure
Dec 14, 2022  | Access Control                 | AC-9           | Insecure direct object references
Dec 14, 2022  | Access Control                 | AC-10          | URL-based access control can be circumvented
Dec 14, 2022  | Access Control                 | AC-11          | Method-based access control can be circumvented
Dec 14, 2022  | Access Control                 | AC-12          | Multi-step process with no access control on one step
Dec 14, 2022  | Access Control                 | AC-13          | Referer-based access control
Dec 15, 2022  | CSRF                           | CSRF-1         | CSRF vulnerability with no defenses
Dec 15, 2022  | CSRF                           | CSRF-2         | CSRF where token validation depends on request method
Dec 15, 2022  | CSRF                           | CSRF-3         | CSRF where token validation depends on token being present
Dec 15, 2022  | CSRF                           | CSRF-4         | CSRF where token is not tied to user session
Dec 15, 2022  | CSRF                           | CSRF-5         | CSRF where token is tied to non-session cookie
Dec 15, 2022  | CSRF                           | CSRF-6         | CSRF where token is duplicated in cookie
Dec 15, 2022  | CSRF                           | CSRF-7         | CSRF where Referer validation depends on header being present
Dec 15, 2022  | CSRF                           | CSRF-8         | CSRF with broken Referer validation
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-1          | Remote code execution via web shell upload
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-2          | Web shell upload via Content-Type restriction bypass
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-3          | Web shell upload via path traversal
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-4          | Web shell upload via extension blacklist bypass
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-5          | Web shell upload via obfuscated file extension
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-6          | Remote code execution via polyglot web shell upload
Dec 16, 2022  | File Upload Vulnerabilities    | FUV-7          | Web shell upload via race condition
Dec 16, 2022  | Information Disclosure         | ID-1           | Information disclosure in error messages
Dec 16, 2022  | Information Disclosure         | ID-2           | Information disclosure on debug page
Dec 16, 2022  | Information Disclosure         | ID-3           | Source code disclosure via backup files
Dec 16, 2022  | Information Disclosure         | ID-4           | Authentication bypass via information disclosure
Dec 16, 2022  | Information Disclosure         | ID-5           | Information disclosure in version control history
Dec 19, 2022  | WebSockets                     | WS-1           | Manipulating WebSocket messages to exploit vulnerabilities
Dec 19, 2022  | WebSockets                     | WS-2           | Manipulating the WebSocket handshake to exploit vulnerabilities
Dec 19, 2022  | WebSockets                     | WS-3           | Cross-site WebSocket hijacking
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-1          | Excessive trust in client-side controls
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-2          | High-level logic vulnerability
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-3          | Inconsistent security controls
Dec 19, 2022  | Business Logic Vulnerabilities | BLV-4          | Flawed enforcement of business rules
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-5          | Low-level logic flaw
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-6          | Inconsistent handling of exceptional input
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-7          | Weak isolation on dual-use endpoint
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-8          | Insufficient workflow validation
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-9          | Authentication bypass via flawed state machine
Dec 20, 2022  | Business Logic Vulnerabilities | BLV-10         | Infinite money logic flaw
Dec 21, 2022  | Business Logic Vulnerabilities | BLV-11         | Authentication bypass via encryption oracle
Dec 21, 2022  | Authentication                 | Auth-1         | Username enumeration via different responses
Dec 21, 2022  | Authentication                 | Auth-2         | 2FA simple bypass
Dec 21, 2022  | Authentication                 | Auth-3         | Password reset broken logic
Dec 21, 2022  | Authentication                 | Auth-4         | Username enumeration via subtly different responses
Dec 21, 2022  | Authentication                 | Auth-5         | Username enumeration via response timing
Dec 21, 2022  | Authentication                 | Auth-6         | Broken brute-force protection, IP block
Dec 22, 2022  | Authentication                 | Auth-7         | Username enumeration via account lock
Dec 22, 2022  | Authentication                 | Auth-8         | 2FA broken logic
Dec 22, 2022  | Authentication                 | Auth-9         | Brute-forcing a stay-logged-in cookie
Dec 22, 2022  | Authentication                 | Auth-10        | Offline password cracking
Dec 22, 2022  | Authentication                 | Auth-11        | Password reset poisoning via middleware
Dec 22, 2022  | Authentication                 | Auth-12        | Password brute-force via password change
Dec 22, 2022  | Authentication                 | Auth-13        | Broken brute-force protection, multiple credentials per request
Dec 22, 2022  | Authentication                 | Auth-14        | 2FA bypass using a brute-force attack
Dec 23, 2022  | OS Command Injection           | OSCI-1         | OS command injection, simple case
Dec 23, 2022  | OS Command Injection           | OSCI-2         | Blind OS command injection with time delays
Dec 23, 2022  | OS Command Injection           | OSCI-3         | Blind OS command injection with output redirection
Dec 23, 2022  | Server-Side Template Injection | SSTI-1         | Basic server-side template injection
Dec 23, 2022  | Server-Side Template Injection | SSTI-2         | Basic server-side template injection (code context)
Dec 23, 2022  | Server-Side Template Injection | SSTI-3         | Server-side template injection using documentation
Dec 23, 2022  | Server-Side Template Injection | SSTI-4         | Server-side template injection in an unknown language with a documented exploit
Dec 23, 2022  | Server-Side Template Injection | SSTI-5         | Server-side template injection with information disclosure via user-supplied objects
Dec 23, 2022  | Server-Side Template Injection | SSTI-6         | Server-side template injection in a sandboxed environment
Dec 24, 2022  | Server-Side Template Injection | SSTI-7         | Server-side template injection with a custom exploit
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-1         | Basic SSRF against the local server
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-2         | Basic SSRF against another back-end system
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-3         | SSRF with blacklist-based input filter
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-4         | SSRF with filter bypass via open redirection vulnerability
Dec 24, 2022  | Server-Side Request Forgery    | SSRF-6         | SSRF with whitelist-based input filter
Dec 25, 2022  | XXE Injection                  | XXE-1          | Exploiting XXE using external entities to retrieve files
Dec 25, 2022  | XXE Injection                  | XXE-2          | Exploiting XXE to perform SSRF attacks
Dec 25, 2022  | XXE Injection                  | XXE-5          | Exploiting blind XXE to exfiltrate data using a malicious external DTD
Dec 25, 2022  | XXE Injection                  | XXE-6          | Exploiting blind XXE to retrieve data via error messages
Dec 25, 2022  | XXE Injection                  | XXE-7          | Exploiting XInclude to retrieve files
Dec 25, 2022  | XXE Injection                  | XXE-8          | Exploiting XXE via image file upload
Dec 25, 2022  | XXE Injection                  | XXE-9          | Exploiting XXE to retrieve data by repurposing a local DTD
Dec 26, 2022  | JWT                            | JWT-1          | JWT authentication bypass via unverified signature
Dec 26, 2022  | JWT                            | JWT-2          | JWT authentication bypass via flawed signature verification
Dec 26, 2022  | JWT                            | JWT-3          | JWT authentication bypass via weak signing key
Dec 26, 2022  | JWT                            | JWT-4          | JWT authentication bypass via jwk header injection
Dec 26, 2022  | JWT                            | JWT-5          | JWT authentication bypass via jku header injection
Dec 26, 2022  | JWT                            | JWT-6          | JWT authentication bypass via kid header path traversal
Dec 26, 2022  | JWT                            | JWT-7          | JWT authentication bypass via algorithm confusion
Dec 26, 2022  | JWT                            | JWT-8          | JWT authentication bypass via algorithm confusion with no exposed key