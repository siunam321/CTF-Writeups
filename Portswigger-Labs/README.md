All my Portswigger Labs writeups will be here.

Date	 	  | Category                      | Directory Name | Lab Title
--------------|-------------------------------|----------------|----------------------
Dec 3, 2022   | SQL Injection                 | SQLi-1         | SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
Dec 3, 2022   | SQL Injection                 | SQLi-2         | SQL injection vulnerability allowing login bypass
Dec 4, 2022   | SQL Injection                 | SQLi-3         | SQL injection UNION attack, determining the number of columns returned by the query
Dec 4, 2022   | SQL Injection                 | SQLi-4         | SQL injection UNION attack, finding a column containing text
Dec 4, 2022   | SQL Injection                 | SQLi-5         | SQL injection UNION attack, retrieving data from other tables
Dec 4, 2022   | SQL Injection                 | SQLi-6         | SQL injection UNION attack, retrieving multiple values in a single column
Dec 4, 2022   | SQL Injection                 | SQLi-7         | SQL injection attack, querying the database type and version on Oracle
Dec 5, 2022   | SQL Injection                 | SQLi-8         | SQL injection attack, querying the database type and version on MySQL and Microsoft
Dec 5, 2022   | SQL Injection                 | SQLi-9         | SQL injection attack, listing the database contents on non-Oracle databases
Dec 5, 2022   | SQL Injection                 | SQLi-10        | SQL injection attack, listing the database contents on Oracle
Dec 6, 2022   | SQL Injection                 | SQLi-11        | Blind SQL injection with conditional responses
Dec 7, 2022   | SQL Injection                 | SQLi-12        | Blind SQL injection with conditional errors
Dec 9, 2022   | SQL Injection                 | SQLi-13        | Blind SQL injection with time delays
Dec 8, 2022   | SQL Injection                 | SQLi-14        | Blind SQL injection with time delays and information retrieval
Dec 11, 2022  | SQL Injection                 | SQLi-17        | SQL injection with filter bypass via XML encoding
Dec 12, 2022  | Directory Traversal           | DT-1           | File path traversal, simple case
Dec 12, 2022  | Directory Traversal           | DT-2           | File path traversal, traversal sequences blocked with absolute path bypass
Dec 12, 2022  | Directory Traversal           | DT-3           | File path traversal, traversal sequences stripped non-recursively
Dec 12, 2022  | Directory Traversal           | DT-4           | File path traversal, traversal sequences stripped with superfluous URL-decode
Dec 12, 2022  | Directory Traversal           | DT-5           | File path traversal, validation of start of path
Dec 12, 2022  | Directory Traversal           | DT-6           | File path traversal, validation of file extension with null byte bypass
Dec 12, 2022  | Access Control                | AC-1           | Unprotected admin functionality
Dec 12, 2022  | Access Control                | AC-2           | Unprotected admin functionality with unpredictable URL
Dec 12, 2022  | Access Control                | AC-3           | User role controlled by request parameter
Dec 12, 2022  | Access Control                | AC-4           | User role can be modified in user profile
Dec 14, 2022  | Access Control                | AC-5           | User ID controlled by request parameter
Dec 14, 2022  | Access Control                | AC-6           | User ID controlled by request parameter, with unpredictable user IDs
Dec 14, 2022  | Access Control                | AC-7           | User ID controlled by request parameter with data leakage in redirect
Dec 14, 2022  | Access Control                | AC-8           | User ID controlled by request parameter with password disclosure
Dec 14, 2022  | Access Control                | AC-9           | Insecure direct object references
Dec 14, 2022  | Access Control                | AC-10          | URL-based access control can be circumvented
Dec 14, 2022  | Access Control                | AC-11          | Method-based access control can be circumvented
Dec 14, 2022  | Access Control                | AC-12          | Multi-step process with no access control on one step
Dec 14, 2022  | Access Control                | AC-13          | Referer-based access control
Dec 15, 2022  | CSRF                          | CSRF-1         | CSRF vulnerability with no defenses
Dec 15, 2022  | CSRF                          | CSRF-2         | CSRF where token validation depends on request method
Dec 15, 2022  | CSRF                          | CSRF-3         | CSRF where token validation depends on token being present
Dec 15, 2022  | CSRF                          | CSRF-4         | CSRF where token is not tied to user session
Dec 15, 2022  | CSRF                          | CSRF-5         | CSRF where token is tied to non-session cookie
Dec 15, 2022  | CSRF                          | CSRF-6         | CSRF where token is duplicated in cookie
Dec 15, 2022  | CSRF                          | CSRF-7         | CSRF where Referer validation depends on header being present
Dec 15, 2022  | CSRF                          | CSRF-8         | CSRF with broken Referer validation
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-1          | Remote code execution via web shell upload
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-2          | Web shell upload via Content-Type restriction bypass
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-3          | Web shell upload via path traversal
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-4          | Web shell upload via extension blacklist bypass
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-5          | Web shell upload via obfuscated file extension
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-6          | Remote code execution via polyglot web shell upload
Dec 16, 2022  | File Upload Vulnerabilities   | FUV-7          | Web shell upload via race condition
Dec 16, 2022  | Information Disclosure        | ID-1           | Information disclosure in error messages
Dec 16, 2022  | Information Disclosure        | ID-2           | Information disclosure on debug page
Dec 16, 2022  | Information Disclosure        | ID-3           | Source code disclosure via backup files
Dec 16, 2022  | Information Disclosure        | ID-4           | Authentication bypass via information disclosure
Dec 16, 2022  | Information Disclosure        | ID-5           | Information disclosure in version control history