# SQL injection attack, querying the database type and version on MySQL and Microsoft

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft), you'll learn: SQL injection attack, querying the database type and version on MySQL and Microsoft! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

To solve the lab, display the database version string.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205054653.png)

**In the previous labs, we found that there is an SQL injection vulnerability in the product category filter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205054946.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055007.png)

And we found that **there are 2 columns in this table.**

**To find the database version, we need to:**

- Find out which column accepts string data type:

```sql
' UNION SELECT 'string1','string2'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055111.png)

Both are accepting string data type.

- List the DBMS(Database Management System) version via `version()`:

```sql
' UNION SELECT NULL,version()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-8/images/Pasted%20image%2020221205055228.png)

# What we've learned:

1. SQL injection attack, querying the database type and version on MySQL and Microsoft