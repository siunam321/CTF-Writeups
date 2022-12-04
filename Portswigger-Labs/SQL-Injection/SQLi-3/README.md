# SQL injection UNION attack, determining the number of columns returned by the query

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns), you'll learn: SQL injection UNION attack, determining the number of columns returned by the query! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.

To solve the lab, determine the number of columns returned by the query by performing an [SQL injection UNION](https://portswigger.net/web-security/sql-injection/union-attacks) attack that returns an additional row containing null values.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204013100.png)

```html
					[...]
                    <section class="search-filters">
                        <label>Refine your search:</label>
                        <a href="/">All</a>
                        <a href="/filter?category=Clothing%2c+shoes+and+accessories">Clothing, shoes and accessories</a>
                        <a href="/filter?category=Corporate+gifts">Corporate gifts</a>
                        <a href="/filter?category=Food+%26+Drink">Food & Drink</a>
                        <a href="/filter?category=Lifestyle">Lifestyle</a>
                        <a href="/filter?category=Toys+%26+Games">Toys & Games</a>
                    </section>
                    <table class="is-table-numbers">
                        <tbody>
                        <tr>
                            <th>Dancing In The Dark</th>
                            <td>$99.37</td>
                            <td><a class="button is-small" href="/product?productId=5">View details</a></td>
                        </tr>
                        [...]
```

As you can see, **there are 2 pages in here: `filter` and `product`.**

**In the lab background, it said: `an SQL injection vulnerability in the product category filter`.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204013337.png)

Let's click one of those filters!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204013403.png)

We can see that there is a GET parameter called `category`.

**Let's try to enumerate the column numbers via `ORDER BY` clause!**
```sql
/filter?category=' ORDER BY 4-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204013558.png)

When we **`ORDER BY` 4 indexes**, it returns a `500 Internal Server Error` HTTP status.

However, when we **`ORDER BY` 3 indexes**:

```sql
/filter?category=' ORDER BY 3-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204013736.png)

It has no error!

Which means we found **the number of columns is 3!!**

**If you prefer using other method, you can use the `UNION` clause:**

```sql
/filter?category=' UNION SELECT NULL,NULL,NULL,NULL-- -
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204014130.png)

**When we selected 4 columns, it outputs `Internal Server Error`.**

**When we select 3 columns:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-3/images/Pasted%20image%2020221204014036.png)

**It outputs normally, which means we found the number of columns is 3!**

# Conclusion

What we've learned:

1. SQL injection UNION attack, determining the number of columns returned by the query