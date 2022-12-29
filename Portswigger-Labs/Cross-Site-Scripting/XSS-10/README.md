# DOM XSS in `document.write` sink using source `location.search` inside a select element

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element), you'll learn: DOM XSS in `document.write` sink using source `location.search` inside a select element! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains a [DOM-based cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/dom-based) vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element.

To solve this lab, perform a [cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) attack that breaks out of the select element and calls the `alert` function.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-10/images/Pasted%20image%2020221229073254.png)

Let's view the of those products:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-10/images/Pasted%20image%2020221229073317.png)

In here, we can see there is a `Check stock` button.

**Let's click on it and intercept the request via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-10/images/Pasted%20image%2020221229073420.png)

When we clicked that button, it'll send a POST request to `/product/stock`, with parameter `productId` and `storeId`.

**View source page:**
```html
<form id="stockCheckForm" action="/product/stock" method="POST">
    <input required type="hidden" name="productId" value="1">
    <script>
        var stores = ["London","Paris","Milan"];
        var store = (new URLSearchParams(window.location.search)).get('storeId');
        document.write('<select name="storeId">');
        if(store) {
            document.write('<option selected>'+store+'</option>');
        }
        for(var i=0;i<stores.length;i++) {
            if(stores[i] === store) {
                continue;
            }
            document.write('<option>'+stores[i]+'</option>');
        }
        document.write('</select>');
    </script>
    <button type="submit" class="button">Check stock</button>
</form>
```

**Let's look at the form's JavaScript codes:**

- `store` = our URL GET parameter `storeId`
- If `store` is set, then use `document.write` sink to write `<option>` tag with `storeId`

Since we have control of `storeId` GET parameter, we can try to exploit it.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-10/images/Pasted%20image%2020221229074057.png)

**To do so, we first need to close the `<option>` tag, then we can include our JavaScript `alert()` function:**
```html
</option><script>alert(document.domain)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-10/images/Pasted%20image%2020221229074216.png)

Nice!

# What we've learned:

1. DOM XSS in `document.write` sink using source `location.search` inside a select element