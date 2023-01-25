# URL normalization

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-normalization), you'll learn: URL normalization! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab contains an XSS vulnerability that is not directly exploitable due to browser URL-encoding.

To solve the lab, take advantage of the cache's normalization process to exploit this vulnerability. Find the XSS vulnerability and inject a payload that will execute `alert(1)` in the victim's browser. Then, deliver the malicious URL to the victim.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125193523.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125193539.png)

In here, we see that the web application is using caches to cache the web content.

**Let's try to go to an non-existence path:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125195318.png)

As you can see, our provided path is reflected to the web page!

**Let's try to inject an XSS payload:**
```html
/doesnt-exist</p><script>alert(1)</script>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125195559.png)

Hmm... It doesn't work, as the payload is URL encoded...

This is because modern browsers typically URL-encode the necessary characters when sending the request, and the server doesn't decode them. The response that the intended victim receives will merely contain a harmless URL-encoded string.

Luckly, some caching implementations normalize keyed input when adding it to the cache key. In this case, both of the following requests would have the same key:

```html
GET /doesnt-exist</p><script>alert(1)</script>
GET /doesnt-exist%3C/p%3E%3Cscript%3Ealert(1)%3C/script%3E
```

This behavior can allow us to exploit these otherwise "unexploitable" XSS vulnerabilities. If we send a malicious request using Burp Repeater, we can poison the cache with an unencoded XSS payload. When the victim visits the malicious URL, the payload will still be URL-encoded by their browser; however, once the URL is normalized by the cache, it will have the same cache key as the response containing our unencoded payload.

As a result, the cache will serve the poisoned response and the payload will be executed client-side. We just need to make sure that the cache is poisoned when the victim visits the URL.

**To do that, we can use Burp Suite's Repeater and poison the cache with our XSS payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125195820.png)

As you can see, our payload doesn't get URL encoded.

**Now, if we go to our payload again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125195907.png)

It triggered an reflected XSS!!

It is executed because the browser's encoded payload was URL-decoded by the cache, causing a cache hit with the earlier request.

Finally, we can let the victim to visit our **poisoned URL**, and trigger our XSS payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Poisoning/Cache-9/images/Pasted%20image%2020230125200321.png)

# What we've learned:

1. URL normalization