# Exploiting path delimiters for web cache deception

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1 [Delimiter Discrepancies](#delimiter-discrepancies)  
    3.2 [Exploiting Delimiter Discrepancies](#exploiting-delimiter-discrepancies)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-path-delimiters), you'll learn: Exploiting path delimiters for web cache deception! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

To solve the lab, find the API key for the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`.

We have provided a list of possible delimiter characters to help you solve the lab: [Web cache deception lab delimiter list](https://portswigger.net/web-security/web-cache-deception/wcd-lab-delimiter-list).

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810151153.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810151229.png)

In here, we can see that **some static resources were cached**. Maybe we could do something with this.

Login page:

Let's login as user `wiener`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810151402.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810151421.png)

After logging in, we can see our API key.

In this lab, our goal is to steal user `carlos`'s API key.

In the previous lab, we leveraged the discrepancies between the RESTful URL path mapping and cache path mapping.

Are there anymore ways to abuse this type of discrepancies to exploit web cache deception?

### Delimiter Discrepancies

Delimiters specify boundaries between different elements in URLs. The use of characters and strings as delimiters is generally standardized. For example, `?` is generally used to separate the URL path from the query string. However, as the URI RFC is quite permissive, variations still occur between different frameworks or technologies.

Discrepancies in how the cache and origin server use characters and strings as delimiters can result in web cache deception vulnerabilities. Consider the example `/profile;foo.css`:

- The Java Spring framework uses the `;` character to add parameters known as matrix variables. An origin server that uses Java Spring would therefore interpret `;` as a delimiter. It truncates the path after `/profile` and returns profile information.
- Most other frameworks don't use `;` as a delimiter. Therefore, a cache that doesn't use Java Spring is likely to interpret `;` and everything after it as part of the path. If the cache has a rule to store responses for requests ending in `.css`, it might cache and serve the profile information as if it were a CSS file.

The same is true for other characters that are used inconsistently between frameworks or technologies. Consider these requests to an origin server running the Ruby on Rails framework, which uses `.` as a delimiter to specify the response format:

- `/profile` - This request is processed by the default HTML formatter, which returns the user profile information.
- `/profile.css` - This request is recognized as a CSS extension. There isn't a CSS formatter, so the request isn't accepted and an error is returned.
- `/profile.ico` - This request uses the `.ico` extension, which isn't recognized by Ruby on Rails. The default HTML formatter handles the request and returns the user profile information. In this situation, if the cache is configured to store responses for requests ending in `.ico`, it would cache and serve the profile information as if it were a static file.

Encoded characters may also sometimes be used as delimiters. For example, consider the request `/profile%00foo.js`:

- The OpenLiteSpeed server uses the encoded null `%00` character as a delimiter. An origin server that uses OpenLiteSpeed would therefore interpret the path as `/profile`.
- Most other frameworks respond with an error if `%00` is in the URL. However, if the cache uses Akamai or Fastly, it would interpret `%00` and everything after it as the path.

### Exploiting Delimiter Discrepancies

We may be able to use a delimiter discrepancy to add a static extension to the path that is viewed by the cache, but not the origin server. To do this, we'll need to identify a character that is used as a delimiter by the origin server but not the cache.

Firstly, find characters that are used as delimiters by the origin server. Start this process by adding an arbitrary string to the URL of our target endpoint. For example, modify `/settings/users/list` to `/settings/users/listaaa`. We'll use this response as a reference when we start testing delimiter characters.

> Note
>  
> If the response is identical to the original response, this indicates that the request is being redirected. We'll need to choose a different endpoint to test.

Next, add a possible delimiter character between the original path and the arbitrary string, for example `/settings/users/list;aaa`:

- If the response is identical to the base response, this indicates that the `;` character is used as a delimiter and the origin server interprets the path as `/settings/users/list`.
- If it matches the response to the path with the arbitrary string, this indicates that the `;` character isn't used as a delimiter and the origin server interprets the path as `/settings/users/list;aaa`.

Once we've identified delimiters that are used by the origin server, test whether they're also used by the cache. To do this, add a static extension to the end of the path. If the response is cached, this indicates:

- That the cache doesn't use the delimiter and interprets the full URL path with the static extension.
- That there is a cache rule to store responses for requests ending in `.js`.

Make sure to test all ASCII characters and a range of common extensions, including `.css`, `.ico`, and `.exe`. Use Burp Intruder to quickly test these characters. To prevent Burp Intruder from encoding the delimiter characters, turn off Burp Intruder's automated character encoding under **Intruder > Payloads > Payload encoding**.

We can then construct an exploit that triggers the static extension cache rule. For example, consider the payload `/settings/users/list;aaa.js`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/settings/users/list;aaa.js`
- The origin server interprets the path as: `/settings/users/list`

The origin server returns the dynamic profile information, which is stored in the cache.

Because delimiters are generally used consistently within each server, we can often use this attack on many different endpoints.

> Note
>  
> Some delimiter characters may be processed by the victim's browser before it forwards the request to the cache. This means that some delimiters can't be used in an exploit. For example, browsers URL-encode characters like `{`, `}`, `<`, and `>`, and use `#` to truncate the path.
>  
> If the cache or origin server decodes these characters, it may be possible to use an encoded version in an exploit.

Let's try this!

First, we'll need to find the characters that are used as delimiters by the origin server. To do so, we can adding an arbitrary string to the URL of our target endpoint, such as from `/my-account` to `/my-accountfoobar`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152104.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152117.png)

As we can see, if we append arbitrary string to `/my-account`, the server respond HTTP status code "404 Not Found".

Now, if we insert an arbitrary string between `/my-account` and `foobar`, **non HTTP status code "404 Not Found" is the delimiter by the origin server**.

To find the delimiter, we can fuzz the path via Burp Suite's Intruder:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152721.png)

Then, copy and paste the delimiter characters into the payload settings:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152823.png)

Next, uncheck payload encoding:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152920.png)

Finally, click "Start attack":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810152945.png)

After fuzzing, we can see that characters `;` and `?` respond HTTP status code "200 OK":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153205.png)

Since `?` is the URL query syntax, we can ignore that. Therefore, **character `;` is the delimiter by the origin server**.

Now we found that the delimiter is `;`, we can process to find which extensions are used by the cache.

To do so, we can fuzz the extensions, such as `.js`, `.css`, `.ico`, and more. After trying, we can see the `.js` indeed get cached:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153515.png)

Which contains the API key:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153525.png)

## Exploitation

Armed with the above information, we can steal `carlos`'s API key via:
1. Trick the victim to visit `/my-account;foobar.js` to cache the API key response
2. We, attacker, go to `/my-account;foobar.js` to get the cached response

We can try to test this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153744.png)

> Note: The `cachebuster` parameter is for testing purposes.

Then, before the cache expired, remove the `Cookie` request header and send the request again:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153841.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810153851.png)

Nice!

Now we can go to our exploit server, and change the response header to this:

```http
HTTP/1.1 301 Moved Permanently
Location: https://0a2f00fa047523c9809db26c00c4003d.web-security-academy.net/my-account;foobar.js
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810154001.png)

Then click button "Deliver exploit to victim". This will trick the victim to cache their API key response:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810154047.png)

Finally, send the following request to retrieve the cached response:

```http
GET /my-account;foobar.js HTTP/2
Host: 0a2f00fa047523c9809db26c00c4003d.web-security-academy.net


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810155422.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810155433.png)

We got `carlos`'s API key! Let's submit it to solve this lab!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810155451.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810155504.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-Cache-Deception/WCD-2/images/Pasted%20image%2020240810155514.png)

## Conclusion

What we've learned:

1. Exploiting path delimiters for web cache deception