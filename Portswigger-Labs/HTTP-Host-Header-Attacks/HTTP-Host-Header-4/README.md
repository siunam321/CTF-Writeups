# Routing-based SSRF

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/host-header/exploiting/lab-host-header-routing-based-ssrf), you'll learn: Routing-based SSRF! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab is vulnerable to routing-based [SSRF](https://portswigger.net/web-security/ssrf) via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

To solve the lab, access the internal admin panel located in the `192.168.0.0/24` range, then delete Carlos.

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195129.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195600.png)

When we go to `/`, it'll redirect us to `/`.

Now, we can try to test routing-based SSRF.

### Routing-based SSRF

It is sometimes also possible to use the Host header to launch high-impact, routing-based SSRF attacks. These are sometimes known as "Host header SSRF attacks", and were explored in depth by PortSwigger Research in [Cracking the lens: targeting HTTP's hidden attack-surface](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface).

Classic SSRF vulnerabilities are usually based on [XXE](https://portswigger.net/web-security/xxe) or exploitable business logic that sends HTTP requests to a URL derived from user-controllable input. Routing-based SSRF, on the other hand, relies on exploiting the intermediary components that are prevalent in many cloud-based architectures. This includes in-house load balancers and reverse proxies.

Although these components are deployed for different purposes, fundamentally, they receive requests and forward them to the appropriate back-end. If they are insecurely configured to forward requests based on an unvalidated Host header, they can be manipulated into misrouting requests to an arbitrary system of the attacker's choice.

These systems make fantastic targets. They sit in a privileged network position that allows them to receive requests directly from the public web, while also having access to much, if not all, of the internal network. This makes the Host header a powerful vector for SSRF attacks, potentially transforming a simple load balancer into a gateway to the entire internal network.

You can use Burp Collaborator to help identify these vulnerabilities. If you supply the domain of your Collaborator server in the Host header, and subsequently receive a DNS lookup from the target server or another in-path system, this indicates that you may be able to route requests to arbitrary domains.

Having confirmed that you can successfully manipulate an intermediary system to route your requests to an arbitrary public server, the next step is to see if you can exploit this behavior to access internal-only systems. To do this, you'll need to identify private IP addresses that are in use on the target's internal network. In addition to any IP addresses that are leaked by the application, you can also scan hostnames belonging to the company to see if any resolve to a private IP address. If all else fails, you can still identify valid IP addresses by simply brute-forcing standard private IP ranges, such as `192.168.0.0/16`.

> CIDR notation:
>  
> IP address ranges are commonly expressed using CIDR notation, for example, `192.168.0.0/16`.
>  
> IPv4 addresses consist of four 8-bit decimal values known as "octets", each separated by a dot. The value of each octet can range from 0 to 255, meaning that the lowest possible IPv4 address would be `0.0.0.0` and the highest `255.255.255.255`.
>  
> In CIDR notation, the lowest IP address in the range is written explicitly, followed by another number that indicates how many bits from the start of the given address are fixed for the entire range. For example, `10.0.0.0/8` indicates that the first 8 bits are fixed (the first octet). In other words, this range includes all IP addresses from `10.0.0.0` to `10.255.255.255`.

Armed with above information, we can try to detect routing-based SSRF.

**To do so, I'll:**

- Go to Burp Suite's Collaborator, and copy the payload:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195536.png)

- Send the "200 OK" HTTP status code `/` request to Burp Repeater:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195702.png)

- Modfiy the `Host` header to your payload one, and send it:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195751.png)

- Go back to Burp Suite's Collaborator, and click "Poll now":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301195827.png)

In here, we received 2 DNS lookups and 1 HTTP request.

That being said, we're able to make the website's middleware issue requests to an arbitrary server.

**According to the lab's background, it said:**

> To solve the lab, access the internal admin panel located in the `192.168.0.0/24` range, then delete Carlos.

So, **we can change the `Host` header's value to `192.168.0.x`**. If we didn't get "504 Gateway Timeout" HTTP status code, we found the internal admin panel:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301200136.png)

**To automate that process, we can write use Burp Suite's Intruder:**

- Send the `GET /` request to Burp Intruder:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205427.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205447.png)

- Clear all payload position:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205525.png)

- Add a payload position to the final octet:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205615.png)

- Uncheck the "Update Host header to match target" option:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205846.png)

- On the "Payloads" tab, select the payload type "Numbers". Under "Payload settings", enter the following values:

```
From: 1
To: 254
Step: 1
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205711.png)

- Click "Start attack":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205730.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301205955.png)

**Nice! We found the internal admin panel in `192.168.0.207`!**

When we go to `192.168.0.207`, it'll redirect us to `/admin`.

**Let's go there:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301210128.png)

In here, we delete users!

When we clicked the "Submit" button, it'll send a POST request to `/admin/delete`, with parameter `csrf`, `username`.

**Armed with above information, we can delete user `carlos` with the following request!**
```http
POST /admin/delete HTTP/1.1
Host: 192.168.0.207
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

csrf=6uwuOhW7H12BOLEi8t0iPn1nGq4MtFVj&username=carlos
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301210303.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/HTTP-Host-Header-Attacks/HTTP-Host-Header-4/images/Pasted%20image%2020230301210311.png)

# What we've learned:

1. Routing-based SSRF