# Multi-endpoint race conditions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint), you'll learn: Multi-endpoint race conditions! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

This lab's purchasing flow contains a race condition that enables you to purchase items for an unintended price.

To solve the lab, successfully purchase a **Lightweight L33t Leather Jacket**.

You can log into your account with the following credentials: `wiener:peter`.

> Note
>  
> Solving this lab requires Burp Suite 2023.9 or higher.

> Tip
>  
> When experimenting, we recommend purchasing the gift card as you can later redeem this to avoid running out of store credit.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831171112.png)

In here, we can purchase some items.

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831171339.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831171911.png)

In the home and profile page, we can purchase **gift cards**.

Let's try to buy 1:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172107.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172120.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172154.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172201.png)

**Then, we can go to our profile page to redeem the gift card:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172251.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172305.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172349.png)

When we clicked the "Redeem" button, it'll send a POST request to `/gift-card` with parameter `csrf` and `gift-card`. After successful redeem, it'll redirect us back to `/my-account`, which is our profile page.

Hmm... The `/gift-card` endpoint sounds interesting. **If it has vulnerability, we can abuse that to gain infinite amount of store credit**! 

Let's test for race condition vulnerability!

**Now, what if we send the `/gift-card` POST request again?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172713.png)

It respond "Invalid gift card". So **it's validating the gift card**.

**Also, if we remove the session cookie, it'll response "Unauthorized":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831172921.png)

So the `/gift-card` endpoint is **validating the user's session**.

- **Benchmark how the endpoint behaves under normal conditions with "Send group in sequence (separate connections)" option:**

**First request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831173511.png)

**Second request and so on:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831173532.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831173542.png)

It behaved as expected. In the first request, the gift card is redeemed, and the rest of the request shouldn't able to redeem it again. 

- **Send the same group of requests at once using the single-packet attack to minimize network jitter:**

**First request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831173750.png)

**Second request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831173807.png)

Same... Maybe `/gift-card` POST endpoint doesn't vulnerable to race condition?

How about **the process of buying gift cards**?

**In there, we can test for hidden multi-step sequences in POST endpoint `/cart` and `/cart/checkout`.**

In practice, a single request may initiate an entire multi-step sequence behind the scenes, transitioning the application through multiple hidden states that it enters and then exits again before request processing is complete. We'll refer to these as "sub-states".

If you can identify one or more HTTP requests that cause an interaction with the same data, you can potentially abuse these sub-states to expose time-sensitive variations of the kinds of logic flaws that are common in multi-step workflows. This enables race condition exploits that go far beyond limit overruns.

For example, you may be familiar with flawed multi-factor authentication (MFA) workflows that let you perform the first part of the login using known credentials, then navigate straight to the application via forced browsing, effectively bypassing MFA entirely.

The following pseudo-code demonstrates how a website could be vulnerable to a race variation of this attack:

```python
    session['userid'] = user.userid
    if user.mfa_enabled:
        session['enforce_mfa'] = True
        # generate and send MFA code to user
        # redirect browser to MFA code entry form
```

As you can see, this is in fact a multi-step sequence within the span of a single request. Most importantly, it transitions through a sub-state in which the user temporarily has a valid logged-in session, but MFA isn't yet being enforced. An attacker could potentially exploit this by sending a login request along with a request to a sensitive, authenticated endpoint.

To detect and exploit hidden multi-step sequences, we recommend the following methodology, which is summarized from the whitepaper [Smashing the state machine: The true potential of web race conditions](https://portswigger.net/research/smashing-the-state-machine) by PortSwigger Research.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831185101.png)

**1 - Predict potential collisions:**

Testing every endpoint is impractical. After mapping out the target site as normal, you can reduce the number of endpoints that you need to test by asking yourself the following questions:

- **Is this endpoint security critical?** Many endpoints don't touch critical functionality, so they're not worth testing.
- **Is there any collision potential?** For a successful collision, you typically need two or more requests that trigger operations on the same record. For example, consider the following variations of a password reset implementation:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831185123.png)

With the first example, requesting parallel password resets for two different users is unlikely to cause a collision as it results in changes to two different records. However, the second implementation enables you to edit the same record with requests for two different users.

**2 - Probe for clues:**

To recognize clues, you first need to benchmark how the endpoint behaves under normal conditions. You can do this in Burp Repeater by grouping all of your requests and using the **Send group in sequence (separate connections)** option. For more information, see [Sending requests in sequence](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group#sending-requests-in-sequence).

Next, send the same group of requests at once using the single-packet attack (or last-byte sync if HTTP/2 isn't supported) to minimize network jitter. You can do this in Burp Repeater by selecting the **Send group in parallel** option. For more information, see [Sending requests in parallel](https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group#sending-requests-in-parallel). Alternatively, you can use the Turbo Intruder extension, which is available from the [BApp Store](https://portswigger.net/bappstore/9abaa233088242e8be252cd4ff534988).

Anything at all can be a clue. Just look for some form of deviation from what you observed during benchmarking. This includes a change in one or more responses, but don't forget second-order effects like different email contents or a visible change in the application's behavior afterward.

**3 - Prove the concept:**

Try to understand what's happening, remove superfluous requests, and make sure you can still replicate the effects.

Advanced race conditions can cause unusual and unique primitives, so the path to maximum impact isn't always immediately obvious. It may help to think of each race condition as a structural weakness rather than an isolated vulnerability.

Perhaps the most intuitive form of these race conditions are those that involve sending requests to multiple endpoints at the same time.

Think about the classic logic flaw in online stores where you add an item to your basket or cart, pay for it, then add more items to the cart before force-browsing to the order confirmation page.

A variation of this vulnerability can occur when payment validation and order confirmation are performed during the processing of a single request. The state machine for the order status might look something like this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831185231.png)

In this case, you can potentially add more items to your basket during the race window between when the payment is validated and when the order is finally confirmed.

**Now, what if I added another gift card while checkout, what will happened?**

- **Test for under normal conditions:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175144.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175159.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175209.png)

Working as expected, purchased a gift card, and another gift card is added to the basket.

- **Single-packet attack:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175819.png)

Nope. No addition gift card order is being placed. 

**Aligning multi-endpoint race windows:**

When testing for multi-endpoint race conditions, you may encounter issues trying to line up the race windows for each request, even if you send them all at exactly the same time using the single-packet technique.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831185256.png)

This common problem is primarily caused by the following two factors:

- **Delays introduced by network architecture -** For example, there may be a delay whenever the front-end server establishes a new connection to the back-end. The protocol used can also have a major impact.
- **Delays introduced by endpoint-specific processing -** Different endpoints inherently vary in their processing times, sometimes significantly so, depending on what operations they trigger.

Fortunately, there are potential workarounds to both of these issues.

**Connection warming:**

Back-end connection delays don't usually interfere with race condition attacks because they typically delay parallel requests equally, so the requests stay in sync.

It's essential to be able to distinguish these from delays from those caused by endpoint-specific factors. One way to do this is by "warming" the connection with one or more inconsequential requests to see if this smoothes out the remaining processing times. In Burp Repeater, you can try adding a `GET` request for the homepage to the start of your tab group, then using the **Send group in sequence (single connection)** option.

If the first request still has a longer processing time, but the rest of the requests are now processed within a short window, you can ignore the apparent delay and continue testing as normal.

If you still see inconsistent response times on a single endpoint, even when using the single-packet technique, this is an indication that the back-end delay is interfering with your attack. You may be able to work around this by using Turbo Intruder to send some connection warming requests before following up with your main attack requests.

- **Perform connection warming:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175928.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175941.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831175953.png)

As you can see, in `/cart` POST endpoint, it took a lot longer than the `/checkout` endpoint. Which means this delay is caused by the back-end network architecture rather than the respective processing time of the each endpoint. Therefore, it is not likely to interfere with our attack.

**After some trial and error, when we try to purchase an item that we don't have enough store credit, it'll redirect us to `/cart?err=INSUFFICIENT_FUNDS`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831181745.png)

Hmm... I wonder **what if we can bypass that restriction**...

**So, if I have 1 gift card in the basket (Any items that fits well with our store credit), then place the order, add an item that exceeds our store credit, and finally place the order again. Will that bypass the restriction and purchase the insufficient store credit item?**

- Create 2 groups:

**Group 1 - Buy jacket:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831183929.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831183943.png)

**Group 2 - Buy gift card:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831184003.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831184010.png)

- Keep sending both groups in parallel until the restriction has been bypassed:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-3/images/Pasted%20image%2020230831184108.png)

Nice! We successfully bypassed the restriction!

## Conclusion

What we've learned:

1. Multi-endpoint race conditions