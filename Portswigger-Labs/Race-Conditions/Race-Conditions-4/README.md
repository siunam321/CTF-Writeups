# Single-endpoint race conditions

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint), you'll learn: Single-endpoint race conditions! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

This lab's email change feature contains a race condition that enables you to associate an arbitrary email address with your account.

Someone with the address `carlos@ginandjuice.shop` has a pending invite to be an administrator for the site, but they have not yet created an account. Therefore, any user who successfully claims this address will automatically inherit admin privileges.

To solve the lab:

1. Identify a race condition that lets you claim an arbitrary email address.
2. Change your email address to `carlos@ginandjuice.shop`.
3. Access the admin panel.
4. Delete the user `carlos`

You can log in to your own account with the following credentials: `wiener:peter`.

You also have access to an email client, where you can view all emails sent to `@exploit-<YOUR-EXPLOIT-SERVER-ID>.exploit-server.net` addresses.

> Note
>  
> Solving this lab requires Burp Suite 2023.9 or higher.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908162737.png)

In here, we can purchase some items.

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908162810.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908162826.png)

In the profile page, we can update our own email address.

**Try to update it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908162938.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908162943.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908163017.png)

When we clicked the "Update email" button, it'll send a POST request to `/my-account/change-email`, with parameter `email` and `csrf`.

After that, it'll show a message that telling us **go to our email to confirm the change of e-mail**.

**Email client:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908163153.png)

- Confirm link endpoint: `/confirm-email?user=wiener&token=Q5jCBYgZvCSPhWvF`

**Click on it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908163254.png)

**Refresh our profile page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908163311.png)

In the confirm link endpoint (`/confirm-email`), it has 2 GET parameters - `user` and `token`.

Hmm... **What if I can retrieve `carlos@ginandjuice.shop`'s confirm email token via race condition, more specially, it's single-endpoint race condition...**

Sending parallel requests with different values to a single endpoint can sometimes trigger powerful race conditions.

Consider a password reset mechanism that stores the user ID and reset token in the user's session.

In this scenario, sending two parallel password reset requests from the same session, but with two different usernames, could potentially cause the following collision:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908163822.png)

Note the final state when all operations are complete:

- `session['reset-user'] = victim`
- `session['reset-token'] = 1234`

The session now contains the victim's user ID, but the valid reset token is sent to the attacker.

> **Note:**
>  
> For this attack to work, the different operations performed by each process must occur in just the right order. It would likely require multiple attempts, or a bit of luck, to achieve the desired outcome.

Email address confirmations, or any email-based operations, are generally a good target for single-endpoint race conditions. Emails are often sent in a background thread after the server issues the HTTP response to the client, making race conditions more likely.

Since we don't have control over the `carlos@ginandjuice.shop` email address, we could try to exploit single-endpoint race condition to read/overwrite `carlos`'s email confirm token.

## Exploitation

**Now, what if there's no session cookie in the `/my-account/change-email` POST endpoint?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908164227.png)

As you can see, it redirected us to the login page. Which means **the change email function is tied to our session**.

**Next, we can try to change email address to `carlos@ginandjuice.shop` and the test one in the normal way:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908164829.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908164838.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908164847.png)

As expected, we can only read the test one confirm email.

**Now, what if I send those requests in parallel?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165133.png)

**Oh! We won the race! Let's click the confirm email link!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165224.png)

**Then refresh our profile page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165246.png)

Nice! We now have administrator privilege!

**Let's delete user `carlos`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165313.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Race-Conditions/Race-Conditions-4/images/Pasted%20image%2020230908165321.png)

## Conclusion

What we've learned:

1. Single-endpoint race conditions