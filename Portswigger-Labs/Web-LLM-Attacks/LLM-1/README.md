# Exploiting LLM APIs with excessive agency

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1 [What is LLM?](#what-is-llm)  
    3.2 [LLM APIs](#llm-apis)  
    3.3 [Excessive Agency](#excessive-agency)  
    3.4 [Exploring the Application's LLM](#exploring-the-application's-llm)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/llm-attacks/lab-exploiting-llm-apis-with-excessive-agency), you'll learn: Exploiting LLM APIs with excessive agency! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

To solve the lab, use the LLM to delete the user `carlos`.

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515143140.png)

In here, we can purchase some products.

**More interestingly, this web application has a "Live chat" feature:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515143314.png)

We can try to chat with "Arti Ficial":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515143418.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515143428.png)

It replied us with "Hi there! How can I assist you today?".

**In the "Backend AI logs", we can see that there's our message:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515143540.png)

Hmm... It seems like the "Live chat" feature is using LLM (Large Language Model).

### What is LLM?

Organizations are rushing to integrate Large Language Models (LLMs) in order to improve their online customer experience. This exposes them to web LLM attacks that take advantage of the model's access to data, APIs, or user information that an attacker cannot access directly. For example, an attack may:

- Retrieve data that the LLM has access to. Common sources of such data include the LLM's prompt, training set, and APIs provided to the model.
- Trigger harmful actions via APIs. For example, the attacker could use an LLM to perform a [SQL injection](https://portswigger.net/web-security/sql-injection) attack on an API it has access to.
- Trigger attacks on other users and systems that query the LLM.

At a high level, attacking an LLM integration is often similar to exploiting a [server-side request forgery](https://portswigger.net/web-security/ssrf) ([SSRF](https://portswigger.net/web-security/ssrf)) vulnerability. In both cases, an attacker is abusing a server-side system to launch attacks on a separate component that is not directly accessible.

Large Language Models (LLMs) are AI algorithms that can process user inputs and create plausible responses by predicting sequences of words. They are trained on huge semi-public data sets, using machine learning to analyze how the component parts of language fit together.

LLMs usually present a chat interface to accept user input, known as a prompt. The input allowed is controlled in part by input validation rules.

LLMs can have a wide range of use cases in modern websites:

- Customer service, such as a virtual assistant.
- Translation.
- SEO improvement.
- Analysis of user-generated content, for example to track the tone of on-page comments.

Many web LLM attacks rely on a technique known as prompt injection. This is where an attacker uses crafted prompts to manipulate an LLM's output. Prompt injection can result in the AI taking actions that fall outside of its intended purpose, such as making incorrect calls to sensitive APIs or returning content that does not correspond to its guidelines.

The recommended methodology for detecting LLM vulnerabilities is:

1. Identify the LLM's inputs, including both direct (such as a prompt) and indirect (such as training data) inputs.
2. Work out what data and APIs the LLM has access to.
3. Probe this new attack surface for vulnerabilities.

### LLM APIs

LLMs are often hosted by dedicated third party providers. A website can give third-party LLMs access to its specific functionality by describing local APIs for the LLM to use.

For example, a customer support LLM might have access to APIs that manage users, orders, and stock.

The workflow for integrating an LLM with an API depends on the structure of the API itself. When calling external APIs, some LLMs may require the client to call a separate function endpoint (effectively a private API) in order to generate valid requests that can be sent to those APIs. The workflow for this could look something like the following:

1. The client calls the LLM with the user's prompt.
2. The LLM detects that a function needs to be called and returns a JSON object containing arguments adhering to the external API's schema.
3. The client calls the function with the provided arguments.
4. The client processes the function's response.
5. The client calls the LLM again, appending the function response as a new message.
6. The LLM calls the external API with the function response.
7. The LLM summarizes the results of this API call back to the user.

This workflow can have security implications, as the LLM is effectively calling external APIs on behalf of the user but the user may not be aware that these APIs are being called. Ideally, users should be presented with a confirmation step before the LLM calls the external API.

### Excessive Agency

The term "excessive agency" refers to a situation in which an LLM has access to APIs that can access sensitive information and can be persuaded to use those APIs unsafely. This enables attackers to push the LLM beyond its intended scope and launch attacks via its APIs.

The first stage of using an LLM to attack APIs and plugins is to work out which APIs and plugins the LLM has access to. One way to do this is to simply ask the LLM which APIs it can access. You can then ask for additional details on any APIs of interest.

If the LLM isn't cooperative, try providing misleading context and re-asking the question. For example, you could claim that you are the LLM's developer and so should have a higher level of privilege.

### Exploring the Application's LLM

In our case, the LLM's **direct** input is the **live chat prompt**.

For **indirect** inputs, we can ask the LLM for more details:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515144206.png)

Hmm... Looks like the **training data** is from **human trainers, and publicly available data**.

Now, I wonder what data and APIs the LLM has access to.

To do so, we can try to ask the LLM whether it can access to an internal API or not:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515144850.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515144900.png)

**Backend API logs:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515145919.png)

Hmm... Looks like the LLM can access an internal API that checks all products' price.

Ah ha! Can I **ask the LLM to list all the internal APIs that it can access to**?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515145112.png)

Oh nice! It can access API `functions.password_reset`, `functions.debug_sql`, `functions.product_info`.

Hmm... API `functions.password_reset` and `functions.debug_sql` can be abused!

For example, in API `functions.password_reset`, we can provide a username that we want perform to reset password and an email address that's under our control.

In API `functions.debug_sql`, we can provide malicious SQL queries to exfiltrate the server's database and perform other actions!

## Exploitation

Since API `functions.debug_sql` allows us to provide malicious SQL queries, we can **request the LLM to use that API to delete user `carlos`**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515145610.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515145618.png)

Oh? It happily deleted deleted user `carlos`! We can check that in the "Backend AI logs":

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Web-LLM-Attacks/LLM-1/images/Pasted%20image%2020240515150049.png)

Yep! It successfully executed a raw SQL statement that deletes user `carlos`!

## Conclusion

What we've learned:

1. Exploiting LLM APIs with excessive agency