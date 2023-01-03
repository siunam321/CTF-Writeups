# Authentication bypass via OAuth implicit flow

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow), you'll learn: Authentication bypass via OAuth implicit flow! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

This lab uses an [OAuth](https://portswigger.net/web-security/oauth) service to allow users to log in with their social media account. Flawed validation by the client application makes it possible for an attacker to log in to other users' accounts without knowing their password.

To solve the lab, log in to Carlos's account. His email address is `carlos@carlos-montoya.net`.

You can log in with your own social media account using the following credentials: `wiener:peter`.

## Reconnaissance

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103070826.png)

In here, we can go to the "My account" link to login.

**Let's click that and intercept the requests via Burp Suite:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103070910.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103070922.png)

**When we clicked that link, we'll be redirected to `/social-login`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103071017.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103071029.png)

Then, **it'll send a GET request to `/auth`, with parameter `client_id`, `redirect_uri`, `response_type`, `nonce`, and `scope`. Which indicates that it's using OAuth.**

***Authorization code grant type:***

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103071301.png)

- 1. **Authorization request:**

Now, we've send a request to the OAuth service's `/auth` endpoint asking for permission to access specific user data.

This request contains the following noteworthy parameters, usually provided in the query string:

- `client_id`: Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service. E.g: `e0c7judrkes9yylmlepoc`.
- `redirect_uri`: The URI to which the user's browser should be redirected when sending the authorization code to the client application. This is also known as the "callback URI" or "callback endpoint". Many OAuth attacks are based on exploiting flaws in the validation of this parameter. E.g: `https://0a4e006204b2a307c221668a00be007e.web-security-academy.net/oauth-callback`.
- `response_type`: Determines which kind of response the client application is expecting and, therefore, which flow it wants to initiate. For the authorization code grant type, the value should be `code`. **However, in our case, the value is `token`, which the OAuth is using the implicit grant type.**
- `state` in OAuth 2.0:
    - Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of [CSRF token](https://portswigger.net/web-security/csrf/tokens) for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow. E.g: `-2044005731`.
- `nonce` in OpenID:
    - Binds the tokens with the client. It serves as a token validation parameter. E.g: `-2044005731`.
- `scope`: Used to specify which subset of the user's data the client application wants to access. E.g: `openid profile email`.

Armed with above information, **we now know that our `response_type` is set to `token` which is the implicit grant type.**

***Implicit grant type:***

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073409.png)

Now, let's forward the authorization request.

- 2. **User login and consent:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103072213.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103072654.png)

When the authorization server receives the initial request, it will redirect the user to a login page, where they will be prompted to log in to their account with the OAuth provider.

Let's login with our own social media account:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073158.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073209.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073611.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073633.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073657.png)

In here, this is based on the scopes defined in the authorization request. The user can choose whether or not to consent to this access.

**Let's click "Continue", to consent to this access.**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073823.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073833.png)

- 3. **Access token grant:**

If the user gives their consent to the requested access, the OAuth service will redirect the user's browser to the `redirect_uri` specified in the authorization request. Then, the authorization code will send the access token and other token-specific data as a URL fragment. E.g: `/oauth-callback#access_token=6WCCPFA1jHBaL0Qc7RnLhmK8Zv0J8ghNUB3Vaj6V3VW&expires_in=3600&token_type=Bearer&scope=openid%20profile%20email`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073849.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080431.png)

- **4. API call:**

Once the client application has successfully extracted the access token from the URL fragment, it can use it to make API calls to the OAuth service's `/me` endpoint:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073857.png)

Burp Suite's HTTP History:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103075050.png)

- **5. Resource grant:**

The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the requested resource i.e. the user's data based on the scope associated with the access token:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103073908.png)

The client application can finally use this data for its intended purpose. In the case of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session, effectively logging them in:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103074022.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103075220.png)

## Exploitation

Now we knew **this lab's OAuth is implemented the implicit grant type**, which is mainly recommended for single-page applications.

In this flow, the access token is sent from the OAuth service to the client application via the user's browser as a URL fragment. The client application then accesses the token using JavaScript. The trouble is, if the application wants to maintain the session after the user closes the page, it needs to store the current user data (normally a user ID and the access token) somewhere.

To solve this problem, the client application will often submit this data to the server in a POST request and then assign the user a session cookie, effectively logging them in. This request is roughly equivalent to the form submission request that might be sent as part of a classic, password-based login. However, in this scenario, the server does not have any secrets or passwords to compare with the submitted data, which means that it is implicitly trusted.

In the implicit flow, this POST request is exposed to attackers via their browser. As a result, this behavior can lead to a serious vulnerability if the client application doesn't properly check that the access token matches the other data in the request. In this case, an attacker can simply change the parameters sent to the server to impersonate any user:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103075925.png)

**Let's log out our account, then log back in, and change the `POST /authenticate` request's `email` parameter value to `carlos@carlos-montoya.net`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080123.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080307.png)

> Note: The first time the user selects "Log in with social media", they will need to manually log in and give their consent, but if they revisit the client application later, they will often be able to log back in with a single click.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080445.png)

**Change `email` parameter value to `carlos@carlos-montoya.net`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080512.png)

Then forward the request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/OAuth-Authentication/OAuth-1/images/Pasted%20image%2020230103080603.png)

I'm user `carlos`!

# What we've learned:

1. Authentication bypass via OAuth implicit flow