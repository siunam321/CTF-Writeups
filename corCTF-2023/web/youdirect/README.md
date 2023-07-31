# youdirect

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)

## Overview

- Contributor: @siunam, @flocto, @Elmou (abdelmoumen)
- 5 solves / 415 points
- Author: larry
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

Find an open redirect in YouTube!

[Admin Bot](https://adminbot.be.ax/web-youdirect)

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731171243.png)

## Enumeration

**In this challenge, we can download a file:**
```shell
┌[siunam♥Mercury]-(~/ctf/corCTF-2023/web/youdirect)-[2023.07.31|17:13:10(HKT)]
└> file adminbot.js     
adminbot.js: JavaScript source, ASCII text
```

**adminbot.js:**
```js
import flag from './flag.txt'

function sleep(time) {
  return new Promise(resolve => {
    setTimeout(resolve, time)
  })
}

export default {
  name: 'youdirect admin bot',
  urlRegex: /^https:\/\/youtube\.com\//,
  timeout: 10000,
  handler: async (url, ctx) => {
    const page = await ctx.newPage();
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await sleep(2000);
    await page.evaluate(flag => {
      window.win(flag);
    }, flag);
    await sleep(1000);
  }
}
```

In here, the admin bot will check the URL is `https://youtube.com/`, then go to our provided URL, sleep for 2 seconds, create `win` attribute in `window` object, and sleep for 1 second.

Hmm... Do we really need to find an undiscovered open redirect in `https://youtube.com/`??

**Upon researching, we found [this blog post: Half-open redirect vulnerability in Youtube](https://untrustednetwork.net/en/2019/07/22/half-open-redirect-vulnerability-in-youtube/).**

In that post, every YouTube video's link in the description, will have the following link structure:

```
https://www.youtube.com/redirect?q=[target_URL]&redir_token=[token]&event=video_description&v=[video_ID]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731171917.png)

```
https://www.youtube.com/redirect?event=video_description&redir_token=QUFFLUhqblRFdkN4bTdxbzFrZWV3UGpwRHNpTFRKTmxid3xBQ3Jtc0tueFZyNjJtU0VGd2tTaWMzS0cwWHdFRF90MmhnNG9vdzZjdXlxR1ZsUGJtUHlqT0lGRUNZdzlNM2FfZU5UcDEtbGJ4N3NrNlIxTVo0T3M1SHJ2N2dUSWlpeld2TkpOQ1d5SlEzT2N2VzA5dlpwbHhHVQ&q=https%3A%2F%2Frick-astley.lnk.to%2FHMIYA2023ID&v=dQw4w9WgXcQ
```

However, if we don't provide or invalid `redir_token`, you'll be prompted to a warning message:

```
https://www.youtube.com/redirect?q=http://google.com
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731172055.png)

If the `redir_token` is valid, you'll be redirected to any website based on the `q` parameter:

```
https://www.youtube.com/redirect?redir_token=QUFFLUhqblRFdkN4bTdxbzFrZWV3UGpwRHNpTFRKTmxid3xBQ3Jtc0tueFZyNjJtU0VGd2tTaWMzS0cwWHdFRF90MmhnNG9vdzZjdXlxR1ZsUGJtUHlqT0lGRUNZdzlNM2FfZU5UcDEtbGJ4N3NrNlIxTVo0T3M1SHJ2N2dUSWlpeld2TkpOQ1d5SlEzT2N2VzA5dlpwbHhHVQ&q=http://google.com
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731172229.png)

BUT!!! The `redir_token` redirect only ***works if the user has a valid YouTube session***...

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731172510.png)

So, no luck in `https://www.youtube.com/redirect`, as the admin bot shouldn't have a valid YouTube session.

One of our teammates also found [this GitHub Gist](https://gist.github.com/rodrigoborgesdeoliveira/987683cfbfcc8d800192da1e73adc486), which lists some active YouTube URL formats.

In that list, we found `http://youtube.com/attribution_link`:

```
http://youtube.com/attribution_link?a=JdfC0C9V6ZI&u=%2Fwatch%3Fv%3DEhxJLojIE_o%26feature%3Dshare
```

The `u` parameter can be used to redirect user:

```
http://youtube.com/attribution_link?u=/blahblahblahblahblahfoobar
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/corCTF-2023/images/%2020230731173010.png)

However, it only redirects to an internal page (`www.youtube.com`)... Which is useless for us to redirect the admin bot to a different domain...

After fumbling around, I decided treating this challenge as Bug Bounty hunting in YouTube, but no luck of finding any open redirect XD.