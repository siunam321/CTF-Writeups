# gigachessbased

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)

</details>

## Overview

- Contributor: @siunam, @ensy.zip, @ozetta, @vow
- 2 solves / 495 points
- Author: @r2uwu2
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★☆

## Background

I was too focused on the trap, I forgot about the cheese.

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211164537.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211164610.png)

In here, we can search for a chess opening. Let's try it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211164806.png)

When we clicked the "go" button, it'll update our URL to `/#/search?q=<opening>`.

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211165027.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211165035.png)

After updating our URL, it'll send a POST request to `/search` with a JSON object. Then, it redirects us to `/render?id=<opening_id>`, in which returns the HTML code of the given opening.

To have a better understanding of this web application, let's read its source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/web/gigachessbased/gigachessbased.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/gigachessbased)-[2025.02.11|16:54:20(HKT)]
└> file gigachessbased.zip 
gigachessbased.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/LA-CTF-2025/web/gigachessbased)-[2025.02.11|16:54:21(HKT)]
└> unzip gigachessbased.zip 
Archive:  gigachessbased.zip
   creating: frontend/
  inflating: frontend/README.md      
[...]
  inflating: admin-bot/Dockerfile    
  inflating: admin-bot/handlers/chessbased.js  
```

After reading the source code a little bit, we can have the following findings:
1. This web application's backend is written in JavaScript with [Express.js](https://expressjs.com/) framework
2. The frontend uses framework [Svelte](https://svelte.dev/)

First off, what's our objective in this challenge? Where's the flag?

In `backend/app.js`, we can see that there's a permium opening called `flag`:

```javascript
const { openings } = require('./openings.js');
[...]
const flag = process.env.FLAG ?? 'lactf{owo_uwu}';
[...]
openings.forEach((op) => (op.premium = false));
openings.push({ premium: true, name: 'flag', moves: flag });
```

So... We need to somehow get the permium opening `flag`.

In GET route `/render`, we can get all the non-premium openings unless we know the admin's password:

```javascript
const adminpw = process.env.ADMINPW ?? 'adminpw';
[...]
const lookup = new Map(openings.map((op) => [op.name, op]));
[...]
app.get('/render', (req, res) => {
  const hasPremium = req.cookies.adminpw === adminpw;
  const id = req.query.id;
  const op = lookup.get(id);

  if (op.premium && !hasPremium) {
    return res.send('nice try buddy pay up');
  }

  res.send(`
    <p>${op?.name}</p>
    <p>${op?.moves}</p>
  `);
});
```

In POST route `/search`, we can only search for non-premium openings, it also checks our request header `Referer` is same as `challdomain`:

```javascript
const challdomain = process.env.CHALLDOMAIN ?? 'http://localhost:3000/';
[...]
app.post('/search', (req, res) => {
  if (req.headers.referer !== challdomain) {
    res.send('only challenge is allowed to make search requests');
    return;
  }
  const q = req.body.q ?? 'n/a';
  const hasPremium = req.cookies.adminpw === adminpw;
  for (const op of openings) {
    if (op.premium && !hasPremium) continue;
    if (op.moves.includes(q) || op.name.includes(q)) {
      return res.redirect(`/render?id=${encodeURIComponent(op.name)}`);
    }
  }
  return res.send('lmao nothing');
});
```

So, without knowing the admin's password, there's no way that we can get the premium `flag` opening.

In this challenge, it also has an admin bot, the source code can be found at `admin-bot/handlers/chessbased.js`.

In here, it launches a headless Chrome browser via library [puppeteer](https://pptr.dev/). Then, it sets a cookie named `adminpw` with the challenge domain, **flag `httpOnly` to `true`**, and **`sameSite` to `Lax`**. Finally, it visits our given URL for 30 seconds, and closes the page and browser:

```javascript
const puppeteer = require("puppeteer");

module.exports = {
    name: "chessbased",
    timeout: 300000,
    noContext: true,
    async execute(nn, url) {
        const browser = await puppeteer.launch({ pipe: true, args: [] });
        try {
          const page = await browser.newPage();
          await page.setCookie({
              name: "adminpw",
              value: process.env.CHALL_CHESSBASED_ADMINPW || "placeholder",
              domain: process.env.CHALL_CHESSBASED_DOMAIN || "localhost:8080",
              httpOnly: true,
              sameSite: "Lax",
          });
          await page.goto(url);
          await page.waitForNetworkIdle({
              timeout: 300000,
          });
          await page.close();
        } finally {
            browser.close();
        }
    },
};
```

With that said, we need to somehow exfiltrate the premium `flag` opening through the admin bot, usually via client-side vulnerabilities. Let's find client-side vulnerabilities!

Since we can't control any openings name and moves, or create new openings, we'll need to focus on the frontend.

In `frontend/src/App.svelte`, there are 2 SPA (Single Page Application) routes, which are `/` (`Index`) and `/search` (`Search`):

```html
<script>
  import Router from 'svelte-spa-router';
  import Index from './Index.svelte';
  import Search from './Search.svelte';

  const routes = {
    '/': Index,
    '/search': Search
  };
</script>

<body>
  <Router {routes} />
</body>
```

Let's take a look at the `Index` component at `frontend/src/Index.svelte`:

```html
<script>
  import { push } from 'svelte-spa-router';

  let query = '';

  const onSubmit = () => {
    push(`/search?q=${encodeURIComponent(query)}`);
  };
</script>

<main>
  <h1>Chessbased</h1>
  <p>Welcome to chessbased, enter an opening to search in our chess opening explorer!</p>
  <form on:submit|preventDefault={onSubmit}>
    <label>
      Opening:
      <input type="text" bind:value={query}>
    </label>
    <input type="submit" value="go">
  </form>
 </main>
```

When the form is submitted, it'll call function `onSubmit`, which updates our URL. In this case, it updates our URL to `/#/search?q=<query>`. Huh, what does the fragment (`#`) do?

As we can see, it uses module [svelte-spa-router](https://www.npmjs.com/package/svelte-spa-router), which uses **hash-based routing**.

According to the module's description, it said:

> With hash-based routing, navigation is possible thanks to storing the current view in the part of the URL after `#`, called "hash" or "fragment".
>   
> For example, if your SPA is in a static file called `index.html`, your URLs for navigating within the app look something like `index.html#/profile`, `index.html#/book/42`, etc. (The `index.html` part can usually be omitted for the index file, so you can just create URLs that look like `http://example.com/#/profile`).
>   
> - [https://www.npmjs.com/package/svelte-spa-router#hash-based-routing](https://www.npmjs.com/package/svelte-spa-router#hash-based-routing)

Nothing weird, how about the `Search` component?

In `frontend/src/Search.svelte`, we can see that when GET parameter `q` is not empty, it'll send a POST request to `search` with a JSON object by calling the `search` function:

```html
<script>
  import { push, querystring } from 'svelte-spa-router';

  let searchResult = '';

  $: query = new URLSearchParams($querystring).get('q') ?? 'n/a';
  $: inputQuery = query;

  const api = import.meta.env.MODE === 'development'
    ? end => `http://localhost:3000${end}`
    : end => end;

  const search = async (query) => {
    searchResult = await fetch(api('/search'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ q: query })
    }).then(r => r.text()).catch(err => err);
  };

  $: search(query);
  [...]
</script>
[...]
```

After that request, it'll render the `searchResult` using [template `@html`](https://svelte.dev/docs/svelte/@html):

```html
<main>
  <h1>Chessbased</h1>
  <p>Welcome to chessbased, enter an opening to search in our chess opening explorer!</p>
  <form on:submit|preventDefault={onSubmit}>
    <label>
      Opening:
      <input type="text" bind:value={inputQuery}>
    </label>
    <input type="submit" value="go">
  </form>
  <div class="search-result">
    {@html searchResult}
  </div>
 </main>
```

According to the [Svelte documentation](https://svelte.dev/docs/svelte/@html), this template syntax will not sanitize the content, and thus it might result in XSS. However, in our case, we can't control the `searchResult`, so no XSS.

Basically, in this component, we can visit a path like `/#/search?q=e1` to search for an opening.

Hmm... In this situation, the only vulnerability that I can come up with is **[XS-Leaks](https://xsleaks.dev/)/[XS-Search](https://xsleaks.dev/docs/attacks/xs-search/)**.

In GET route `/render`, we can search for an opening based on the opening name (`id`):

```javascript
const lookup = new Map(openings.map((op) => [op.name, op]));
[...]
app.get('/render', (req, res) => {
  const hasPremium = req.cookies.adminpw === adminpw;
  const id = req.query.id;
  const op = lookup.get(id);

  if (op.premium && !hasPremium) {
    return res.send('nice try buddy pay up');
  }

  res.send(`
    <p>${op?.name}</p>
    <p>${op?.moves}</p>
  `);
});
```

Hmm... Can we leverage [Scroll to Text Fragment (STTF)](https://developer.mozilla.org/en-US/docs/Web/URI/Fragment/Text_fragments) to perform XS-Leak?

According to [xsleaks.dev](https://xsleaks.dev/docs/attacks/experiments/scroll-to-text-fragment/), we could use STTF to detect when the browser brought into the viewport. However, it requires:
1. The web application can be embedded using `<iframe>` element
2. Some type of HTML injection

For the first one, it already failed, as the web application has the following Content Security Policy (CSP) and response header `X-Frame-Options`:

```javascript
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
```

In the CSP, the directive `frame-ancestors` with source `none`, it disallows the page cannot be embedded. For the `X-Frame-Options` response header, when it sets to `DENY`, it denies the page to be embedded. Therefore, we cannot embedded this web application using `<iframe>` element.

In the second requirement, as I mentioned earlier, we can't control an opening's name and moves. So, nope.

How about other XS-Leaks techniques? Like [navigations](https://xsleaks.dev/docs/attacks/navigations/).

> Check the value of `history.length`, which is accessible through any window reference. This provides the number of entries in the history of a victim that were either changed by `history.pushState` or by regular navigations. To get the value of `history.length`, an attacker changes the location of the window reference to the target website, then changes back to same-origin, and finally reads the value. - [https://xsleaks.dev/docs/attacks/navigations/](https://xsleaks.dev/docs/attacks/navigations/)

Let's say we want to determine whether `/#/search?q=lactf{a` is correct or not, we can:
1. The bot visit our exploit on our attacker website
2. The exploit opens a new window to `https://gigachessbased.chall.lac.tf/`
3. Change the new window's location to `https://gigachessbased.chall.lac.tf/#/search?q=lactf{a`
4. Change the new window's location to our attacker website
5. Get the new window's `history.length`

> Note: The reason why we need to change the location to our attacker website, it's because the browser disallows us to read a window's `history.length` if it's on a different origin.

Since if the opening `moves` (`lactf{a`) is in the opening, it'll **redirect** to `/render?id=flag`, which increment 1 in the `history.length`. Otherwise, the `history.length` will not be incremented:

```javascript
app.post('/search', (req, res) => {
  [...]
  for (const op of openings) {
    [...]
    if (op.moves.includes(q) || op.name.includes(q)) {
      return res.redirect(`/render?id=${encodeURIComponent(op.name)}`);
    }
  }
  return res.send('lmao nothing');
});
```

However, after some testing, it didn't work...

Before redirect:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211194402.png)

In theory, after the redirect, our `history.length` should be `4`.

After redirect:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211194505.png)

Wait, why the length is `3` instead of `4`?

Turns out, the POST request to `/search` made from the `fetch` API will not push to the history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211194842.png)

So... We can't detect the oracle by using `history.length`...

There must be another way to detect the oracle... How about [server-side maximum redirects](https://xsleaks.dev/docs/attacks/navigations/#max-redirects)?

> When a page initiates a chain of 3XX redirects, browsers limit the maximum number of redirects to 20. This can be used to detect the exact number of redirects occurred for a cross-origin page by following the below approach:
>  
> 1. As a malicious website, initiate 19 redirects and make the final 20th redirect to the attacked page.
> 2. If the browser threw a network error, at least one redirect occurred. Repeat the process with 18 redirects.
> 3. If the browser didn’t threw a network error, the number of redirects is known as `20 - issued_redirects`.
>   
> - [https://xsleaks.dev/docs/attacks/navigations/#max-redirects](https://xsleaks.dev/docs/attacks/navigations/#max-redirects)

With that said, we should be able to detect an oracle by redirecting the browser to our attacker website 18 times. Then, the 19th redirect to `https://gigachessbased.chall.lac.tf/#/search?q=lactf{a`. If the `moves` is correct, the browser should throw a network error.

Well, notice the wording here: **a chain of** 3XX redirects.

In our case, the 19th redirect will absolutely break the chain of redirects, as it'll return HTTP status code "200 OK" (or "304 Not Modified" if cached):

![](https://github.com/siunam321/CTF-Writeups/blob/main/LA-CTF-2025/images/Pasted%20image%2020250211195728.png)

So, nope again.

How about using the [CSS `:visited` selector](https://xsleaks.dev/docs/attacks/css-tricks/)? According to a writeup from [Jorian Woltjer](https://jorianwoltjer.com/): [XS-Leaking flags with CSS: A CTFd 0day](https://jorianwoltjer.com/blog/p/hacking/xs-leaking-flags-with-css-a-ctfd-0day), we can leverage CSS `:visited` selector to measure the re-paint timing between visited links and non-visited links without any user interactions.

However, it also doesn't work. The reason is same as the one in `history.length`, the POST request made from the `fetch` API will not push to the `history`, which means the CSS `:visited` selector will not even work, as the URL in the `history` doesn't exist.

Okay... Here's the last 2 XS-Leaks techniques I think will work in this challenge...

[Cross-window Timing Attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks):

> An attacker can also measure the network timing of a page by opening a new window with `window.open` and waiting for the `window` to start loading. - [https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks)

In the following PoC, it measures the timing of a page being loaded: (From `xsleaks.dev`)

```javascript
// Open a new window to measure when the iframe starts loading
var win = window.open('https://example.org');
// Measure the initial time
var start = performance.now();
// Define the loop
function measure(){
  try{
    // If the page has loaded, then it will be on a different origin
    // so `win.origin` will throw an exception
    win.origin;
    // If the window is still same-origin, immediately repeat the loop but
    // without blocking the event loop
    setTimeout(measure, 0);
  }catch(e){
    // Once the window has loaded, calculate the time difference
    var time = performance.now() - start;
    console.log('It took %d ms to load the window', time);
  }
}
// Initiate the loop that breaks when the window switches origins
measure();
```

In our case, if we try to open a new window to `https://gigachessbased.chall.lac.tf/#/search?q=lactf{a`, we can... Oh, wait a minute, we can only measure how fast of the index page (`https://gigachessbased.chall.lac.tf/`) is being loaded, NOT the time of the redirect...

Huh... This is the last one technique, if this also doesn't work, I think we'll need to find a new, novel XS-Leaks technique. Introducing... [Connection pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/).

> Another way to measure the network timing of a request consists of abusing the socket pool of a browser. Browsers use sockets to communicate with servers. As the operating system and the hardware it runs on have limited resources, browsers have to impose a limit. - [https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool/).

Since the browser has a hard limit for concurrent requests (256 global sockets for TCP), we can detect if a redirect occurred via: (From `xsleaks.dev`)
1. Block 255 TCP sockets infinitely by performing 255 requests to **different hosts** that simply hang the connection
2. Use the 256th TCP socket by performing a request to the target page (`https://gigachessbased.chall.lac.tf/#/search?q=lactf{a`)
3. Perform the 257th request to another host. Since all the sockets are being used (in steps 1 and 2), this request must wait until the pool receives an available TCP socket. This waiting period provides the attacker with the network timing of the 256th socket, which belongs to the target page. This works because the 255 sockets in step 1 are still blocked, so if the pool received an available socket, it was caused by the release of the socket in step 2. The time to release the 256th socket is directly connected with the time taken to complete the request

TL;DR: If the 256th request redirected to `/render?id=flag`, we should be able to know that the release time of the other sockets is longer than usual, thus detecting whether if the `moves` is correct or not.

Unfortunately for our team, since this technique's setup is quick complex, we don't have enough time to successfully leak the flag using this technique. I'll leave the reader to try to give it a shot!