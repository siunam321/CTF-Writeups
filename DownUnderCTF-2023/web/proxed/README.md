# proxed

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 966 solves / 100 points
- Author: Jordan Bertasso
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Cool haxxorz only

Author: Jordan Bertasso

[http://proxed.duc.tf:30019](http://proxed.duc.tf:30019)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903185912.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903185940.png)

When we go to the index page (`/`), it'll response HTTP status code "403 Forbidden" with data "untrusted IP: 10.152.0.17".

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/proxed/proxed.tar.gz):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/proxed)-[2023.09.03|19:02:11(HKT)]
└> file proxed.tar.gz                         
proxed.tar.gz: gzip compressed data, last modified: Wed Aug 16 02:28:43 2023, from Unix, original size modulo 2^32 6144
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/proxed)-[2023.09.03|19:02:15(HKT)]
└> tar xf proxed.tar.gz              
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/proxed)-[2023.09.03|19:02:16(HKT)]
└> ls -lah proxed
total 20K
drwxr-xr-x 3 siunam nam 4.0K Aug 16 10:19 .
drwxr-xr-x 3 siunam nam 4.0K Sep  3 19:02 ..
drwxr-xr-x 3 siunam nam 4.0K Sep  3 19:02 cmd
-rw-r--r-- 1 siunam nam  130 Aug 16 10:23 Dockerfile
-rw-r--r-- 1 siunam nam   47 Aug 16 10:22 go.mod
```

**After reading the source code a little bit, the `cmd/secret_server/main.go` contains the web application's main logic:**
```go
package main

import (
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"
)

var (
    port = flag.Int("port", 8081, "The port to listen on")
)

func main() {

    flag.Parse()

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        xff := r.Header.Values("X-Forwarded-For")

        ip := strings.Split(r.RemoteAddr, ":")[0]

        if xff != nil {
            ips := strings.Split(xff[len(xff)-1], ", ")
            ip = ips[len(ips)-1]
            ip = strings.TrimSpace(ip)
        }

        if ip != "31.33.33.7" {
            message := fmt.Sprintf("untrusted IP: %s", ip)
            http.Error(w, message, http.StatusForbidden)
            return
        } else {
            w.Write([]byte(os.Getenv("FLAG")))
        }
    })

    log.Printf("Listening on port %d", *port)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}
```

In the `/` route, **when request header `X-Forwarded-For`'s value is `31.33.33.7`, it'll response us with the flag**.

## Exploitation

**That being said, we can get the flag via providing that request header:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903190810.png)

- **Flag: `DUCTF{17_533m5_w3_f0rg07_70_pr0x}`**

## Conclusion

What we've learned:

1. Proxying via `X-Forwarded-For` header