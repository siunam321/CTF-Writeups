# Guess the Password?

- 263 Points / 175 Solves

- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆☆

## Background

We found a VIP's box, but when we try to guess his short password, we get rate limited! We managed to get the source code and it looks like the server implements its security in a way that isn't secure! Can you reverse the python code and get the flag?

`nc guessthepassword.challenges.ctf.ritsec.club 1337`

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401200607.png)

## Find the flag

**In this challenge, we can download 3 files:**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Reversing/Guess-the-Password?)-[2023.04.01|20:06:26(HKT)]
└> file *       
encoding.py:      Python script, ASCII text executable
server.py:        Python script, ASCII text executable
supersecret.json: JSON text data
```

**By looking at function `chatter()` in `server.py`, we need to send a **8-digit password** to the server. Then, i'll check our input (`encoder.check_input()`):**
```py
[...]
def chatter(self, connection_info):
    self.debug_print("Client connected")
    client_socket = connection_info[0]
    client_ip = connection_info[1][0]

    if self.user_is_rate_limited(client_ip):
        client_socket.send( "You are being rate limited".encode() )
        client_socket.close()
        return

    client_socket.send( "Enter the passcode to access the secret: \n".encode() )
    user_input = client_socket.recv(1024).decode() [:8]

    if len(user_input) == 8 and self.encoder.check_input(user_input):
        secret = self.encoder.flag_from_pwd(user_input)
        response = f"RS{ {secret} }\n"

    else:
        response = "That password isn't right!\n\tHint: The last 8 digits of your phone number\n"

    response += "\nClosing connection...\n"
    client_socket.send(response.encode())
    client_socket.close()

    self.debug_print("Client connection closed")
[...]
```

**encoding.py:**
```py
[...]
def hash(self, user_input):
    salt = "RITSEC_Salt"
    return hashlib.sha256(salt.encode() + user_input.encode()).hexdigest()


def check_input(self, user_input):
    hashed_user_input = self.hash(user_input)
    # print("{0} vs {1}".format(hashed_user_input, self.hashed_key))
    return hashed_user_input == self.hashed_key
[...]
```

Next, our user input will be hashed via **SHA256 with salt `RITSEC_Salt`**.

**If the our user input hash is matched to the correct one, we're in!**

**supersecret.json:**
```json 
{
    "key":"657fa7558ae9011e8b9d3f56d5c083273557c3139f27d7b62cac458eb1a1a19d",
    "secret":"xxxxCORRUPTED_SECRETxxxx"
}
```

With that said, we can write a script that brute force the 8-digit password with that salt!

Since I'm good at Python, let's write a Python script to do that! You can write that in Rust, Go, whatever language you want.

**crack_hash.py:**
```py
#!/usr/bin/env python3
import hashlib

def main():
    salt = 'RITSEC_Salt'
    key = '657fa7558ae9011e8b9d3f56d5c083273557c3139f27d7b62cac458eb1a1a19d'

    for i in range(100000000):
        user_input = f'{i:08d}'

        hashed = hashlib.sha256(salt.encode() + user_input.encode()).hexdigest()
        print(f'[*] Trying password {user_input}, after hashed: {hashed}', end='\r')

        if hashed == key:
            print('[+] Found the correct password!')
            print(f'[+] Before hashed: {user_input}')
            print(f'[+] After hashed: {hashed}')
            exit()

if __name__ == '__main__':
    main()
```

This script will loop `00000000` to `99999999`. If the hashed number is matched to the key one, we found the correct password!

**Let's run it!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Reversing/Guess-the-Password?)-[2023.04.01|19:10:30(HKT)]
└> python3 crack_hash.py
[...]
[*] Trying password 54744973, after hashed: 657fa7558ae9011e8b9d3f56d5c083273557c3139f27d7b62cac458eb1a1a19[+] Found the correct password!
[+] Before hashed: 54744973
[+] After hashed: 657fa7558ae9011e8b9d3f56d5c083273557c3139f27d7b62cac458eb1a1a19d
```

**Nice! We found the correct password: `54744973`!**

**Let's `nc` to the challenge's machine!**
```shell
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023/Reversing/Cats-At-Play)-[2023.04.01|18:39:29(HKT)]
└> nc guessthepassword.challenges.ctf.ritsec.club 1337
Enter the passcode to access the secret: 
54744973
RS{'PyCr@ckd'}

Closing connection...
```

- **Flag: `RS{'PyCr@ckd'}`**

## Conclusion

What we've learned:

1. Brute Forcing SHA256 Hash With Salt