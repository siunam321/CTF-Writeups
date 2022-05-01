# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/background.png)

In this challenge, you'll have to use [CyberChef](https://gchq.github.io/CyberChef/) and [RapidTables](https://www.rapidtables.com/) to solve it. (If you don't know what is CyberChef and RapidTables, it basically helps you to decode, decrypt, encode and encrypt things.)

# Question 1

Let's look at the first question.

![question1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question1.png)
```
First Question: What is the ASCII plaintext corresponding to this binary string?
010110100110010101110010011011110111001100100000001001100010000001001111011011100110010101110011
```
It's said it's a `binary` string, so why not put that string to [CyberChef](https://gchq.github.io/CyberChef/)? copy that string paste it in the `Input` textbox, then search `binary` at Opeartions tab, and choose `From Binary`.

![question1s](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question1solution.png)

As you can see in the output, it outputs out `Zeros & Ones`, and this is the answer for the first question!

# Question 2

![question2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question2.png)
```
Second Question: What is the ASCII plaintext corresponding to this hex string?
4f6820776f77777721204261736520313020697320636f6f6c20616e6420616c6c2062757420486578787878
```
It's said it's a `hex` string, so copy and paste this string like last question.

![question2s](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question2solution.png)
And it outputs out `Oh wowww! Base 10 is cool and all but Hexxxx`.

# Question 3

![question3](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question3.png)
```
Third Question: What is the ASCII plaintext corresponding to this octal string?
(HINT: octal -> int -> hex -> chars) 
535451006154133420162312701623127154533472040334725553046256234620151334201413347444030460563312201673122016730267164
```
> This question really makes so frustrating because I trusted CyberChef too much Lol.

In this question, it's said we've to find the ASCII plaintext from that `octal` string, and that octal string is **encoded from ASCII plaintext -> hexadecimal -> integer(decimal) -> octal**, so we need to **decode that octal string to octal -> integer(decimal) -> hexadecimal -> ASCII plaintext.** (I've tried using CyberChef to convert octal to integer, but it doesn't work.)

Then I started using [RapidTables](https://www.rapidtables.com/convert/number/octal-to-decimal.html). Copy and paste the octal string, and it outputs out `3131880780077943822552217163958175390677077601044656010262087478932193255537275603789701176597829315030644` 
in the Decimal number textbox

![question3s1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question3solution1.png)

Next, we need to convert this `3131880780077943822552217163958175390677077601044656010262087478932193255537275603789701176597829315030644` integer to hexadecimal. In order to do that, we can use [RapidTables](https://www.rapidtables.com/convert/number/decimal-to-hex.html). (CyberChef doesn't work, I tried)

Now, it should outputs out this hexadecimal `57652063616E20726570726573656E74206E756D6265727320696E20616E7920626173652077652077616E74`.

![question3s2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question3solution2.png)

Then, you can simply copy and paste that hexadecimal to CyberChef and start baking with the `From Charcode` recipe. (Charcode means ASCII plaintext)

![question3s3](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question3solution3.png)

And the answer is `We can represent numbers in any base we want`!!

# Question 4

![question4](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question4.png)
```
Fourth Question: What is the ACII representation of this integer? 
(HINT: int -> hex -> chars)
8889185069805239596091046045687553579520816794635237831028832039457
```
Again, using the previous technique to decode!

![question4s1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question4solution1.png)

![question4s2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question4solution2.png)

Answer: `This is one big 'ol integer!`

# Question 5

![question5](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question5.png)
```
Fifth Question: What is the ASCII plaintext of this Base64 string? 
QmFzZXMgb24gYmFzZXMgb24gYmFzZXMgb24gYmFzZXMgOik=
```

It's said it's a `Base64` encoded string, let's use CyberChef to decode that!

![question5s](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question5solution.png)

Answer: `Bases on bases on bases on bases :)`

> Bonus tips!

**What if no one tells you that string is Base64 encoded? How would you determine that string using what encoding method?**

There's a quick way to determine that string.

If you saw there's a `=` or `==` in that string, that must be Base64, because that `=` or `==` is called padding in Base64! Base64 requires the length of an output-encoded string **must be a multiple of three.** So, next time if you see `=` or `==` in an encoded string, it must be Base64!

```
Bonus Challenge: What is the ASCII plaintext of this encoded string? 
QmFzZTY0X0hhc19BX1BhZGRpbmchCg==
```

# Question 6

![question6](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question6.png)
```
Last Question: What is the Big-Endian representation of this Little-Endian hex string? 
293a2065636e657265666669642065687420776f6e6b206f7420646f6f672073277449
```
It's said it's a `Little-Endian hexadecimal`! So let's convert that string to ASCII plaintext by using CyberChef!

![question6s1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question6solution1.png)

Hmm... Looks like it's a ASCII plaintext, but a little bit weird. Oh!!! We can change the `Word length` in the `Swap endianness` recipe!

![question6s2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/question6solution2.png)

Yes! We've successfully solve the last question! `It's good to know the difference :)`

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Wizard/images/flag.png)

Now we finally have the flag!!