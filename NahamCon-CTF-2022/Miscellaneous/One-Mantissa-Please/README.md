# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/background.png)

As usual, start the instance and connect to it via netcat!

# Question
![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/question.png)

Hmm... It's said the shell will run this Javascript if we type something.
```javascript
console.log(%d == (%d + 1));
```

Looks like it's comparing an output.

`%d` in Javascript means an `Integer`, so we need to type an integer, otherwise it won't accept our input.

That Javascript will always return `False` boolean.(Boolean means True and False, True = 1, False = 0)

Example:
```javascript
d = 1 // Set d is 1

console.log(d == (d + 1)); // 1 is not equal to 2 (1 + 1)

false // Output:
```

But, what if we want it to return `True`? It's possible? Then, I started to google `Javascript maximum integer`, as I remember one YouTube video was talking about the  Year 2038 problem.(32-bit systems time formatting bug)

![solution1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/solution1.png)

And google returns `9007199254740991`!!

What I'm thinking is that what if I type an integer that **exceed that maximum integer?** Will it returns True? Now, let's test my theory in Node.js.

![solution2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/solution2.png)

Looks like 9007199254740991 is not working, as it doesn't exceed the maximum integer yet. How about I add 1 to that maximum integer `9007199254740992`? Will it returns True?

![solution3](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/solution3.png)

Wow!! My theory is correct! It returns true! Let's throw that integer to the instance.

![solution4](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/solution4.png)

Yes! We've successfully esacpe that false boolean!

Now, the challenge said: 

> **"The correct answer is the smallest positive integer value."**

Let's copy and paste `9007199254740992` to [CyberChef](https://gchq.github.io/CyberChef/) with the `MD5` recipe and submit the flag!

![solution5](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/solution5.png)

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Miscellaneous/One-Mantissa-Please/images/flag.png)