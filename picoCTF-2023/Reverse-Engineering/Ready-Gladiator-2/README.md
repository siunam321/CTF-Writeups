# Ready Gladiator 2

## Overview

- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

Author: LT 'syreal' Jones

Your opponent is the Imp. The source is available [here](https://artifacts.picoctf.net/c/284/imp.red). If you wanted to pit the Imp against himself, you could download the Imp and run your own core wars server

Description

Can you make a CoreWars warrior that wins every single round? Your opponent is the Imp. The source is available [here](https://artifacts.picoctf.net/c/279/imp.red). If you wanted to pit the Imp against himself, you could download the Imp and connect to the CoreWars server like this: `nc saturn.picoctf.net 56794 < imp.red` To get the flag, you must beat the Imp all 100 rounds.

## Find the flag

**In this challenge, we can download a file and able to connect the instance machine via `nc`:**
```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-2)-[2023.03.28|23:12:01(HKT)]
└> cat imp.red                
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-2)-[2023.03.28|23:12:13(HKT)]
└> nc saturn.picoctf.net 56794 < imp.red
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end
Submit your warrior: (enter 'end' when done)

Warrior1:
;redcode
;name Imp Ex
;assert 1
mov 0, 1
end

Rounds: 100
Warrior 1 wins: 0
Warrior 2 wins: 0
Ties: 100
Try again. Your warrior (warrior 1) must win 100 times.
```

In the previous challenge (Ready Gladiator 1), we've learned what is CoreWars and how it works.

In "Redcode" assembly language, there's a `JMP` instruction, which jumps to a value.

Hmm... What if we **control the target address of the "Imp" opponent `MOV` instruction** after it has been copied over?

That being said, **can we use the `JMP` instruction to jump back behind so that "Imp" can't move forward, which will then kills the "Imp"??**

**Warrior:**
```asm
;redcode
;name Imp Ex
;assert 1
jmp 0,<-2
end

```

The `jmp 0,<-2` is to jump to position behind `-2`.

```shell
┌[siunam♥earth]-(~/ctf/picoCTF-2023/Reverse-Engineering/Ready-Gladiator-2)-[2023.03.28|23:13:24(HKT)]
└> nc saturn.picoctf.net 56794 < imp.red
;redcode
;name Imp Ex
;assert 1
jmp 0,<-2
end
Submit your warrior: (enter 'end' when done)

Warrior1:
;redcode
;name Imp Ex
;assert 1
jmp 0,<-2
end

Rounds: 100
Warrior 1 wins: 100
Warrior 2 wins: 0
Ties: 0
You did it!
picoCTF{d3m0n_3xpung3r_fc41524e}
```

Nice! We did it!

- **Flag: `picoCTF{d3m0n_3xpung3r_fc41524e}`**

## Conclusion

What we've learned:

1. Winning CoreWars "Imp"