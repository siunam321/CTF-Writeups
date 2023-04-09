# tcl-tac-toe

## Overview

- 73 solves / 422 points

- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

> Author: BobbySinclusto

Time to tackle tcl-tac-toe: the tricky trek towards top-tier triumph

[http://tcl-tac-toe.chals.damctf.xyz/](http://tcl-tac-toe.chals.damctf.xyz/)

[http://161.35.58.232/](http://161.35.58.232/)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408113705.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408113017.png)

In here, we can play the Tic-Tac-Toe game:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Peek%202023-04-08%2011-32.gif)

**When we click one of those cells, it'll send the following POST request:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408113519.png)

**Now, let's view the [source code](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/web/tcl-tac-toe/tcl-tac-toe.zip)!**
```shell
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/tcl-tac-toe)-[2023.04.08|11:37:13(HKT)]
└> file tcl-tac-toe.zip 
tcl-tac-toe.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/DamCTF-2023/web/tcl-tac-toe)-[2023.04.08|11:37:14(HKT)]
└> unzip tcl-tac-toe.zip 
Archive:  tcl-tac-toe.zip
   creating: tcl-tac-toe/
  inflating: tcl-tac-toe/Dockerfile  
   creating: tcl-tac-toe/app/
  inflating: tcl-tac-toe/app/app.tcl  
   creating: tcl-tac-toe/app/static/
  inflating: tcl-tac-toe/app/static/index.css  
  inflating: tcl-tac-toe/app/static/index.html  
  inflating: tcl-tac-toe/app/static/index.js
```

**In `/Dockerfile`, we see this:**
```bash
RUN wget https://wapp.tcl-lang.org/home/zip/wapp.zip --no-check-certificate && unzip wapp.zip -d /usr/lib && echo pkg_mkIndex /usr/lib/wapp | tclsh
```

As you can see, it's using a web application framework called "Wapp", which is a framework for writing web applications in Tcl. Tool Command Language (Tcl) is a powerful scripting language with programming features. It is available across Unix, Windows and Mac OS platforms. Tcl is used for **Web and desktop applications, networking, administration, testing, rapid prototyping, scripted applications and graphical user interfaces (GUI)**.

**In `/app/app.tcl`, we see the main application.**

First off, let's find where the flag is.

**In procedure (function) `wapp-page-update_board{}`, we can see how the flag is being read:**
```tcl
[...]
proc wapp-page-update_board {} {
    # allow cross-origin requests because otherwise the ssl reverse proxy thing breaks
    wapp-allow-xorigin-params
    # get prev_board, new_board, signature
    set prev_board [wapp-param prev_board]
    set new_board [wapp-param new_board]
    set signature [wapp-param signature]

    # verify previous board signature
    if [verify $prev_board $signature] {
        # verify move
        if [valid_move $prev_board $new_board] {
            set message {}
            set winner [check_win $new_board]
            if {$winner == "tie"} {
                set message "Cat's game!"
            } elseif {$winner == "X"} {
                set flag [get_file_contents "../flag"]
                set message "Impossible! You won against the unbeatable AI! $flag"
            } elseif {$winner == "O"} {
                set message "Haha I win!"
            } else {
                set new_board [computer_make_move $new_board]
                # Check if computer won or it tied the game
                set winner [check_win $new_board]
                if {$winner == "O"} {
                    set message "Haha I win!"
                } elseif {$winner == "tie"} {
                    set message "Cat's game!"
                }
            }
            # compute signature of new board
            set signature [sign $new_board]
            # send the new board, signature, and message
            wapp "$new_board,$signature,$message"
        } else {
            wapp "$prev_board,$signature,Invalid move!"
        }
    } else {
        wapp "$prev_board,$signature,No hacking allowed!"
    }
}
[...]
```

**Flag flow:**

> If the previous board signature is verified
    > If the move is verified
        > If the winner is ourself (`X`), read the flag and display it
        
That being said, we need to **win the game** in order to get the flag!

Now, when we send a POST request to `/update_board`, it'll send 3 parameters: `prev_board`, `new_board`, `signature`.

Then, it'll first verify previous board signature. Let's look at that procedure!

**Procedure `verify {}`, `sign {}`, `wapp-page-index.js {}`:**
```tcl
[...]
proc sign {msg} {
    return [exec << $msg openssl dgst -sha256 -sign key.pem -hex -r | cut -d { } -f1]
}

proc verify {msg signature} {
    return [expr {[sign $msg] == $signature}]
}
[...]
proc wapp-page-index.js {} {
    wapp-mimetype text/javascript
    # Start with an empty board
    wapp "var gameBoard = \['', '', '', '', '', '', '', '', ''\];\nvar signature = \"[sign {- - - - - - - - -}]\";\n"
    wapp [get_file_contents "static/index.js"]
}
[...]
```

The `expr` will evaluate the output of procedure `sign {}` is equal to the correct `$signature`, and the correct signature is in `/index.js`. Also, the signature is generated via `openssl`, and digested via SHA256.

Hmm... It seems like we can't bypass that?

Let's see what if the previous board signature is verified.

**Next, it'll verify our move:**
```tcl
if [valid_move $prev_board $new_board]
```

```tcl
[...]
proc valid_move {old_board new_board} {
    # Make sure only one spot was updated and that the spot that was updated was valid
    set diff_count 0
    for {set i 0} {$i < 9} {incr i} {
        if {[lindex $old_board $i] != [lindex $new_board $i]} {
            incr diff_count
            # Make sure space is not already occupied
            if {[lindex $old_board $i] == {X} || [lindex $old_board $i] == {O}} {
                return 0
            }
        }
    }
    return [expr {$diff_count == 1}]
}
[...]
```

This procedure will check there's only one spot was updated and it's occupied or not.

Then, what if both previous board signature and move is valided?

```tcl
set winner [check_win $new_board]
```

**It'll run procedure `check_win $new_board`:**
```tcl
[...]
proc check_win {board} {
    set win {{1 2 3} {4 5 6} {7 8 9} {1 4 7} {2 5 8} {3 6 9} {1 5 9} {3 5 7}}
    foreach combo $win {
        foreach player {X O} {
            set count 0
            set index [lindex combo 0]
            foreach cell $combo {
                if {[lindex $board [expr {$cell - 1}]] != $player} {
                    break
                }
                incr count
            }
            if {$count == 3} {
                return $player
            }
        }
    }
    # check if it's a tie
    if {[string first {-} $board] == -1} {
        return {tie}
    }
    return {-}
}
[...]
```

**What this procedure does is to check the following pattern has 3 `X` or `O`:**
```tcl
{1 2 3}
{4 5 6}
{7 8 9}
{1 4 7}
{2 5 8}
{3 6 9}
{1 5 9}
{3 5 7}
```

If it does, return the winner (`X` or `O`).

Let's move on!

**If there's NO winner:**
```tcl
        [...]
        } else {
            set new_board [computer_make_move $new_board]
            # Check if computer won or it tied the game
            set winner [check_win $new_board]
            if {$winner == "O"} {
                set message "Haha I win!"
            } elseif {$winner == "tie"} {
                set message "Cat's game!"
            }
        }
        [...]
```

**Run procedure `computer_make_move $new_board`:**
```tcl
[...]
proc computer_make_move {board} {
    set win {{1 2 3} {4 5 6} {7 8 9} {1 4 7} {2 5 8} {3 6 9} {1 5 9} {3 5 7}}
    # check if computer can win
    foreach combo $win {
        set count 0
        set index [lindex combo 0]
        foreach cell $combo {
            if {[lindex $board [expr {$cell - 1}]] eq {O}} {
                incr count
            } else {
                set index [expr $cell - 1]
            }
        }
        if {$count == 2} {
            if {[lindex $board $index] == {-}} {
                lset board $index {O}
                return $board
            }
        }
    }
    # check if human can win, block them if they can
    set played 0
    foreach combo $win {
        set count 0
        set index [lindex combo 0]
        foreach cell $combo {
            if {[lindex $board [expr {$cell - 1}]] eq {X}} {
                incr count
            } else {
                set index [expr $cell - 1]
            }
        }
        if {$count == 2 && [lindex $board $index] == {-}} {
            lset board $index {O}
            set played 1
        }
    }
    if {$played == 1} {
        return $board
    }
    # choose something to play if neither condition holds
    for {set i 0} {$i < 9} {incr i} {
        if {[lindex $board $i] == {-}} {
            lset board $i {O}
            return $board
        }
    }
}
[...]
```

It'll check the computer and human can win. If human can win, try to block them.

After that, it'll check the winner again via procedure `check_win $new_board`.

**Finally, compute signature of new board:**
```tcl
# compute signature of new board
set signature [sign $new_board]
# send the new board, signature, and message
wapp "$new_board,$signature,$message"
```

Armed with above information, we can try to exploit it to win the game!

## Exploitation

In the above source code analysis, we can control `prev_board`, `new_board`, `signature` in `/update_board` POST request.

Hmm... I wonder if we can forge our own signature...

However, I tried that, no dice.

Let's play with it!

***Now, what if I'm the AI (`O`)?***

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150116.png)

Umm... It doesn't check I'm the AI!

Then I decided to ***let the AI win***:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150244.png)

> Note: You'll need to replace the `signature` with the `new_board` signature, `prev_board` replace to new one, and add a new move in `new_board`.

Arghh... Can I still play the game ***AFTER it's lost/tied***?

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150452.png)

I can!

***Let's try to win the game while it's already lost:***

![](https://github.com/siunam321/CTF-Writeups/blob/main/DamCTF-2023/images/Pasted%20image%2020230408150521.png)

Boom! We beat the game!!

I guess the reason why we beat that is the `check_win` procedure checks the following pattern ***in order***:

```tcl
{1 2 3}
{4 5 6}
{7 8 9}
{1 4 7}
{2 5 8}
{3 6 9}
{1 5 9}
{3 5 7}
```

So I guess we won the **race condition** of the check!

- **Flag: `dam{7RY1N9_Tcl?_71m3_70_74k3_7W0_7YL3n01_748L37s}`**

## Conclusion

What we've learned:

1. Exploiting Logic Bug & Race Condition