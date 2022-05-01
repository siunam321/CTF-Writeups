# Background
![background](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Crash-Override/images/background.png)

In this challenge, we've 3 files, `crash_override.c`, `Makefile` and `crash_override`

crash_override.c is a C language source code.

Makefile is a gcc command that complies C source code.

crash_override is an ELF 64-bit LSB executable.

Let's connect to the instance first.

![question](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Crash-Override/images/question.png)

Looks like it waiting for the user's input.

Now, let's look at the C source code and see what we can find.
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <signal.h>

void win(int sig) {
    FILE *fp = NULL;
    char *flag = NULL;
    struct stat sbuf;

    if ((fp = fopen("flag.txt", "r")) == NULL) {
        puts("Failed to open the flag. If this is on the challenge server, contact an admin.");
        exit(EXIT_FAILURE);
    }

    if (fstat(fileno(fp), &sbuf)) {
        puts("Failed to get flag.txt file status. If this is on the challenge server, contact an admin.");
        exit(EXIT_FAILURE);
    }

    flag = calloc(sbuf.st_size + 1, sizeof(char));
    if (!flag) {
        puts("Failed to allocate memory.");
        exit(EXIT_FAILURE);
    }

    fread(flag, sizeof(char), sbuf.st_size, fp);
    puts(flag);

    free(flag);

    exit(EXIT_SUCCESS);
}

int main(void) {
    char buffer[2048];

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    signal(SIGSEGV, win);

    puts("HACK THE PLANET!!!!!!");
    gets(buffer);

    return 0;
}
```
As you can see, it has 2 functions, `win` and `main`.

Let's dive in to the `main` function.

In the main function, it has a variable called buffer, and set it to 2048 bytes.
```c
char buffer[2048];
```

```c
gets(buffer);
```
Also, we've see a `gets` function to get the user's input, which is vulnerable to `buffer overflow`, as it doesn't perform any array bound checking and keep reading the characters until the new line (Enter).

Then, I started analzye the `win` function.

If there's no flag.txt in the current directory, it returns that puts function's string.
```c
if ((fp = fopen("flag.txt", "r")) == NULL) {
    puts("Failed to open the flag. If this is on the challenge server, contact an admin.");
    exit(EXIT_FAILURE);
}
```

Hmm... Let's create a fake flag.txt to proof that statement.

Now, we can type bunch of characters that are **more than the buffer size.** Hence, we can **overflow the buffer size.**

Let's use python's one liner to print out 2500 A's, run the 64-bit executable, copy and paste to it, so that it should overflows the buffer size.

![solution1](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Crash-Override/images/solution1.png)

![solution2](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Crash-Override/images/solution2.png)

Yes!! We've successfully have the fake flag! Let's do it in the instance that I started.

![flag](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2022/Warmups/Crash-Override/images/flag.png)

Wow! We have the flag now!!