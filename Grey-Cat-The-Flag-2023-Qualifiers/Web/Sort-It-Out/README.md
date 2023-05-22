# Sort It Out

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)

## Overview

- 21 solves / 428 points
- Overall difficulty for me (From 1-10 stars): ★★★★★★★★★★

## Background

I enrolled in a data structures class in order to buff up my programming skills to complete my Indie Anime Stealth Action Video Game. I'm learning about sorting algorithms and their various time complexities now. Cool stuff!

[http://34.124.157.94:10556/](http://34.124.157.94:10556/)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521132030.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521132113.png)

In here, we can choose a file to shuffle, which is doing a sorting algorithm.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521132135.png)

When we submit a file, it returns 10 sorting algorithm's time.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/Web/Sort-It-Out/sort-it-out-dist.zip):**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Sort-It-Out)-[2023.05.21|13:25:51(HKT)]
└> file sort-it-out-dist.zip   
sort-it-out-dist.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Sort-It-Out)-[2023.05.21|13:25:52(HKT)]
└> unzip sort-it-out-dist.zip   
Archive:  sort-it-out-dist.zip
   creating: dist/
  inflating: dist/.dockerignore      
  inflating: dist/docker-compose.yml  
  inflating: dist/Dockerfile         
 extracting: dist/flag               
  inflating: dist/readflag.c         
   creating: dist/src/
  inflating: dist/src/alice_in_wonderland.txt  
  inflating: dist/src/index.php      
  inflating: dist/src/quotes.txt     
  inflating: dist/src/words_shuffled.txt     
```

**In `dist/readflag.c`, it's a C programe that reads the flag:**
```c
#include <stdio.h>

int main() {
    FILE *fp;
    char flag[100];

    fp = fopen("/flag", "r");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }

    fgets(flag, 100, fp);
    printf("%s\n", flag);

    fclose(fp);
    return 0;
}
```

That being said, **this challenge requires Remote Code Execution (RCE), and get an interactive shell to read the flag.**

**`dist/src/*.txt`:**
```shell
┌[siunam♥earth]-(~/ctf/Grey-Cat-The-Flag-2023-Qualifiers/Web/Sort-It-Out)-[2023.05.21|13:29:20(HKT)]
└> head -n 5 dist/src/*.txt
==> dist/src/alice_in_wonderland.txt <==
Alice's Adventures in Wonderland

                ALICE'S ADVENTURES IN WONDERLAND

                          Lewis Carroll

==> dist/src/quotes.txt <==
If you want to achieve greatness stop asking for permission. ~Anonymous
Things work out best for those who make the best of how things work out. ~John Wooden
To live a creative life, we must lose our fear of being wrong. ~Anonymous
If you are not willing to risk the usual you will have to settle for the ordinary. ~Jim Rohn
Trust because you are willing to accept the risk, not because it's safe or certain. ~Anonymous

==> dist/src/words_shuffled.txt <==
Ripley's
Wisconsinite
despicable
consortia
reunite
```

In `dist/src/index.php`, we see the web application's main logic.

**When the POST parameter `filename` is provided, it'll do the following stuff:**
```php
<?php
[...]
function bubbleSort($arr) {
[...]
function selectionSort($arr) {
[...]
function insertionSort($arr) {
[...]
function mergeSort($arr) {
[...]
function merge($left, $right) {
[...]
function quickSort($arr) {
[...]
function heapSort($arr) {
[...]
function heapify(&$arr, $n, $i) {
[...]
if (isset($_POST['filename'])) {
    $filename = $_POST['filename'];
    $contents = file_get_contents($filename);
    $arr = explode("\n", $contents);

    // god i wish there was an easier way to do this
    $arr_copy = $arr;
    $start = microtime(true);
    sort($arr_copy);
    $end = microtime(true);
    $sort_time = $end - $start;

    [...]
    $arr_copy = bubbleSort($arr_copy);
    [...]

    [...]
    $arr_copy = selectionSort($arr_copy);
    [...]

    [...]
    $arr_copy = insertionSort($arr_copy);
    [...]

    [...]
    $arr_copy = mergeSort($arr_copy);
    [...]

    [...]
    $arr_copy = quickSort($arr_copy);
    [...]

    [...]
    $arr_copy = heapSort($arr_copy);
    [...]
    
    $start = microtime(true);
    exec("sort " . escapeshellcmd($filename));
    $end = microtime(true);
    $sort_utility_time = $end - $start;

    echo "<table>";
    echo "<tr><th>Algorithm</th><th>Time</th></tr>";
    echo "<tr><td>PHP sort</td><td>$sort_time</td></tr>";
    echo "<tr><td>Bubble sort</td><td>$bubble_sort_time</td></tr>";
    echo "<tr><td>Selection sort</td><td>$selection_sort_time</td></tr>";
    echo "<tr><td>Insertion sort</td><td>$insertion_sort_time</td></tr>";
    echo "<tr><td>Merge sort</td><td>$merge_sort_time</td></tr>";
    echo "<tr><td>Quick sort</td><td>$quick_sort_time</td></tr>";
    echo "<tr><td>Heap sort</td><td>$heap_sort_time</td></tr>";
    echo "<tr><td>GNU sort</td><td>$sort_utility_time</td></tr>";
    echo "</table>";
}
?>
```

**It might seem intimidating, but we can just focus on 2 things:**
```php
<?php
[...]
    $filename = $_POST['filename'];
    $contents = file_get_contents($filename);
    $arr = explode("\n", $contents);
    [...]
    $start = microtime(true);
    exec("sort " . escapeshellcmd($filename));
    $end = microtime(true);
    $sort_utility_time = $end - $start;
```

When the POST parameter `filename` is provided, it'll use `file_get_contents()` function to read the file's contents into a string.

After that, it splits the file's contents via delimiter new line (`\n`).

**In the "GNU sort" sorting algorithm, it's using the `sort` command with our provided `filename`'s value to do sorting.**

However, our `filename` is being escaped by `escapeshellcmd()` function, which escapes shell metacharacters.

**According to [PHP's documentation](https://www.php.net/manual/en/function.escapeshellcmd), it said:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/Grey-Cat-The-Flag-2023-Qualifiers/images/Pasted%20image%2020230521134651.png)

With that said, we're no luck for OS command injection?

Maybe we can leverage the `sort` command's ***arguments***? This is also called "**Argument Injection**"

But... No dice... I tried to use `--compress-programe` and other arguments to gain RCE...

We can also use the `-o` or `--output` to output a file. But after we done that, how can we even exfiltrate it's contents??