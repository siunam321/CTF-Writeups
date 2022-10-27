# Juggling Facts

## Background

> An organization seems to possess knowledge of the true nature of pumpkins. Can you find out what they honestly know and uncover this centuries-long secret once and for all?

> Difficulty: Easy

- Overall difficulty for me: Hard

**In this challenge, we can spawn a docker instance and [download a file](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/web_juggling_facts.zip):**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a1.png)

```
┌──(root🌸siunam)-[~/ctf/HackTheBoo/Web/Juggling-Facts]
└─# unzip web_juggling_facts.zip 
Archive:  web_juggling_facts.zip
   creating: web_juggling_facts/
  inflating: web_juggling_facts/entrypoint.sh  
   creating: web_juggling_facts/challenge/
  inflating: web_juggling_facts/challenge/Database.php  
   creating: web_juggling_facts/challenge/views/
  inflating: web_juggling_facts/challenge/views/index.php  
   creating: web_juggling_facts/challenge/static/
   creating: web_juggling_facts/challenge/static/css/
  inflating: web_juggling_facts/challenge/static/css/index.css  
   creating: web_juggling_facts/challenge/static/js/
  inflating: web_juggling_facts/challenge/static/js/index.js  
  inflating: web_juggling_facts/challenge/Router.php  
   creating: web_juggling_facts/challenge/models/
  inflating: web_juggling_facts/challenge/models/FactModel.php  
  inflating: web_juggling_facts/challenge/models/Model.php  
   creating: web_juggling_facts/challenge/controllers/
  inflating: web_juggling_facts/challenge/controllers/Controller.php  
  inflating: web_juggling_facts/challenge/controllers/IndexController.php  
  inflating: web_juggling_facts/challenge/index.php  
   creating: web_juggling_facts/config/
  inflating: web_juggling_facts/config/nginx.conf  
  inflating: web_juggling_facts/config/supervisord.conf  
  inflating: web_juggling_facts/config/fpm.conf  
  inflating: web_juggling_facts/build-docker.sh  
  inflating: web_juggling_facts/Dockerfile
```

## Find the flag

**Home page:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a2.png)

When I press the `Secret Facts`, it shows: `Secrets can only be accessed by admin`.

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a3.png)

**`IndexController.php`:**
```php
<?php

class IndexController extends Controller
{
    public function __construct()
    {
        parent::__construct();
    }

    public function index($router)
    {
        $router->view('index');
    }

    public function getfacts($router)
    {
        $jsondata = json_decode(file_get_contents('php://input'), true);

        if ( empty($jsondata) || !array_key_exists('type', $jsondata))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);

            case 'spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('spooky')
                ]);
            
            case 'not_spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('not_spooky')
                ]);
            
            default:
                return $router->jsonify([
                    'message' => 'Invalid type!'
                ]);
        }
    }
}
```

But I don't see anything that is vulnerable... I thought it's doing some `REMOTE_ADDR` bypass, but no dice.

Let's take a step back.

**Since this challenge's name is `Juggling Facts`, I'll google `php juggling`:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a4.png)

**PHP juggling exploit? I never seen this before.**

Now, we can dig deeper in this exploit: [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling).

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a5.png)

**Sweat! It seems like the `IndexController.php` is vulnerable?**

**Let's look at the switch statement:**
```php
        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);
```

**The first if statement is NOT vulnerable, as it's using strict comparison (`===`, `!==`). So, we have to parse the `type` POST parameter.**

**However, the `switch` statement is vulnerable.**

According to offical [PHP documentation](https://www.php.net/manual/en/control-structures.switch.php), **switch/case does [loose comparison](https://www.php.net/manual/en/types.comparisons.php#types.comparisions-loose).**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a6.png)

**It also includes a loose comparison table:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a7.png)

**Hmm... What if I send a POST request JSON value: `{"type":true}`?**

**Since the case `secrets` is the first item, it can bypass the `REMOTE_ADDR`!**

**Let's intercept the POST request in Burp Suite, and change the `type` to `true`!**

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a8.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a9.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/HackTheBoo/Web/Juggling-Facts/images/a10.png)

Yes! We got the flag!

# Conclusion

What we've learned:

1. Exploiting PHP Type Juggling