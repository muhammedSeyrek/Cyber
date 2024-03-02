Introduction
We have prepared the Web Attacks 101 training to provide a better understanding of cyber attacks (of which 75% are web based applications) and how to respond to these attacks.

What are Web Attacks?
Web applications are applications that provide services for users through a browser interface. Today web applications make up a large portion of internet usage. Sites such as Google, Facebook and YouTube (excluding the mobile applications) are actually web applications.

Because web applications are an interface on the internet for many organizations, attackers could exploit these applications and infiltrate into devices, they could capture personal data or cause service breakdowns inflicting a serious amount of financial damage. 

A study by Acunetix determined that 75 % of all cyber attacks performed were at the web application level.

Below you will find some attack methods used to infiltrate web applications. We will address these methods in our “Web Attacks 101” course; we will explain what these methods are, how and why attackers use them and how we can detect such activities.

SQL Injection
Cross Site Scripting
Command Injection
IDOR
RFI & LFI
File Upload (Web Shell)
What skill will you gain at the end of the course?
You will gain knowledge about web  vulnerabilities such as SQL Injection, Command Injection, IDOR; knowledge about what purpose hackers use these methods for and gain the skills to identify these attack methods.

References

[1] https://www.acunetix.com/websitesecurity/web-application-attack/

### How Web Applications Work

In order to detect an anomaly we should first understand how the technology works. Applications utilize certain protocols to communicate accurately with each other. Web applications communicate via the Hyper-Text Transfer Protocol (HTTP). Let’s look into how the HTTP protocol works.

For a start, it’s important to know that the HTTP protocol is on the 7th layer of the OSI model. This means that protocols such as the Ethernet, IP, TCP, and SSL are used before the HTTP protocol.


 ![[HTTP-Protocol-TCP-IP-Model-OSI-Model.png]]

HTTP communication takes place between the server and the client. First, the client requests a specific resource from the server. The server receives the HTTP request and sends back an (HTTP Response) to the client after passing it through certain controls and processes. The client’s device receives the response and displays the requested resource in an appropriate format.

![[HTTP-Request-and-HTTP-Response.png]]

Let’s examine HTTP Requests and HTTP Responses in more detail.

  

## **HTTP Requests**

An HTTP Request is used to retrieve a certain resource from a web server. This resource may be an HTML file, video, or json data etc. The web server’s job is to process the received response and present it to the user. 

There is a standard HTTP format, and all requests must comply with this format so web servers can understand the request. If the request is sent in a different format, then the web server will not understand it and it will send an error to the user or the web server may not be able to provide service (which is another attack type).

![[HTTP-Request.png]]

An HTTP Request consists of a request line, request headers and a request message body. A request line consists of the HTTP method and the resource requested from the web server. The request header contains certain headers that the server will process. The request message body contains data that is intended to be sent to the server.

In the image above you see an example of an HTTP Request. Let’s examine this HTTP Request line by line.

1. The GET method states that the resource “/” is requested from the server. Because there is no name, rather a symbol such as “/” means that the web server’s main page is requested.
2. Nowadays there are web applications that belong to more than one domain found on a single web server, so browsers use“Host” header to describe which domain the requested resource belongs to.
3. When a web application wants to store information on the client’s device it stores it in a “Cookie” header. Cookies are generally used to store session information. Therefore, you do not have to re enter your username and password when you visit a web application that requires login. 
4. The “Upgrade-Insecure-Requests” header is used to state that the client wants to communicate with encryption (SSL).
5. There is information regarding the client’s browser and operating system under the “User-Agent" header. Web servers use this information to send specific HTTP Responses to the client. You can find some automated vulnerability scanners by looking under this header.
6. The type of data requested is found under the “Accept” header.
7. The encoding type that the client understands is found under “Accept-Encoding” header. You can usually find compression algorithm names under this header.
8. Under the “Accept-Language” header you can find the clients language information. The web server uses this information to display the prepared content in the client’s language.
9. The “Connection” header shows how the HTTP connection will be made. If there is any data such as “close” found here, it means that the TCP connection will be closed after the HTTP response is received. If you see “Keep-alive” this means that the connection will be continued.
10. An empty line is put between the HTTP Request Header and the HTTP Request Message Body to make a partition.
11. Other data intended to be sent to the web application is found within the Request Message Body. If the HTTP POST method is used, then POST parameters can be found here.

  

## **HTTP Responses**

Once the web server receives an HTTP Request, it performs the required controls and processes and then sends the requested resource to the client. There is no uniform process here because there are numerous technologies and designs involved. The server may pull data from the database according to what the requested resource is, or it can process according to incoming data. But the HTTP Response Message must reach the client after all the processing.

A HTTP Response Message contains a Status Line, Response Headers, and a Response Body. The Status Line contains the status code (such as 200: OK) and HTTP protocol information. There are headers used for numerous purposes within the Response Header.  Data related to the requested resource is found within the Response Body.

If a web page was requested, there will usually be HTML codes in the Response Body. When the client receives the HTML code, the web browser processes the HTML code and displays the web page.

![[HTTP-Response.png]]

You can see a HTTP Response request in the image above. Let’s examine a HTTP Response request based on this image.

  

**Status Line**

There is information about the HTTP version and HTTP response status code in the Status Line. HTTP response status code is used to describe the status of the request. There are many HTTP response status codes, but they can be summarized as so:

●      **100-199**: Informational responses

●      **200-299**: Successful responses

●      **300-399**: Redirection messages

●      **400-499**: Client error responses

●      **500-599**: Server error responses

  

**Response Headers**

Here are some HTTP Response Headers that you may come across frequently:

●      **Date**: The exact time the server sent the HTTP Response to the client.

●      **Connection**: It states how the connection will be handled, just like in the HTTP Request header. 

●      **Server**: Information about the server’s operating system and the web server’s version. 

●      **Last-Modified**: Information about when the requested resource was changed. This header is used for the cache mechanism.

●      **Content-Type**:  The type of data that is sent. 

●      **Content-Length**: The size of the data sent. 

  

**Response Body**

The HTTP Response Body contains the resource that was sent by the server and requested by the client.

![[HTML-example.png]]

## **What is SQL Injection (SQLi)?**

SQL Injections are critical attack methods where a web application directly includes unsanitized data provided by the user in SQL queries.


![[sql-injection.png]]

The frameworks we use these days to develop web applications have preventative mechanisms in place to protect against SQL Injection attacks. But we still come across SQL Injection vulnerabilities because sometimes raw SQL queries are used, sometimes the framework has an innate SQL Injection vulnerability or the framework is not used properly.

  

### **SQL Injection Types**

There are 3 types of SQL Injections. These are: 

1. **In-band SQLi (Classical SQLi)**: If a SQL query is sent and replied to over the same channel, we call these In-band SQLi. It is easier for attackers to exploit these compared to other SQLi categories.
2. **Inferential SQLi (Blind SQLi):** SQL queries that receive a reply that cannot be seen are called Inferential SQLi. They are called Blind SQLi because the reply cannot be seen.
3. **Out-of-band SQLi**: If the reply to a SQL query is communicated over a different channel then this type of SQLi is called Out-of-band SQLi. For example, if the attacker is receiving replies to his SQL queries over the DNS this is called an out-of-band SQLi.

  

## **How Does SQL Injection Work?**

Today standard web applications most commonly receive data from a user and use this data to display specific content. The login page is where most SQL Injection attacks happen. Let’s examine how SQL injections work through an example.

A user is generally expected to enter his/her username and password on the login page. On the other side, the web application will use this username and password information to create a SQL query like the one below:

> SELECT * FROM users WHERE username = '**USERNAME**’ AND password = '**USER_PASSWORD**'

The meaning of this SQL query is “bring me all the information about the user from the users table whose name is **USERNAME** and whose password is **USER_PASSWORD**”. If the web application does find a matching user, it will authenticate the user, if it cannot find a user after the query is performed then the login will be unsuccessful.

![[Login-page.png]]

Let’s say your username is “**john**”, and your password is “**supersecretpassword**”. When you enter this information and click on the login button the SQL query you see below will be queried and you will be able to enter because there was a match found after the SQL query.

> SELECT * FROM users WHERE username = ‘**john**’ AND password = '**supersecretpassword**'

So, what if we did not use this system the way it was designed and we put an apostrophe (‘) in the username area? The SQL query will be as below and the error will be excluded from the database because the query was faulty.

> SELECT * FROM users WHERE username = ‘**john**’’ AND password = '**supersecretpassword**'

![[SQL-Injection-login-page.png]]

An attacker would be glad to get an error message. Attacker can both manipulate the information in the error message for his own advantage and it also shows him that he is on the right path. What if the attacker enters a payload like the one below into the username area?

> ‘ OR 1=1 -- -

When the attacker sends the payload the web application will execute the following SQL query:

> SELECT * FROM users WHERE username = ‘’ OR 1=1 -- - AND password = '**supersecretpassword**'

In SQL, whatever characters come after  “-- -” will be perceived as a comment line. So if we look at the query above, the queries that come after “-- -” do not mean anything. So let’s remove this part in order to simplify things before we continue to examine the SQL query.

> SELECT * FROM users WHERE username = ‘’ OR 1=1

So now the query above looks like this: “**if the username is empty or 1=1**”. It is not really important whether the username area is left empty or not because 1 is always equal to 1. That is why this query will always be true and it will most probably call the first entry in the database. The attacker will be able to successfully enter the web application because there is a match.

This example is a typical SQL injection attack. Of course SQL injection attacks are not limited to this example, the attacker could use SQL to execute commands in the system with the help of SQL commands such as  **xp_cmdshell.**

  

## **How Attackers Leverage with SQL Injection Attacks**

In order to understand why SQL Injection attacks are so critically important, let’s take a look at what a SQL injection attack can cause.

- Authentication bypass
- Command execution
- Exfiltrating sensitive data
- Creating/deleting/updating database entries

  

## **How to Prevent SQL Injections**

- **Use a framework:** of course just using a framework will not be sufficient to prevent a SQL Injection attack. It is of utmost importance to use the framework in accordance with documentation.
- **Keep your framework up to date:** Keep your web application secure by following security updates related to the framework you use.
- **Always sanitize data received from a user:** Never trust data received from a user. On top of that do not only sanitize the form data but also do the same with other data (such as Headers, URLs, etc.)
- **Avoid using raw SQL queries:** You may have a habit of writing raw SQL queries but you should opt to make use of the benefits a framework provides and you should also make use of the security it provides.

  

## **Detecting SQL Injection Attacks**

We have discussed what attackers can do with a SQL Injection attack in the previous section. Each of the results of a SQL Injection stated above could cause great loss for an institution so as SOC Analysts we should be able to detect these attacks and be able to take precautions against them.

So, how can we detect SQL Injection attacks?

There is more than one answer to this question. These are: 

- **When examining a web request check all areas that come from the user:** Because SQL Injection attacks are not limited to the form areas, you should also check the HTTP Request Headers like User-Agent.
- **Look for SQL keywords:** Look for words like INSERT, SELECT, WHERE within the data received from users.
- **Check for special characters:** Look for apostrophes (‘), dashes (-), or parentheses which are used in SQL or special characters that are frequently used in SQL attacks within the data received from the user.
- **Familiarize yourself with frequently used SQL Injection payloads:** Even though SQL payloads change according to the web application, attackers still use some common payloads to check for SQL Injection vulnerabilities. If you are familiar with these payloads, you can easily detect SQL Injection payloads. You can see some frequently used SQL Injection payloads [here](https://github.com/payloadbox/sql-injection-payload-list).

  

### **Detecting Automated SQL Injection Tools**

Attackers use many automated devices to detect SQL Injection vulnerabilities. One of the most well known is Sqlmap. Let’s look at the wider picture instead of focusing on a specific tool.

You may use the methods listed below to detect SQL Injection devices:

1. **Look at the User-Agent:** Automated browser devices generally have their names and versions recorded. You can look at the User-Agent to detect these automated devices.
2. **Check the frequency of requests:** Automated devices were designed to send an estimated amount of many requests per second to be able to test payloads as quickly as possible. A normal user could send 1 request per second, so you can tell if the requests are made by an automated device or not by looking at the number of requests per second.
3. **Look at the contents of the payload:** Automated devices usually record their own names in their payloads. For example a SQL Injection payload sent by an automated device could look like this:  **sqlmap’ OR 1=1**
4. **Is the payload complicated:** This detection method may not always work but based on my experience, I could say that automated devices send more complicated payloads.

  

### **Detection Example**

We have access logs of a web application that was victim to a SQL Injection attack. 

You may not have heard what an access log is before. In short, these are the web server’s access logs. These logs usually contain the source IP address, date, requested URL, HTTP method, user-agent and HTTP Response code. These logs are very useful in investigations.

![[sql-injection-access-log.png]]


(SQL Injection Access Logs)

We have an access log in hand. Now what do we do?

Firstly, when we look at the pages that were requested we see that besides pages like “info.php” which is fairly readable, there are also requests made for pages that are complex and have symbols like %. We cannot say that requests for pages like these are malicious but the fact that they are made repetitively and many times is suspicious.

First of all, let’s talk about what the % symbols mean. When we request a page that contains special characters, these requests are not directly transferred to the web server. Instead, our browsers perform a URL encoding (Percent Encoding) of the special characters and replaces each special character with a character string that begins with % and has 2 hexadecimal characters in it. So the pages containing the % symbol above are pages that contain special characters.


![[URL-Encoding.png]]

Now that we understand what the % symbols mean, let’s revisit the access logs. When we look at the requests, we can easily see that besides the % symbols there are readable words such as “UNION”, “SELECT”, “AND”, “CHR”.  Because these are specific words that belong to SQL, we can determine that we are face to face with a SQL Injection attack.

To save our eyes, let’s make the examination a little easier :) You can conduct a search using the keywords “Online URL Decoder” to find web applications that will automatically do the URL decoding for you. In order to read these access logs easier I will get help from these web applications, by doing so I won’t have to strain my eyes or yours.

Let me add a little note. It is not wise to upload something like an access logs which contain critical information on a 3rd party web application. The access logs I uploaded were prepared specifically for this training so there is no problem in my doing so. But you shouldn’t make such mistakes in your professional life.

![[Access-logs-with-URL-decoding.png]]

When we do the URL decoding we can more clearly see that this is a SQL Injection attack. So what should we do now? Yes, we have confirmed that it is a SQL Injection attack but do we leave it there?

Of course not. Now we are going to find any other pieces of information that we can from these access logs.


![[sql-injection-access-logs-date.png]]

First, let’s look at the request dates. All the SQL Injection payloads were sent on “19/Feb/2022 11:09:24”. We can see that more than 50 requests were made in 1 second. The fact that so many requests were made in such a short time shows us that this is an automatized attack. Additionally, as we have mentioned before, when attackers perform manual tests they choose to test easy payloads first. But when we look at the access logs we see that the payloads are very complicated. This goes to show that the attack may very well be automated.

We have confirmed that a SQL Injection attack has been performed and that it has been performed with an automated device. So we can end our analysis, right?

There is one more step left to do. We need to determine whether the attack was successful or not. You can determine whether a SQL Injection attack has been successful by looking at the response but in your professional career you will almost never have access to the response. We can presume that all responses will be about the same size because the attack is performed on the same page and over the “id” variable. We can estimate the success of the attack by looking at the size of the response.

Unfortunately, the basic web server that was developed to serve as an example cannot supply a reliable response size. Therefore, we cannot estimate if the attack has been successful looking at this example. But with web servers that have been configured correctly, we can find the response size within the access logs. You can examine this area to determine whether there is a notable difference in response sizes. If there is a notable difference you can estimate that the attack has been successful. But in this situation it would be best to escalate this alert to a higher-tier analyst.

What we know:

1. There has been a SQL Injection attack performed on the “id” parameter on the web application’s main page.
2. The requests came from the IP address: 192.168.31.174.
3. Because there have been 50+ requests per second, this attack has been performed by an automated vulnerability scanning tool.
4. The complex nature of the payloads supports the claim in # 3.
5. We cannot determine whether the response was successful or not because we do not have any information about the response size.


### Detecting Cross Site Scripting (XSS) Attacks

## **What is Cross Site Scripting (XSS)?**

Cross Site Scripting (XSS), is a type of injection based web security vulnerability that is included in legitimate web applications and enables malicious code to be run.

![[xss.png]]

Today most frameworks that are used to develop web applications have taken preventative measures against cross-site scripting attacks. But we still frequently see XSS vulnerabilities today because frameworks are sometimes not used, or the framework itself has an XSS vulnerability and the data coming from the user is not sanitized.

  

### **XSS Types**

There are 3 different types of XSS. These are: 

1. **Reflected XSS (Non-Persistent)**: It is a non-persistent XSS type that the XSS payload must contain in the request. It is the most common type of XSS.
2. **Stored XSS (Persistent)**: It is a type of XSS where the attacker can permanently upload the XSS payload to the web application. Compared to other types, the most dangerous type of XSS is Stored XSS.
3. **DOM Based XSS**: DOM Based XSS is an XSS attack wherein the attack payload is executed as a result of modifying the DOM “environment” in the victim’s browser used by the original client side script, so that the client side code runs in an “unexpected” manner. (OWASP)

  

## **How XSS Works?**

Just like other web attack methods, XSS is a security vulnerability that happens due to the lack of data sanitization. XSS vulnerability occurs when the data received from the user is sent in the response without sanitizing.

Let’s follow an example to better understand XSS attacks.


![[XSS-vulnerable-code.png]]

Let’s look at the piece of code above. What it does is actually very basic. It merely displays whatever is entered in the ‘user’ parameter. If we enter “LetsDefend” as the ‘user’ parameter, we will see the words “Hello LetsDefend”.


![[XSS-image-1.png]]

Up till now, there is no problem. If we enter the appropriate data in the user parameter, we are greeted with a warm salutation. But, as we have seen above, there is no control mechanism for the user parameter. This means that whatever we enter in the “user” parameter will be included in the HTTP Response that we receive back.

So,what would happen if we didn’t enter a normal value but instead we entered a payload that would summon a pop-up?

Payload: **<script>alert(1)</script>**

![[XSS-popup.png]]

Because whatever we enter in the “user” parameter is directly included in the HTTP Response, the javascript code we wrote worked and a pop-up window appeared on the screen.

So, this is exactly how XSS works. Because the value entered by the user is not confirmed, the attacker may enter whatever javascript code he likes and get the result he wants. What if the attacker wants to redirect the user to a malicious site?

Payload: **<script>window.location=’https://google.com’</script>**

https://letsdefend.io/xss_example.php?user=%3Cscript%3Ewindow.location=%27https://google.com%27%3C/script%3E


![[XSS-google-redirect-1.png]]

Of course we are not going to direct you to a web application. Directing you to Google will be sufficient as an example. When the user clicks on the URL he will be directed to Google instead of the perfect LetsDefend web application.

![[XSS-google-redirect-2.png]]

## **How Attackers Leverage with XSS Attacks**

Because XSS is a client-based attack method, it may seem less important than other attack methods but XSS attacks and their impact should not be taken for granted.

Attackers can do the following with an XSS attack:

- Steal a user’s session information
- Initiate processes that a user can     
- Capture credentials

…and other various functions.

  

## **How to Prevent a XSS Vulnerability**

- **Sanitize data coming from a user:** Never trust data coming from a user. If user data needs to be processed and saved it should be encoded with html encoding using special characters and only then should it be saved.
- **Use a framework:** Most frameworks come with preventive measures against XSS attacks.
- **Use the framework correctly:** Almost all frameworks used to develop web applications come with a sanitation feature but if this is not used properly there still is a chance for XSS vulnerabilities to occur. 
- **Keep your framework up to date:** Frameworks are developed by humans so they too may contain XSS vulnerabilities. But these kinds of vulnerabilities are usually patched by security updates. So you should make sure that you have completed your framework’s security updates.

  

## **Detecting XSS Attacks**

Like we mentioned in the previous article, according to a study done by Acunetix, 75% of cyber attacks are performed over web applications. Because XSS is one of the most frequently tested vulnerabilities, you will be seeing a lot of these during your career as a SOC analyst.

- **Look for keywords:** The easiest way to catch XSS attacks is to look for keywords such as “alert” and “script” which are commonly used in XSS payloads.
- **Familiarize yourself with frequently used XSS payloads:** Attackers primarily use the same payloads to look for vulnerabilities before they exploit a XSS vulnerability. This is why familiarizing yourself with frequently used XSS payloads would make it easier for you to detect XSS vulnerabilities. You can examine some frequently used payloads [here](https://github.com/payloadbox/xss-payload-list). 
- **Check if any special characters have been used:** Check data coming from a user to see if any special characters that are frequently used in XSS payloads like greater than (>) or lesser than (<) are present. 

  

### **Example of a Detection**

In this example, we see access logs from an Apache server with Wordpress. Don’t forget to revisit our article on “Detecting SQL Injection Attacks” for more information about access logs.

![[XSS-apache-access-log.png]]

Now, let’s examine the access logs that have been provided. 

Firstly, let’s take a general look at the requests that have been made and try to understand them. We see that all the requests have been made for the “/blog/” page and that only the “s” parameter values have been changed. If you pay attention to the URLs of the web pages you visit, you would have noticed that when you perform a search in Wordpress, the words you enter are sent using the “?s=” parameter. The example we are looking at shows us that these are searches performed in Wordpress.

It is hard to find easily readable examples like the example in the “Detecting SQL Injection Attacks” article. Instead, we find characters that have transformed into %XX as a result of URL encoding. We will perform URL decoding next but first let’s take a look at the URLs and try to see if we can recognize any words.

When we look at the logs, we notice javascript related words such as “script”, “prompt”, and “console.log”. When we see javascript it immediately brings XSS to mind. If we do a URL decoding we will easily be able to understand the requests that are made.


![[xss-apache-access-log-with-url-decoding.png]]

When we take another look at the access logs after performing a URL decoding we clearly see the XSS payloads. We can definitely say that the Wordpress application which we got these access logs from has become the victim of a XSS attack.

When we look at the requested IP addresses, we see there are more than one. Are more than one attackers trying to perform a XSS attack simultaneously? Or is the attacker constantly changing his IP address to avoid being blocked by security products such as firewalls and IPS? If you check the IP address you will see that it belongs to Cloudflare. Because the Wordpress application has been put behind Cloudflare, it is quite normal that Cloudflare is making the request.

![[xss-apache-access-log-date.png]]

When we examine the dates of the requests, we find that there was a request made every 3-4 seconds. It is not really possible for a human to try to enter this many XSS payloads in such a short time but you may not be able to be sure that the number of requests made per second is excessive. We are lucky because we have the User-Agent information in this example. If we examine this information we see that it belongs to a urllib library. This shows us that these requests were made through an automated vulnerability scanner tool.

So was the attack successful? 

We cannot say anything definite because we don’t have access to the responses. 

As a result of our examinations: 

1. It is determined that the attack targeted the web application where the access logs came from.
2. After looking at the amount of requests and the User-Agent information we determined that the attack was performed by an automated vulnerability scanner.
3. Because the application is behind Cloudflare the source IP addresses were not found.
4. We do not know whether the attack was successful or not.

### Detecting Command Injection Attacks

## **What are Command Injection Attacks?**

Command Injection Attacks are attacks that happen when the data received from a user is not sanitized and is directly transmitted to the operating system shell.

![[command-injection.png]]

Attackers exploit command injection vulnerabilities to directly execute commands on the operating system. The fact that the attacker’s priority is to take control of the system makes these vulnerabilities more critical than other vulnerabilities.

Because the command that the attacker sends will be using the rights of the web application user, a misconfigured web application would grant the attacker access with admin rights. 

  

## **How Command Injection Works?**

Command injection vulnerabilities happen when the data received from the user is not sanitized. Let’s examine command injection vulnerabilities with an example.

Let’s say we have a basic web application that copies the user’s file in the “/tmp” folder. The web application’s code is below.

![[web-application-code-example.png]]

Under normal conditions the application will work normally if used accurately. For example if we load a file named “letsdefend.txt” it will successfully copy the file to the “/tmp” folder.

So, what will happen if we upload a file named “letsdefend;ls;.txt”? The command would become:

Command: **cp letsdefend;ls;.txt**

 “;” signifies that the command has ended. So when we look at the payload above, there are three different commands that the operating system executes. These are:

1. cp letsdefend
2. ls
3. .txt 

![[command-injection-example.png]]

The first command is for the copying process but if the parameters are not entered correctly it will not work correctly.

Command #2 is the directory listing command the attacker wants to execute. The user does not receive the command output so the attacker cannot see the files in the directory but the operating system successfully executes the command.

When the operating system wants to execute command number 3 there will be an error message because there is no “.txt” command.

As you see, the code has been executed in the web server’s operating system. So, what if the attacker uploads a file named ““letsdefend;shutdown;.txt”? The operating system would shut itself down, and the web application will not be able to function.

The attacker can create a reverse shell in the operating system with the help of the accurate payload.

  

## **How Attackers Leverage with Command Injection Attacks**

Attackers can execute commands on an operating system by exploiting command injection vulnerabilities. This means that the web application and all other components on the server are at risk.

  

## **How to Prevent Command Injection**

- **Always sanitize data received from a user:** Never trust data received from a user. Not even a file name!
- **Limit user rights:** Adjust web application user rights to a lower level whenever possible. Hardly any web application requires the user to have admin rights. 
- **Make use of virtualization technologies such as dockers**

  

## **Detecting Command Injection Attacks**

I think we all understand the criticality level of Command Injection vulnerability very well. If such a critical vulnerability is exploited and gone undetected the company involved may lose a great amount of money and reputation.

So, how can we detect Command Injection Attacks? 

There is more than one way. These are: 

- **When examining a web request look at all the areas:** The command injection vulnerability may be located in various areas depending on the operation of the web application. This is why you should check all areas of the web request.
- **Look for keywords related to the terminal language:** Check the data received from the user for keywords that are related to terminal commands such as: dir, ls, cp, cat, type, etc.
- **Familiarize yourself with frequently used Command Injection payloads:** When attackers detect a command injection vulnerability they usually create a reverse shell in order to work more easily. This is why knowing frequently used Command Injection payloads will make it easier to detect a command injection attack .

  

### **Detection Example**

In this example we will not be looking at access logs, rather we will be examining a HTTP Request.

> GET / HTTP/1.1
> 
> Host: yourcompany.com
> 
> User-Agent: () { :;}; echo "NS:" $(</etc/passwd)
> 
> Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
> 
> Accept-Encoding: gzip, deflate
> 
> Accept-Language: en-US,en;q=0.9
> 
> Connection: close

If we look at the HTTP Request above, we see that the main page of the web application yourcompany[.]com has been requested.

But when we look at the HTTP Request Headers we see a suspicious situation in  the User-Agent header. There is a bash command in the User-Agent header whereas there should be browser/operating system information here.

Actually, this request was captured during the exploitation of a vulnerability named Shellshock. Shellshock is a security weakness that was published in 2014 and had great effects. 

Shellshock is a security vulnerability that originates from bash somehow involuntarily executing  Environment Variables. Shellshock is a great example of a command injection attack. 

When the bash command which is located within User-Agent is executed, the “/etc/passwd” file’s contents will be returned to the attacker in the HTTP Response header as “NS”.

### Detecting Insecure Direct Object Reference (IDOR) Attacks

## **What is IDOR?**

**I**nsecure **D**irect **O**bject **R**eference (IDOR), is a vulnerability caused by the lack of an authorization mechanism or because it is not used properly. It enables a person to access an object that belongs to another.

![[idor.png]]

Among the highest web application vulnerability security risks published in the 2021 OWASP, IDOR or “Broken Access Control” takes first place. 


## **How IDOR Works**

IDOR is not a security vulnerability caused by unsanitary conditions like other web application based security vulnerabilities. The attacker manipulates the parameters sent to the web application, gains access to an object that doesn’t belong to himself and is able to read, change or erase the contents. 

Here’s an example to better understand how the IDOR vulnerability is exploited.

Let’s imagine a basic web application. It retrieves the “**id”** variable from the user, then it displays data that belongs to the user who made the request. 

URL: **https://letsdefend.io/get_user_information?id=1**

When a request is made in our web application, like the one above, it displays the information of the user with an id value of 1.

If I am the user who made the request and my id value is 1 everything will work normally. When I make the request I will see my personal information.

But what happens if we make a request with 2 as the “id” parameter? Or 3?

If the web application is not controlling: “Does the “id” value in the request belong to the person making the request?” then anyone can make this request and see my personal information.This web vulnerability is called IDOR.

Attackers can reach objects that do not belong to themselves by changing parameters like the  “id”. What kind of  information they can gain access to may change according to the web application but either way you wouldn’t want anyone to access your personal information, right?

  

## **How Attackers Leverage with IDOR Attacks**

What an attacker can do is limited by the area of an IDOR vulnerability. But the most common areas they are seen are usually pages where a user’s information is received. If an attacker exploits an IDOR vulnerability he could:

- Steal personal information
- Access unauthorized documents 
- Conduct unauthorized processes (For example: deletion, alteration) 

# How to Prevent IDOR

In order to establish a secure environment without an IDOR vulnerability you should always check if the person who made the request has any authority.

On top of this, unnecessary parameters should be removed and only the least amount of parameters should be taken away from the user. If we think about the previous example, we don’t need to get the “id” parameter. Instead of getting the  “id” parameter from user, we can identify the person who made the request using the session information.

  

## **Detecting IDOR Attacks**

IDOR attacks are more difficult to detect than other attacks. Because it does not have certain payloads such as SQL Injection and XSS.

Having the HTTP Response at hand would help to identify IDOR attacks. But HTTP Responses are not logged for various reasons and thus it is harder to identify IDOR attacks.

There are a couple of methods used in identifying IDOR attacks. These are:

- **Check all parameters:** an IDOR vulnerability may occur in any parameter. This is why you should not forget to check all parameters.
- **Look at the amount of requests made for the same page:** When attackers detect an IDOR vulnerability they also want to access the information related to all other users so they usually perform a brute force attack. This is why you may see many requests made for the same page from one source.
- **Try to find a pattern:** Attackers will plan a brute force attack to reach all objects. Because they will perform the attack on successive and foreseeable values like integer values you can try to find a pattern in these requests. For example: if you see requests such as id=1, id=2, id=3, you may suspect something.

  

### **Detection Example**

Below you can see a screen image of logs found on a web server running Wordpress.


![[idor-apache-access-log.png]]

As in our other examples, let’s start with a general, broad based examination. Because there are no special characters included in the requests that were made we can easily read the logs.

If you have used the Wordpress application before you might know that the “wp-admin/user-edit.php?user_id=” page contains information about registered Wordpress users. It could be seen as normal to be able to access this page, in fact if you have more than one user you may be gaining access with more than one “user_id: parameter. But it is not normal to have this many different “user_id” parameters. 

It looks like we have an IDOR attack on our hands.

When we look at what the source IP was we see it belongs to Cloudflare. This means that the web application that we received the access log for was using a Cloudflare service. This is why the requests were transmitted to the web application through Cloudflare.

We see 15-16 requests within the short time frame that access logs are recorded and this shows us that the attack is performed with an automated device. If we look at the User-Agent header we can see it says “wfuzz/3.1.0”. Wfuzz is a device that is frequently used by attackers. We did not only determine that this attack was performed by an automated scanner tool, we also determined that it was performed by a tool named Wfuzz.

But we still haven’t answered the most important question. Has the attack been successful? 

Was the attacker able to gain access to the users’ information?

Our job would be easier if we had the HTTP Responses. Because we don’t have the HTTP Responses let’s look at the response size in the Access Logs and make an inference.

Like we mentioned before, the requested page was displaying user information. Information such as the users’ names, last names and usernames’ total size will not be the same. This is why we can ignore requests with a response size of 479 bytes.

If we look at the requests with a response size of 5691 and 5692, we see that the response code will be 302 (redirect). Successful web requests will generally be answered with the response code 200. So we can say that the attack was not successful. But this information alone may not be sufficient to determine the attack as unsuccessful.

There are 10 requests with the response size of 5692 and 4 with the response size of 5691.

Like we stated before, there is a very low possibility for the total of all information like the user’s name, last name, username to be equal. This strengthens the possibility that the attack was not successful.


### Detecting RFI & LFI Attacks

## **What is Local File Inclusion (LFI)?**

Local File Inclusion (LFI), is the security vulnerability that occurs when a file is included without sanitizing the data obtained from a user. It differs from RFI because the file that is intended to be included is on the same web server that the web application is hosted on.

Attackers can read sensitive files on the web server, they can see the files that contain passwords that would enable them to reach the server remotely.

  

## **What is Remote File Inclusion (RFI)?**

Remote File Inclusion (RFI), is the security vulnerability that occurs when a file is included without sanitizing the data obtained from a user. It differs from LFI in that the file that is intended to be included is hosted on a different server.

The attackers host malicious codes on their prepared server and they invite the victim website over the remote server and try to get it to execute.

  

## **How LFI & RFI Works?**

Just like most web application based vulnerabilities, LFI and RFI also have vulnerabilities caused by not sanitizing data received from a user. 

SQL Injection vulnerabilities occur when data received from a user is entered in SQL queries; Command Injection vulnerabilities happen when data received from a user is executed directly in the system shell; IDOR vulnerabilities occur when data received from a user is used to directly access objects. RFI and LFI vulnerabilities are caused by the use of data received from a user directly in the system or to include a file on a remote server.

Why would data received from a user be used to include a file? Web applications have become highly complicated and unfortunately each feature that is developed is used for malicious purposes. The language option found in web applications is used in order to include files based on data received from a user.

![[local-file-inclusion-code-example.png]]

If we examine the piece of code in the image above, we see that the desired website language is selected by using the “language” parameter received from the user. 

In a normal situation the web application will work as planned. For example if “en” is entered as the “language” parameter we will receive the file seen below.

“website/**en**/home.php”

But if an attacker enters the payload seen below into the “language” parameter then unfortunately the web application will display the “/etc/passwd” file to the user.

Payload: **/../../../../../../../../../etc/passwd%00**

“website/**/../../../../../../../../../etc/passwd%00**/home.php

“../” is used to go to the parent directory. Because the attacker does not know what directory the web application is in, he tries hard to reach the “root” directory using “../”. Later, he names the “/etc/passwd” file and enables the inclusion of the file within the web application. “%0” is used to end the string. This way, the remaining “/home.php” string is not read by the web application.

  

## **How Attackers Leverage with RFI & LFI**

- Code execution
- Sensitive information disclosure
- Denial of service

  

## **How to Prevent LFI & RFI**

The most effective way to prevent RFI and LFI attacks is to sanitize any data received from a user before using it. Do not forget that client based controls are easily bypassed. This is why you should always do your controls on both the client-side and the server-side.

  

## **Detecting LFI & RFI Attacks**

We previously mentioned what attackers can accomplish with RFI and LFI attacks. Because a company can experience a great deal of loss due to the exploitation of such vulnerabilities we should be able to detect such attacks and take precautions. 

How can we detect and prevent LFI and RFI attacks?

- **When examining a web request from a user, examine all the fields.**
- **Check for any special characters:** Within the data that is received from users, especially look for notations such as ‘/’,  `.`, `\`.
- **Familiarize yourself with files frequently used in LFI attacks:** In an LFI attack the attacker reads the files that are on the server. If you familiarize yourself with the critical file names on the server, you can detect LFI attacks more easily.
- **Search for acronyms such as HTTP and HTTPS:** In RFI attacks the attacker includes the file on his own device and enables the file to execute. 
- In order to include a file, attackers usually set up a small web server on their own device and display the file over an HTTP protocol. This is why you should search for notations such as “http” and “https” to be able to detect RFI attacks more easily.


