### Hypertext Transfer Protocol (HTTP) - 1

## What is HTTP Protocol?

Hypertext Transfer Protocol (HTTP) is a network protocol that provides communication between client and server on the web.

  
  

## Features of HTTP Protocol

- According to the OSI model, the HTTP protocol is in the 7th Layer (Application Layer).
- It uses the TCP protocol at the transport layer.
- It has a Client-Server architecture.
- The HTTP protocol is a connectionless protocol, according to the OSI model, there is no need for connection setup at the application layer level.

  
## HTTP Messages

There are 2 basic message types of the HTTP protocol:


**HTTP Request**

The HTTP request is the message sent by the client to the HTTP server. There can be 4 sections in the HTTP request:

- Request Line
- HTTP Request Headers
- A Blank Line
- Request Message Body

For example, the sections in an HTTP request are as in the image below:


**  
HTTP Response**

The HTTP response is the message sent by the HTTP server in response to the HTTP request sent by the client. There can be 4 sections in the HTTP response:

- Status Line
- HTTP Response Headers
- A Blank Line
- Response Message Body

For example, the sections in an HTTP response are as in the image below:


## HTTP Methods

HTTP methods are protocol-specific methods defined in order to perform various operations on the server. Among the many HTTP methods, a few are described below:

  
  

1. **GET Method**

HTTP Client requests a specific web page from the server to be sent to it with the GET method.

  
  

2. **POST Method**

The POST method ensures that the data assigned to the address given by the URL is accepted by the server. It transmits all the data to the server.

  
  

3. **OPTIONS Method**

The OPTIONS method allows getting the HTTP methods supported by the server.

  
  

Some of the HTTP methods are given above. You can access the list and details of the methods of the HTTP protocol at the following address:

**HTTP Methods**: [https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods) 

  
  

## HTTP Request Headers

One of the most basic parts of an HTTP request is request headers. Some request headers and descriptions are as follows:

  
  

1. **Host**

It is the header that contains the domain name of the server. In some cases, the domain name and port number may be included together.

  
  

2. **Accept**

It is the header that notifies the server of the data types accepted by the client.

  
  

3. **Accept-Language**

It is the header that notifies the server of the languages ​​that the client accepts.

  
  

4. **Accept-Encoding**

It is the header that notifies the server of the encoding algorithms supported by the client. Generally, this section contains the supported compression algorithms.

  
  

5. **Connection**

It is the header that informs the server whether the network connection will be open at the end of the process.

  
  

6. **Referer**

This header contains the information from which the address the request is directed. When clicking on the links of other addresses on the current website, this header can be added and a request can be sent.

  
  

7. **User-Agent**

With this header, the operating system information and browser information of the client is transmitted to the server.

  
  

8. **Cache-Control**

This header contains information about the control of the caching mechanism.

  
  

9. **Authorization**

It is the header that contains the credentials required for HTTP authentication.

  
  

10. **Cookie**

It is the header that contains the cookie information set by the server.

  
  

Some of the HTTP request headers are given above. You can access the list and details of the request headers of the HTTP protocol at the following address:

**HTTP Request Headers:** [https://en.wikipedia.org/wiki/List_of_HTTP_header_fields](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)


## HTTP Methods

HTTP methods are protocol-specific methods defined in order to perform various operations on the server. Among the many HTTP methods, a few are described below:

  
  

1. **GET Method**

HTTP Client requests a specific web page from the server to be sent to it with the GET method.

  
  

2. **POST Method**

The POST method ensures that the data assigned to the address given by the URL is accepted by the server. It transmits all the data to the server.

  
  

3. **OPTIONS Method**

The OPTIONS method allows getting the HTTP methods supported by the server.

  
  

Some of the HTTP methods are given above. You can access the list and details of the methods of the HTTP protocol at the following address:

**HTTP Methods**: [https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol#Request_methods) 

  
  

## HTTP Request Headers

One of the most basic parts of an HTTP request is request headers. Some request headers and descriptions are as follows:

  
  

1. **Host**

It is the header that contains the domain name of the server. In some cases, the domain name and port number may be included together.

  
  

2. **Accept**

It is the header that notifies the server of the data types accepted by the client.

  
  

3. **Accept-Language**

It is the header that notifies the server of the languages ​​that the client accepts.

  
  

4. **Accept-Encoding**

It is the header that notifies the server of the encoding algorithms supported by the client. Generally, this section contains the supported compression algorithms.

  
  

5. **Connection**

It is the header that informs the server whether the network connection will be open at the end of the process.

  
  

6. **Referer**

This header contains the information from which the address the request is directed. When clicking on the links of other addresses on the current website, this header can be added and a request can be sent.

  
  

7. **User-Agent**

With this header, the operating system information and browser information of the client is transmitted to the server.

  
  

8. **Cache-Control**

This header contains information about the control of the caching mechanism.

  
  

9. **Authorization**

It is the header that contains the credentials required for HTTP authentication.

  
  

10. **Cookie**

It is the header that contains the cookie information set by the server.

  
  

Some of the HTTP request headers are given above. You can access the list and details of the request headers of the HTTP protocol at the following address:

**HTTP Request Headers:** [https://en.wikipedia.org/wiki/List_of_HTTP_header_fields](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields)


In the image above, some of the HTTP response status codes are included. You can find the list and details of the response status codes of the HTTP protocol at the following address:

**HTTP Response Status Codes**: [https://en.wikipedia.org/wiki/List_of_HTTP_status_codes](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes) 

  
  

## HTTP Security Headers

HTTP protocol uses security headers to provide security. Some of these headers are as follows:

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options

  
  

**Note**: Although the HTTP protocol tries to provide security by using security headers, it is of particular importance that the traffic is transmitted as encrypted. They are SSL/TLS protocols that provide encrypted transmission of traffic. The specific name of the HTTP protocol, which uses SSL/TLS protocols, is HTTPS.  
  
You can find a detailed explanation of SSL/TLS protocols in the cryptology training: [Introduction to Cryptology](https://app.letsdefend.io/training/lessons/introduction-to-cryptography)

  
  

## HTTP Protocol Review with Wireshark

There are some tools with a graphical user interface (GUI) that allow network packets to be examined in detail. One of these tools is the "Wireshark" tool.

You can download the Wireshark tool from the following address:

**Wireshark:** [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)

In the images below, HTTP request headers and HTTP response headers are seen when the network packets of the HTTP protocol are examined over Wireshark:

**Note:** You can access the pcap file in the example from the "Course Files" area at the end of the course.


  
As seen in the image above, a window with HTTP request and response headers can be opened by following the "Follow" and "HTTP Stream" steps, respectively:

As seen in the image above, HTTP request headers, HTTP response headers, and body fields in the traffic of HTTP protocol were successfully displayed.

