## What is FTP Protocol?

File Transfer Protocol (FTP) is a network protocol that provides file transfer between devices.
## Features of FTP Protocol

- According to the OSI model, the FTP protocol is located in the 7th Layer (Application Layer).
- It uses the TCP protocol at the transport layer.
- It has a Client-Server architecture.
- Different operating systems can use it.
- For file transfer with FTP protocol, a connection must be established first.
- While establishing the FTP connection, the authentication process that provides basic security is performed using a username and password.
- FTP does not encrypt its traffic; all transmissions are in clear text, and usernames, passwords, commands, and data can be read by anyone able to perform packet capture (sniffing) on ​​the network. (Source: Wikipedia)
- Provides data representation diversity (like ASCII and EBCDIC).

## FTP Commands

The FTP protocol uses some commands while performing its tasks. Some of these commands are explained below:  
  

1. **USER Command**

The USER command is the command that determines which user to connect to the FTP Server.


2. **PASS Command**

The PASS command is the command that gives the password of the user provided with the USER command for the connection to the FTP Server.


3. **HELP Command**

It is the command that provides information about the usage of commands. If used without parameters, a list of commands is displayed.

  
4. **PWD Command**

The PWD command is the command that shows which directory it is working on.

  
5. **RETR Command**

The RETR command is the command used to initiate the file transfer process.

  
6. **STOR Command**

It is the command used to transfer the specified file to the server.

  
7. **LIST Command**

It is the command that lists the names and properties of the directory and files under the current directory.


8. **QUIT Command**

It is the command that terminates the FTP connection.

## File Transfer with FTP

Transferring files using the FTP protocol is very convenient and simple. Some configurations are required to be able to transfer files. For example, the port to be used on the system where the FTP server is installed (the default FTP port TCP 21 is used in the example below) may need to have a firewall rule in the configuration on the firewall to allow incoming requests.

**Note:** The topic of firewall configuration on Windows is included in the "Windows Fundamentals" training. You can access it from the link below: