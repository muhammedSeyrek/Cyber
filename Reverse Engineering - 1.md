# Preliminary Information about Reverse Engineering Fundamentals Course

Cyber threats identified by SOC analysts can sometimes go far beyond the network access and network breach. Threat Hunters who are actually the Blue Team members can detect malware on servers or endpoints within the organization. It is very important to obtain detailed information about the activities of the malicious element detected to eradicate it from the network before spreading to other systems and reduce the damage that may cause in the organization. After the malicious file is exported from the infected system, it is delivered to the Malware Analyst, a SOC member, for analysis. Malware Analyst examines the malware with reverse engineering techniques in order to detect the malicious activities of the malware. This is simply how the malware behaviors are analyzed and necessary actions and precautions are taken.  
  
In this training, the basics of reverse engineering are explained in a simple way. This course is an entry-level course. Candidates who do not have any enough knowledge about reverse engineering and would like to start learning about it technically about this subject are recommended to complete this training carefully.

# Introduction to Reverse Engineering

## **How Should You Follow this Training?**

First of all, please note that this training is an introduction to the advanced subject of "Reverse Engineering" and it is assumed that you have some background information regarding it. For example, assuming you know the basics in computer science, only reverse engineering is covered in the training.

  
  

## **Regarding the Training Chapters**

  
  

**Reverse Engineering Basics**

Under this topic, we will cover what Reverse Engineering is, when and why reverse engineering techniques are used and its importance for blue team are explained. We will cover, the sample lab environment and tools that can be used for reverse engineering in the last part of this section.

  
  

**Basic Concepts**

Under this topic, we will cover the basic reverse engineering concepts that you will encounter while working on reverse engineering and practical examples about them.

  
  

**Memory Layout**

It is important to have some foundational background information on how the basic computer hardware and software function in order to be able to work on reverse engineering. Under this topic, we will cover the components of memory and their functioning.

  
  

**Sample C Program**

To have a thorough understanding of C programming language is one of the most important steps to be able to start learning about reverse engineering because the C programming language is the system programming language that is closest to the assembly language, which is very similar to machine code, and it is the most appropriate and necessary programming language to be able to understand  the reverse engineering. Under this topic, we will cover the C programming language as well as the Ghidra tool.

  
  

**C Binary Decompiling with Ghidra**

We will cover how to decompile C binary files with the Ghidra tool which is an important tool for reverse engineering.

  
  

In this part of the training, general information about the training content and sections is given. In the next part of the training, the subject of “**Reverse Engineering Basics**” is explained.


### Reverse Engineering Basics

## **What is Reverse Engineering?**

Reverse engineering is the analysis that helps determine what operations are the programs running when they started. This analysis is conducted while the executable files at the assembly code level (low level) are in operation or statically. Reverse engineering is mainly used for malware analysis within the cybersecurity industry.

## **When Should the Reverse Engineering be Conducted and Why?**

Malware analysts must perform accurate analyses in order to use time efficiently as the reverse engineering is a time-consuming analysis process. For example, if mobile devices are not included in the assets within the organization, it would not be a coherent approach to perform mobile malware analysis. Instead, known malware types that may be a threat to existing assets within the organization should be analyzed. Alarms in the security products can be updated and additional measures can be taken according to the analysis reports. The important thing here is to reveal the attack methods of the current threats and take the necessary precautions, also to improve the monitoring and detection capability of the SOC team accordingly.

## **The Role of the Reverse Engineering in the Blue Team**

Different type of malware are the common ways to infect and seize the victim system nowadays and so reverse engineering is very important for the blue team as reverse engineering techniques are used to analyze the behavior of malwares. Since it is not usually possible to directly access the source code of the malware, we can only know or learn the behaviors and activities of the malware through reverse engineering techniques.


## **Creating a Reverse Engineering Lab**

The lab environment to be used for reverse engineering works and analyses are highly suggested to be virtual systems as we will examine malicious files mostly and would not want our systems to be infected with the malware that we are analyzing. The files to be analyzed in this training are files that are specifically created for this training class and do not have malicious elements. However, it is still recommended that the analysis environment be located on an isolated virtual operating system. It would be more appropriate to analyze the files in their own ecosystem in order for reverse engineering work to be carried out correctly and get the best results. For example, if a file with the extension ".exe" is to be analyzed, analysis should be performed with the Windows specific tools on a Windows operating system.

In this training, we will analyze Linux binary files and so we will work on a "Debian" Linux distribution installed as a virtual machine. The analysis is explained via the command line.

## Tools to be Used in Reverse Engineering Lab


**File Command**

The file command is a basic command used to get information about files on Linux.

**Objdump**

Objdump is one of the tools that can be used for reverse engineering on the Linux command line.

**GCC**

GCC is a tool used to compile source codes of the C programming language on the Linux command line.

**GNU Debugger (GDB)**

GNU Debugger (GDB) is a tool on the Linux command line that allows to analyze files dynamically while they are running.

We have briefly covered an introduction to reverse engineering in this part of our training. We have mentioned the lab environment and tools for reverse engineering. We will cover “**Basic Concepts**” in the next part of the training.

### Basic Concepts

## What is Compiling and Decompiling?

Compiling is the process that enables the source code of the programming language to run on the target system. A compiled source code transforms into binary type machine code. The extension of such files on Windows is “.exe”.

  
Decompiling is the process of obtaining the source code from the executable file. Decompiling cannot be done easily in every programming language because software manufacturers do not want the source codes of their software to be revealed. In order for the source code not to be revealed out through decompiling, vendors take advantage of different features of the programming languages and some other techniques while developing the software. This makes it much more difficult to implement the reverse engineering processes of the software.

  
  

**Note**: We are not covering the techniques used to prevent obtaining the source code with decompiling as they are not the focus of this training.

As an example, the executable file will be decompiled in order to obtain the source code of an executable file written in C# programming language without anti-reversing techniques applied below. Some of the tools that can be used for this are:

- ILSpy - [https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy) 
- dotPeek - [https://www.jetbrains.com/decompiler/](https://www.jetbrains.com/decompiler/)
- .NET Reflector - [https://www.red-gate.com/products/dotnet-development/reflector/](https://www.red-gate.com/products/dotnet-development/reflector/) 
- JustDecompile - [https://github.com/telerik/justdecompileengine](https://github.com/telerik/justdecompileengine) 

  
  

## **C# Binary Decompile Example with ILSpy Tool**

We will use the “**ILSpy**” tool in this example to decompile the executable file written in C# programming language. This is a tool that runs on Windows systems and has a graphical user interface (GUI). You can access the non-installation file of the ILSpy tool using the link below:

  
  

**ILSpy**: [https://github.com/icsharpcode/ILSpy/releases/download/v8.0-preview3/ILSpy_binaries_8.0.0.7246-preview3.zip](https://github.com/icsharpcode/ILSpy/releases/download/v8.0-preview3/ILSpy_binaries_8.0.0.7246-preview3.zip) 

  
  

**Note**: “.NET 6.0” must be installed on your Windows system in order to be able use the ILSpy tool on the link above. “ILSpy” and “.NET 6.0” installation files are located in the “CourseFiles” directory in the Linux system, which is included in the following parts of the training.

Let's start with the example:

**Note**: You can access the “**LetsDefend.exe**” file in the example on the “**CourseFiles**” directory in the Linux system, which is included in the following parts of the training.

Let's run the "LetsDefend.exe" file shown in the image above.

  
The window you see above pops open when the program is run. Let's see what the program does:

As seen in the image above, the program shows an image when the “Click Me” button is clicked. So, let's open the "ILSpy" tool to reveal the source code of the program with the decompile process to be able to reveal how this happens or through what code it does happen.

The window you see above will pop open when the ILSpy tool is run.

We can upload our file to the program using "File -> Open" option.

As you can see the image above, the decompile process starts and after the program is uploaded into the ILSpy tool. We can use the navigation menu on the left to see what happens when the button is clicked through the source code:

  
As seen in the source code in the image above, the invisible picture box becomes visible when the button is clicked.

We have obtained the source code of the program which was written in C# language with the help of the ILSpy tool and the exact function of the button in the code was revealed.

  
  

## What is Assembler and Disassembler?

Assembler is a compiler that converts the source code written in assembly language to machine code.

“**The Netwide Assembler (NASM)**”, is an example of an assembler:

  

**The Netwide Assembler (NASM)**: [https://www.nasm.us/](https://www.nasm.us/)

  
  

Disassembler is a tool that helps acquire the assembly code of the executable binary file.


  
Examples of disassembler include:

- IDA Pro (Windows & Linux) - [https://www.hex-rays.com/ida-pro/](https://www.hex-rays.com/ida-pro/) 
- Hopper Disassembler (Linux) - [https://www.hopperapp.com/](https://www.hopperapp.com/) 
- Binary Ninja - [https://binary.ninja/](https://binary.ninja/) 
- Objdump (Linux) - [https://man7.org/linux/man-pages/man1/objdump.1.html](https://man7.org/linux/man-pages/man1/objdump.1.html) 

  
  

## What is Debugging and Debugger?

Debugging is the in-depth analysis process in order to see the detailed and step-by-step operations of the programs during operation. Debugging can be done for many different purposes. For example, it can be used to test the program. If debugging is applied within the scope of reverse engineering, the aim is to learn the flow of the program and to reveal its processes. Debugging can be done in high-level programming languages such as C#, as well as in low-level languages such as Assembly.

Special programs are needed for debugging that are also known as "debuggers". For example, a debugger can be used in the "Visual Studio" software for debugging C# source codes. There are different debugger tools specific to each operating system in order to perform debugging at the Assembly language level. Below are some of the debuggers:

- OllyDbg (Windows) - [https://www.ollydbg.de/](https://www.ollydbg.de/) 
- ImmunityDebugger (Windows) - [https://www.immunityinc.com/products/debugger/](https://www.immunityinc.com/products/debugger/) 
- GDB (Linux) - [https://www.sourceware.org/gdb/](https://www.sourceware.org/gdb/) 
- IDA Pro (Windows & Linux) - [https://hex-rays.com/ida-pro/](https://hex-rays.com/ida-pro/) 
- X64dbg (Windows) - [https://x64dbg.com/](https://x64dbg.com/) 
- Windbg (Windows) - [https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) 

In this part of the training, we have covered the basic concepts in reverse engineering and will learn “**Memory Layout**” on our next part.

### Memory Layout

## What is Memory?

Memory is one of the most basic hardware units used for running the programs and the operation of the computer. When the computer is started, the operating system which is actually a software, the system software is loaded into the memory. The operating system is much larger than other software. Memory is a storage unit that is temporarily used during the execution of programs. Today, programs use memory for data storage because they use too much program data in size to be kept in processor variables. Memory contains some data structures that have their own special functions.

  
**Note**: System level memory analysis is an advanced level subject that the SOC analyst should have knowledge of. The SOC analyst should also be able to perform memory analysis if needed. You can access the "**Memory Forensics**" training at the link below:


**Memory Forensics**: [https://app.letsdefend.io/training/lessons/memory-forensics](https://app.letsdefend.io/training/lessons/memory-forensics) 

## What is Stack and Heap?

A “**Stack**” is a section of memory that is allocated when a program is run. Stack contains local variables and function arguments of the program.

“**Heap**” is a partition in memory that is reserved when a program is run. There are dynamic variables created for the program in the heap. There are no static variables in the heap as it is in the stack. Compared to the stack, heap is larger and has more freedom inside the operating system.

## How Stack and Heap Work?

Stack is an area that expands from high memory addresses to low memory addresses. The heap is the exact opposite and expands from low memory addresses to high memory addresses.

## Stack Operations

Stack applies a certain method when importing or extracting data from its data structure. This method is called “**Last In First Out (LIFO)**”. In this method, the data that enters the data structure last is removed from the stack in the first place. There are two basic functions in the Stack data structure. These are the "**Push**" and "**Pop**" functions.

**Push**

“**Push**” is the function that provides data intake to the stack. The below image shows how a few data are placed on the stack with the push function respectively, and the working principle of the stack:

The above image simply shows how the data is placed into the stack. Access to the data in the stack is provided by memory addresses and the ESP register. Each data in the stack has a separate memory address.

**Pop**

“Pop” is a function that helps extract data from the stack. The below image shows the working principle of the stack as well as how some data that were previously placed in the stack in accordance with its working logic, are removed from the stack with the pop function:

## What is Endianness?

A processor can access the data in memory in different ways in accordance with the memory structure. This is called endianness and has 2 methods:

- Big Endian
- Little Endian

**Big Endian** is matching the byte at the smallest address in the memory with the byte (most significant byte) at the largest address in the register when accessing the memory.

**  
Little Endian** is matching the byte at the smallest address in the memory with the byte (least significant byte) at the smallest address in the register when accessing the memory.

In this part of the training, we have covered what memory is, the working structures of stack and heap areas in the memory, what big endian and little endian are. In the next part of the training, we will explain “**Example C Program**”.


### Sample C Program
## About the C Programming Language

The C programming language is one of the most popular programming languages that was created in the 1970s and has been widely used for many purposes since then. It is a programming language that is close to the operating system and to program it is relatively easier than the Assembly language. C is also one of programming languages that really helps understanding the reverse engineering. Therefore, the programs used for reverse engineering in this training were written in C programming language. It is necessary and would be helpful to have thorough knowledge of the programming language when conducting reverse engineering. For example, the functions are used as references during the analysis and being familiar to the function names of the programming language will definitely make a difference for us to be able to continue the analysis. The C programming language is very comprehensive and can even be the topic of its own training series. Basic knowledge of C programming language will be sufficient for this training.

  
## Compile Process

A source code written in the C programming language goes through many intermediate stages while being compiled until it becomes an executable file. In this section, these steps are briefly mentioned. These stages are as follows:

- Pre-processing
- Compilation
- Assembling
- Linking

**Pre-processing**

A source code file with the extension ".c" is given to the pre-processing stage. At this stage, some preliminary preparations are applied on the source code to prepare for the compilation process. For example, deleting the comment lines in the source code is one of them. The file extension at this stage is “.i”.
 
  
**Compilation**

At this stage, the code takes the form of assembly code. The file extension at this stage is “.s”.
  

**Assembling**

At this stage, assembly code becomes machine code and is the last stage before it becomes an executable file. This state of the file is the "object" state. At this stage, the file extension is “.obj” or “.o”.

**Linking**

The last stage before the executable file is created is the linking stage. This stage is very important in terms of its task because the linking of the libraries of the functions used in the program is performed at this stage. The object file created in the previous stage and the library files are combined to form the executable file. After this stage, the file extension becomes “.exe” for Windows systems. In Linux systems, it is in the form of “.out”, but since there is no file extension for executable files in Linux systems, output files can be created without the extension. At this file state, it is now ready to be run.
  

## Compiling C Source Code with GCC

After briefly mentioning the compile process of the C programming language, let's see how to compile the C source code with the "**.c**" extension using "**GCC**" in this section.

First, type "**Hello World!**" on the command line. Let's see the source code of the program that prints it:


  
As seen in the image above, a source code with a simple print operation was written in C programming language and saved as a "**helloworld.c**" file.

**Note:** It usually comes pre-installed by default in “**GCC**” Linux distros, and it may need to be installed later in some Linux distros. For example, we will need to have it installed in the “**Debian**” used in this training as it is not installed in it. The following command can be used in Debian-based some Linux distros to install the GCC tool:

**Install GCC:** sudo apt-get install gcc-multilib

Let's compile this source code with GCC:

As seen in the image above, GCC and C source code were successfully compiled and an executable file named "**helloworld**" was created. The meanings of the parameters in the command are as follows:

**-m32**: This parameter allows compile to 32-bit systems. This parameter is required because 32-bit executable files are used in the training.

**-o**: This is the parameter that gives the name of the file as output.

**Compile Command**: sudo gcc -m32 helloworld.c -o helloworld

Let's see the print operation by running the file:

  
As you can see in the image above, the file was successfully run.

**Note:** The “**helloworld.c**” source code file and the “**helloworld**” executable binary file shown above are located under the “**CourseFiles**” directory in the Linux system, which is included in the later parts of the training.
## Reviewing the C Source Code

We covered the stack and heap fields in the previous topics. We will exemplify the elements in the stack and heap area over the C code in this topic:

As can be seen in the image above, the status of the variables in the stack or heap can change depending on the fact that there are many different qualities in the C code. Variables named “**a**” and “**y**” defined as local variables are located in the stack area. Also, the variable named "**x**", which is defined as the function parameter is another example for a variable in the stack area. On the other hand, "**global_variable**", which is defined as a global variable is the example for the variables in the Heap field. In addition, the variable named “**static_var**”, which is defined as static, is also included in the heap area. Finally, another variable in the heap field is the variable named “**z**”, which is defined as an integer pointer. The reason why this variable is in the heap field is that the function named “**malloc**”, which is one of the dynamic allocation functions, is used. In addition to the malloc function, the C functions named **calloc**, **free** and **realloc** can be given as examples of functions used for dynamic memory allocation purposes.

**Note:** The “**example1.c**” source code file shown above is located under the “**CourseFiles**” directory in the Linux system, which is included in our training later on.

  
## Installing Ghidra Tool on Linux


**Ghidra** is an advanced reverse engineering tool that can be installed and used for free and available to everyone. Ghidra is a versatile tool where many reverse engineering operations can be conducted. One of its most important features is the decompile feature. Ghidra has a user friendly graphical user interface (GUI) and can run on both Windows and Linux.

You can access the Ghidra tool at the following link:

**Ghidra**: [https://ghidra-sre.org/](https://ghidra-sre.org/)

The installation of the Ghidra tool is simply as follows:

JDK 17 is required for the Ghidra tool to work, so JDK 17 must be downloaded and installed first:

**JDK 17 (64-Bit)**: [https://adoptium.net/temurin/releases/](https://adoptium.net/temurin/releases/)

**Note:** Ghidra and JDK files are included in the Linux system, which is covered later in the training.

As seen in the image above, the 64-bit version of JDK 17 for Linux is downloaded. The downloaded compressed file with the extension "**tar.gz**" is extracted under any directory:

As you can see in the image above, the JDK file has been successfully extracted. After this process, "**bin**" directory that is in the JDK directory should be added to the path for ghidra to work. For this, a line must be added to the ".bashrc" file. For this, a line must be added to the "**.bashrc**" file.

Let's open this file under the home directory with the nano editor:

**Command**: sudo nano ~/.bashrc

The red section in the image above shows the added line. The purple area in this section shows the bin directory location in the JDK.

**Added Line:** export PATH=/home/letsdefend/reverse/jdk-17.0.5+8/bin:$PATH

**Note:** The path part of the JDK file should be arranged in such a way that the full path should be the exact location of the JDK file.

We have installed the JDK successfully. The zip file of the Ghidra tool is downloaded and opened.

**Command**: unzip ghidra_10.2.2_PUBLIC_20221115.zip

  
After extracting the Ghidra zip file, the installation is completed. Running the underlined file in the image above will be enough to open the Ghidra tool.

In this part of the training, we have covered topics like the C programming language, the compile process, how the C source code is compiled, examples of stack and heap fields on the C source code, the Ghidra tool, and the installation of the Ghidra tool. The next part of the training will cover “**C Binary Decompiling with Ghidra**”.