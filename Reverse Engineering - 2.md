### Registers - 1

## What is Register?

Registers are the variables in the assembly language. The size of each register in x86 architecture is 32 bits. Registers are located in the processor and each processor can have its own proprietary registers.

## General Purpose Registers

General purpose registers can be divided into 3 subcategories:

- Data Registers
- Pointer Registers
- Index Registers


## Data Registers

Data registers are the ones that contain data.


**EAX (Accumulator Register)**

The most basic register used in arithmetic operations is the "EAX" register. It stores the results of arithmetic operations and the return values of functions. For example, it is used for operations such as addition and multiplication.

  
  

**EBX (Base Register)**

It is the register that holds the base address of the program.

  
  

**ECX (Counter Register)**

The “**ECX**” is the register that is used as counter. It is used in loop and string operations.

  
  

**EDX (Data Register)**

It is a register that is generally used for holding data. It is also used in I/O (Input/Output) operations.

  
  

## Pointer Registers

Pointer registers are the ones that hold memory addresses.

  
  

**EBP (Base Pointer)**

EBP is the one that holds the lowest address of the Stack and is used for local variables.

  
  

**ESP (Stack Pointer)**

It is the register that holds the top address of the stack. Displays the last element that entered the Stack.

  
  

**EIP (Instruction Pointer)**

The EIP register may be the most important register as it holds the address of the next instruction to be executed in the program flow. In other words, if the value of this register is changed, the flow of the program can be interfered with.

  
  

**2.1.9.** **Index Registers**

Index registers are used for index information storage.

  
  

**ESI (Source Index)**

It is the register that holds the source index information for string operations. It holds the address of where the data will be read.

  
  

**EDI (Destination Index)**

It is the register that holds the destination index information for string operations. It holds the address of where the data will be written.

  
  

In this part of the training, we covered what the register is, what the register types are and what tasks the registers fulfil. In the next part of the training, we will cover "Registers - 2", which is the continuation of the Registers.


### Registers - 2

## Segment Registers

Segment registers are the registers used to hold addresses of specific segments in memory.

  
  

**Stack Segment (SS)**

It is the segment register that holds the base location address of the stack.

  
  

**Code Segment (CS)**

It is the register which is known as “**.text**” and it holds the address of the code segment used for data access.

  
  

**Data Segment (DS)**

It is the register which is also known as “**.data**” and it holds the address of the data segment which is the default variable location for data access.

  
  

**Extra Segment (ES)**

It is the register that holds the address of the extra segment used during string operations.

  
  

## EFLAGS Register - Status Flags

The EFLAGS register, unlike other registers, is a special register where each bit has a different meaning. The values of the bits of this register allow the CPU operations to be controlled and monitored.

  
  

**Adjust Flag (AF)**

It is the flag that is set when there is a transfer from the 3rd bit to the 4th bit in arithmetic operations.

  
  

**Carry Flag (CF)**

It is the flag that is set in arithmetic operations when the value of the register is more than the maximum value or if the value is less than the minimum value of the register. For example, the description over 4 bits is as follows:

  
  

**Example 1**: 

Initially: “**CF = 0**”

1111 + 0001 = 0000 (CF = 1)

0000 - 0001 = 1111 (CF = 0)

  
  

**Example 2**: 

Initially: “**CF = 0**”

0000 - 0001 = 1111 (CF = 1)

  
  

**Example 3**: 

Initially: “**CF = 0**”

0111 + 0001 = 1000 (CF = 0)

1000 - 0001 = 0111 (CF = 0)

  
  

**Direction Flag (DF)**

It is the flag that determines the direction in the transport and comparison of string data. The string operation is performed from left to right in case of “**DF = 0**”, and from right to left in case of “**DF = 1**”.

  
  

**Interrupt Flag (IF)**

It is the flag that determines whether external interruptions are taken into consideration and therefore it is the flag that determines whether the necessary operation is implemented. Keyboard entry would be a good example to the external interruption. Interruptions are ignored in case of "**IF = 0**" and considered disabled, and are applied to the process in case the "**IF = 1**" state.

  
  

**Overflow Flag (OF)**

The overflow flag is set when a positive value for the signed integer is too large to be represented in the register, or when a negative value is too small.

  
  

**Parity Flag (PF)**

It is the flag that shows the total number of "**1**" bits in the results of arithmetic operations. If the total number of “1” bits is even, it becomes “PF = 1”. If the total number of “**1**” bits is odd, it becomes “**PF = 0**”.

  
  

**Example 1**: 

10111100 + 00010001 = 11001101 (PF = 0)

  
  

**Example 2**: 

10111100 + 00010000 = 11001100 (PF = 1)

  
  

**Sign Flag (SF)**

It is the flag that indicates whether the result of an arithmetic operation is negative or positive. If the result of the arithmetic operation takes a negative value, the sign flag is set as “**SF = 1**”. In case of a positive result, the sign flag will be in the state of “**SF = 0**”.

  
  

**Trap Flag (TF)**

It is the flag that allows the processor to set the operating mode as single-step mode. The debugger program sets this flag to run each command one by one. In this way, each command executed by the processor at the assembly level can be executed step by step.

  
  

**Zero Flag (ZF)**

It is the flag set depending on whether the result of the arithmetic or the comparison operations is "**0**" (zero). If the result of the operation is “**0**”, then the  zero flag is set as “**ZF = 1**”. If the operation result is other than zero, then the zero flag is not set “**ZF = 0**”.  
  
In this part of the training, we have covered the segment registers and status flags, which are the continuation of register. In the next part of the training, "**X86 Assembly Language and CPU Instructions**" will be covered.


### X86 Assembly Language and CPU Instructions


## What is X86 Assembly Language?

Assembly language can be described as a machine language which is different for each processor. Assembly language is more difficult to understand than other programming languages. Running programs can be analyzed at the processor level only through the assembly language. This training describes the x86 assembly language.


## AT&T and Intel Syntax

Many syntaxes can be used when expressing commands in the assembly language program flow. "**AT&T**" and “**Intel**” syntaxes are two of them. Brief examples of both syntaxes are given below. The syntax to be used in the examples in the training as well as the reverse engineering processes is the "**Intel**" syntax.

The following examples show different syntax versions of the same "**main**" function. The tool used for disassemble operation is the "**objdump**" tool.


**AT&T Syntax**


**Command**: sudo objdump -d helloworld

**Note**: The executable file used for the Syntax examples is the Linux executable file named “helloworld”, which is also included in the previous parts of the training It is located on the Linux system in the training.

You can see the “**AT&T**” syntax roughly in the image above. In the AT&T syntax, which has a different notation than the Intel syntax, the "**%**" sign is prefixed to the register names. Another difference is that the direction of operation in MOV instruction is from left to right.

**Intel Syntax**

**Command**: sudo objdump -d -M intel helloworld

The above image shows the “**Intel**” syntax
## Addressing Modes

The assembly language has many different addressing modes. Some of these are as follows: 


**Register Addressing**

In this addressing, registers are used as operands. For example:

MOV EAX, EBX

Above, the operation is applied between two registers. 


**Immediate Addressing**

A fixed value is used as the operand in this addressing. For example:

MOV EAX, 0x0

The operation is applied between the fixed value and the register in the above operation.  


**Memory Addressing**

The memory address is used as the operand in this addressing. For example:

MOV EAX, DWORD PTR [ESP]

The operation is applied between the memory address and the register in the above operation.


## CPU Instructions - 1

Instructions are the commands in the assembly language. There are a lot different type of instructions for different tasks and purposes. Some may have similar duties. It is vital to know the instructions in order to follow the program flow in the assembly language. Below are some of the instructions and their tasks:

## Arithmetic Instructions

Arithmetic instructions are those that perform arithmetic operations between operands. For example, the four arithmetic operations are examples of such transactions.


**ADD**

The “**ADD**” is the instruction that enables to perform the addition. For example:

ADD    ESP, 0x8

With the above instruction, 8 is added to the value of the ESP register.

**SUB**

The "**SUB**" is the instruction that enables the subtraction. For example:

SUB    ESP, 0x4

With the above instruction, 4 is subtracted from the value of the ESP register.


**MUL**

The "**MUL**" is the instruction that enables multiplication to be performed.


**DIV**

The "**DIV**" is the instruction that enables division to be performed.



**INC**

The “**INC**” is an instruction that allows you to increment the value of the operand by 1. For example:

INC    EBX

With the above instruction, the value of the EBX register is incremented by 1.


**DEC**

The “**DEC**” is an instruction that allows you to decrement the value of the operand by 1. For example:

DEC    EBX

With the above instruction, the value of the EBX register is decremented by 1.



**Branch Instructions**

Branch instructions are those that performs the comparison and/or branching. They are vital with respect to follow the program flow in the assembly language. Below are some of these instructions:

**JMP**

The “**JMP**” is the instruction that allows branching unconditionally. It takes the memory address as an operand. For example:

JMP    0x56556020

With the above instruction, the program flow branches to the memory address given as operand (branching).

**JZ/JE**

The “**JZ**” and “**JE**” instructions are among the conditional branching instructions. They stand for: 

JZ = Jump if Zero

JE = Jump if Equal

JE and JZ instructions take memory address as operand. For example:

JE     0x5555555551b5 <main+277>

With the above instruction, the condition for branching to the memory address in the operand is that the zero flag is set to "1" in the form of "**ZF=1**".

**JNZ/JNE**

The “**JNZ**” and “**JNE**” instructions are also among the conditional branching instructions. They stand for: 

JNZ = Jump if not Zero

JNE = Jump if not Equal

JNE ve JNZ instructions take memory address as operand. For example:

JNE    0x565561e7 <main+78>

The condition for branching to the memory address in the operand with the above instruction is that the zero flag is set to "0" in the form of "**ZF=0**".

**CALL**

The “**CALL**” instruction is the instruction used for function call. It takes a function address as an operand. For example:

CALL   0x56556199 <function1>

With the above instruction, the function named “**function1**” is called. There are 2 basic operations with this instruction:

- The address of the instruction after the CALL instruction in the program flow is pushed to the stack (Return address)
- The value of the EIP register is set as the function address, so that the program flow branches to the corresponding function.

**CMP**

The “**CMP**” instruction is used for comparison operations. Takes 2 values to compare as operands. For example:

CMP    EDX, EAX

The above instruction compares the EAX and EDX registers. Depending on the result of the comparison, “**Zero Flag(ZF)**” and “**Carry Flag(CF)**” may be changed. The below table shows the conditions that will cause these changes.

  
In this part of our training, we have covered x86 assembly language, AT&T syntax, Intel syntax, addressing modes, arithmetic instructions and branch instructions. We will detail the "CPU Instructions - 2", which is the continuation of the instructions topic in the next part of the training.



 CPU Instructions - 2

## Data Transfer Instructions

There are many data transfer instructions in assembly language that are used for different purposes. Some of these are listed below:


**MOV**

The “**MOV**” is the most basic data transfer instruction used to assign a value to a register or to an address in the memory. For example:

MOV    EAX, 0x0

With the above instruction, the value “**0**” (zero) is assigned to the EAX register.


**LEA**

The “**LEA**” is the instruction used to assign a memory address to the target. It stands for "**LEA: Load Effective Address**". For example:

LEA    ECX, [esp+0x4]

With the above instruction, the memory address is assigned to the ECX register.


**XCHG**

The "**XCHG**" instruction allows to exchange values in 2 registers. For example:

EAX = 0x2

EBX = 0x3

Let the register values be as above.

XCHG    EAX, EBX

After the above instruction is executed, the updated values of the registers are as follows:

EAX = 0x3

EBX = 0x2


**PUSH**

The "**PUSH**" is the instruction that allows adding data to the stack. For example:

PUSH    EDX

As seen in the image above, the value in the EDX register has been successfully added to the stack with the "**PUSH**" instruction.

**POP**

The "**POP**" is the instruction that extracts data from the stack. For example:

POP    EDX

As seen in the image above, the data at the top of the stack has been removed from the stack using the "POP" instruction and assigned to the EDX register successfully.


## Logical Instructions

Assembly language has many instructions that are used for logical operations. Some of these instructions are described below:


**AND**

The “**AND**” is the instruction that enables to implement the logical AND operation. For example:

AND    ESP, 0xfffffff0

With the above instruction, the fixed value and the ESP register are ANDed.


**OR**

The “**OR**” is the instruction that enables to implement the logical OR operation. For example:

OR    EAX, 0xfffffff0

With the above command, the fixed value and the EAX register are ORed.

**XOR**

The “**XOR**” is the instruction that enables to execute the logical XOR (exclusive OR) operation. For example:

XOR    EBP, EBP

With the above instruction, the EBP register is XORed with itself.

**NOT**

The "**NOT**" is the instruction that enables to implement the bitwise inversion operation. For example:

EAX = 0x626c7565 (Hexadecimal)

Let the EAX register have the above value.

0x626c7565 => Binary => 01100010 01101100 01110101 01100101

NOT    EAX

New EAX Value = 10011101100100111000101010011010 (Binary)

New EAX Value = 0x9d938a9a (Hexadecimal)

With the above instruction, the bitwise NOT operation has been executed successfully and with that, the EAX register has a new value.


## NOP Instruction

The "**NOP**" instruction means "**no operation**" that allows to move on to the next instruction without any operation being executed. It is used alone without the operand.

**Note**: More instructions for X86 Assembly architecture can be found at:

**X86 Assembly Instructions**: [https://www.aldeid.com/wiki/X86-assembly/Instructions](https://www.aldeid.com/wiki/X86-assembly/Instructions)

**X86 Assembly Instructions(Wikipedia)**: [https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086/8088_instructions](https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086/8088_instructions) 

## What is Opcode(Operation Code)?

Opcode(Operation Code) is a unique value that belongs to each instruction. Thanks to this value, the machine understands which instruction to execute. The following image shows the opcodes of the instructions according to the x86 architecture:

Opcodes are usually expressed in hexadecimal notation. For example, let's see the opcode of the "**NOP**" instruction according to the image above:

After finding the "**NOP**" instruction on the image, we should first look at its equivalent on the left lines: "**9**", then, check the column equivalent at the top: “**0**”. The combination of these hexadecimal values creates the opcode: “**0x90**”.

**NOP Instruction Opcode**: 0x90

We have covered the, “data transfer instructions”, “logical instructions”, “NOP instruction” and “opcode concept” in CPU instructions, which is the continuation of the previous topic. The next part of the training will be about the “GNU Debugger (GDB)” domain.


### GNU Debugger (GDB)

  
  

## What is GDB?

GNU Debugger (GDB) is a reverse engineering tool that enables debugging Linux executable files on the Linux command line.

  
  

## The installation of GDB

Installing the GDB tool on Linux is quite simple. Since the "Debian" Linux distro is used in this training, the installation of the gdb tool is explained for Debian. The same command can be used for any Debian based Linux distro:

  
  

**Command**: sudo apt-get install gdb


As seen in the image above, when the gdb installation command is applied, the gdb tool is installed by giving the answer "Y" to the question asked.

As seen in the image above, after the gdb tool installation is completed, the gdb tool can be opened with the "**gdb**" command. The gdb tool can be used without any plugins as it is here.

  
  

## PEDA (Python Exploit Development Assistance) Plugin Installation

There are some specific plugins to use the gdb tool with a more understandable user interface. One of them is the PEDA (Python Exploit Development Assistance) plugin. This plugin provides a more colorful and more understandable interface to the user during debugging. The PEDA plugin can be downloaded from:

  
  

**PEDA**: [https://github.com/longld/peda](https://github.com/longld/peda) 

  
  

**Note**: PEDA gdb plugin has already been installed on the Linux machine given in the training.

The PEDA plugin installation steps are as in the image below:


Let's execute the installation commands above.

  
  

**Command**: git clone https://github.com/longld/peda.git ~/peda


As seen in the image above, the PEDA plugin has been successfully downloaded.

  
  

**Command**: echo "source ~/peda/peda.py" >> ~/.gdbinit


As seen in the image above, the command that provides the necessary settings to open the gdb tool with the PEDA plugin has been successfully applied.

Let's open the gdb tool and check see if the PEDA plugin is installed properly:


As we can see it in the screenshot above, the PEDA plugin was successfully installed and the gdb tool was opened with the PEDA plugin.

  
  

## Introduction to Debugging with GDB

If the "**-q**" parameter is used while opening the gdb tool, the banner information is not printed on the command line:


Since the gdb tool is a tool that works on the command line, all operations are executed through the gdb specific commands. In order to see all the commands of the gdb tool, the following command can be applied:

**Command**: help all


**Note**: Since the output of the command applied in the above image is very long, only the first part is displayed.

  
  

## Basic GDB Commands

Below are the basic commands that we must know in order to use the gdb tool:

  
  

**Note**: We will use the executable file named “**helloworld**” that we also used in the previous parts of the training to apply the commands here.

  
  

**File Command**

After opening the gdb tool, the file to be debugged is given to the program with the below file command:


**Command**: file helloworld


**Info Command**

After the file is given to gdb with the file command, it should be determined where the program flow will be stopped. Generally, executable files written in C programming language are started to be debugged from the "**main**" function:

The “**info**” command is that the one that provides information in accordance with the given parameter. For example, let's see the functions in the executable file with this command:

  
  

**Command**: info functions




**  
Break (or b) Command**

The points where the program flow will be stopped on gdb are called "**breakpoints**". The command used to set a breakpoint is the "**break**" or "**b**" command for short. The break command can be given an address or a function name as a parameter. Let's put a breakpoint in the "**main**" function seen in the output of the previous command:

  
  

**Command**: break main


As it can be seen in the screenshot above, a breakpoint has been placed in the main function successfully.


  
The "info breakpoints" command can display all the set breakpoints as you can see in the image above.

  
  

**Run Command**

The gdb commands so far are the commands applied before the executable file named “**helloworld**” is run. The program is executable after the breakpoint is set.

The “**run**” command is to "run" the executable. Let's start the debugging process by executing the command:



  
The see the main screen during the debugging process on gdb on the image above. There are 3 sections on this screen:

- Registers
- Code
- Stack

“**Registers**” is the field that displays the current values of the registers after each instruction execution.  
“**Code**” is the field where the executed instructions in the program flow are located.  
“**Stack**” is the field where the elements in the stack data structure are displayed.  

  
  

**Nexti(ni) and Stepi(si) Commands**

“**nexti(ni)**” and “**stepi(si)**” are vitally important commands to be able to execute each instruction in the program flow. A single instruction is executed with the "**nexti(ni)**" command and changes are applied to the relevant register or data fields. With this command will not enable us to get into the functions called with the "**call**" instruction. If the next instruction to be executed is "call" and it is needed to get into the called function, the "**stepi(si)**" command should be executed.

For example, in the previous image, we saw that the "call" instruction will be executed in the program flow. Let's go inside the function called with the "si" command:

  
  

**Note**: Let's set a breakpoint at the address of the instruction after the "call" instruction in the main function, so that we can go back to where we left off in the main function after entering the function called with "**call**":

  
  

**Command**: b *0x565561ad



**  
Note**: As you can see in the image above, "*****" sign is prefixed to the address when setting breakpoints to memory addresses.

Let's enter into the function with the "**si**" command after setting up the breakpoint:



The above screenshot shows that the function has been entered successfully.

  
  

**Continue Command**

“**Continue**” is the command that should be used to execute the instructions up to the breakpoint, which was previously left in order to return to the main function. It can be abbreviated and use as "**c**". Let's run the instructions up to the breakpoint in the main function with the “**continue**” command:



  
The above screenshot shows that the program was run successfully until the breakpoint with the "**continue**" command.

  
  

**Set Command**

In some cases, we may need to interfere with the program flow during debugging. For example, we may need to jump the program flow directly to a different instruction. In this case, we need to change the value of the EIP register using the "**set**" command. Let's set the value of the EIP register to a different address using the set command:

  
  

**Command**: set $eip=0x565561bb

  
  

**Note**: When assigning values to registers, a "**$**" sign must be prefixed the register name in the command.



  
The above screenshot shows that the value of the EIP register has been changed successfully and the program flow has been interfered with.

  
  

**Note**: The "**context**" command used in the screenshot above is used to show the current information on the debugging screen.

  
  

**Quit Command**

“**Quit**” is the command to close the gdb tool.

  
  

**Note**: The GDB tool can be used online at at its own website below.

  
  

**Online GDB**: [https://www.onlinegdb.com/](https://www.onlinegdb.com/) We have covered the GDB tool, its installation, PEDA plugin and GDB basic commands in this part of our training. We will detail the “**Debugging with GDB**” topic next.



### Debugging with GDB

## Example of Debugging with GDB

In this part of the training, reverse engineering studies will be carried out on a Linux executable file written in C programming language. During these studies, GDB debugger tool will be used mainly. In addition, some tools will be used as auxiliary to GDB.

  
  

**Note:** The “**pincode**” executable binary file in the example is located under the “**CourseFiles**” directory on the Linux system in the training.

Before starting the reverse engineering process, it is necessary to obtain some information about the executable file to be analyzed. Obtaining information such as which operating system the executable file was compiled for, the type of the file, which programming language it was written in, and whether anti-reversing techniques were applied or not will allow the methods and tools to be used in the reverse engineering process to be selected more accurately. The executable file to be used in the example is the file named “**pincode**” as you can see in the image below.

Let's start collecting information about the file by opening the command line in the directory where the file is located, and then we can start the reverse engineering processes.

The "**file**" command is what you can use to get information about files. With the "file" command, you can get variety of information about the file such as its type, etc. Let's see the "file" command output of the file:

  
  

**Command**: file pincode


As seen in the image above, the file command output indicates that the file named “pincode” is an “ELF 32-bit” type file. The ELF file type is the type of executable files in Linux. In this section, there is no information about which programming language was used while writing the program. Programming language knowledge will be vital when applying reverse engineering techniques and understanding the code written. Therefore, we need to utilize another tool to determine which programming language is used for this file.

Another tool that can be used on each file in the Linux command line is the "**strings**" tool. The Strings is a very useful tool used to obtain information about files and will help display all the values in the string type in the file. Let's examine the results by applying the Strings tool on the pincode file:

  
  

**Command**: strings pincode


**  
Note**: The output of the Strings command can sometimes be very long. Therefore, it is possible to examine it easier with commands such as “**more**” that can be applied on the command line in Linux.

Looking at the "strings" output, some of which can be seen in the image above, we see some familiar function names belonging to the language used as the programming language. In addition, there are some expressions in the program as strings. Some of the information contained in the "**strings**" output can be very important. For example, a password information used in the program can be included in this output, or if the file is malicious, the IP address of the command and control(C2) server can be included in this section. Knowing all this useful information, let's continue to examine the "strings" output:


  
File extensions in strings can sometimes give us helpful tips. For example, in the image above, we see file names with the extension "**.c**", which are the extensions of source code files belonging to more than one C programming language. In this way, we can say that the program is written in the C programming language.

Having obtained all this information, let's run the program and observe its actions and behaviors:



As seen in the image above, a 4-digit PIN code is requested from the user after the program is run and feedback related to whether the entered PIN code is correct or not is provided back to the user. So far, we were able to obtain some information about the executable without seeing the assembly code with the help of some tools and techniques. It is necessary to examine the codes at the assembly level in order to find out what the correct 4-digit PIN code is in the program. Before examining the executable file dynamically with GDB to find the PIN code, we can see the assembly codes of the functions through the disassembling process, which is a static process. We have used the "**objdump**" tool here but we could have utilized the GDB as well to get the same results.

  
  

**Command**: sudo objdump -d pincode -M intel


  
The above image shows the instructions in the program flow in the "**main**" function.

Let's start debugging via the GDB tool:


  
As seen in the image above, the gdb tool started and the "**pincode**" executable file was imported into gdb. Looking at the list of functions, we can see the function to be debugged with the name "**main**".

Let's set a breakpoint in the main function with the "**b main**" command and run the file with the "**run**" command:


Since the value we want to find in the program flow is the PIN code, we must find the assembly instruction with the comparison in the verification part. For this, we can use the processes we know that are in the program flow as a reference. For example, there are some string values that are printed on the command line and we the user input is received as well. We will have to move forward the program flow as the PIN code comparison comes later than these operations. Let's advance the program flow to the desired section by executing the "**ni**" command as required:


As seen in the image above, the "**printf**" function which was used for command line printing process was detected. Let's find the part that we received the user input by advancing the program flow with the "**ni**" command:


As seen in the image above, the "**scanf**" function, which received input from the user, was detected. When we advance the program flow, an input will be received from the user:


  
As seen in the image above, input has been received from the user with the “scanf” function. Let's continue by typing any value in the form of "**1111**".


As we see in the screenshot above, we are at the part where the comparison process is made. The instruction used for the comparison operation is the "**CMP**" instruction. In the red area above, the input value entered by the user is assigned to the EAX register with the MOV instruction. Next, CMP instruction compares the fixed value which is the correct PIN code and the input entered by the user assigned to the EAX register.


As seen in the image above, the hexadecimal value of "**0x457**" was assigned to the EAX register by executing an instruction with the "**ni**" command. The decimal equivalent of this hexadecimal value is “**1111**”. The hexadecimal value “0x1b96”, which is the operand of the “CMP” instruction, is the correct PIN code we are looking for and the decimal equivalent of its value is “**7062**”. We think that the value "7062" we found here in this section is the correct PIN code, but is the value we found really correct? The simplest way to find that out is to run the file and try this value.


  
As seen in the image above, the detected PIN code was verified. There is no need to continue further investigation on GDB as we have the answer we are looking for. If we were to continue to investigate, we would reach the section with the string displayed on the screen and then see the assembly codes where the program was terminated.

  
  

In this part of the training, the technical knowledge of the reverse engineering topics we have been learning since the beginning of the training has been shown with some practical examples.

