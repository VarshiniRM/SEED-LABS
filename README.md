# SEED-LABS

🔐 VPN Lab Using TLS/SSL | SEED Labs Implementation

This repository documents the setup and implementation of a basic Virtual Private Network (VPN) using TLS/SSL, following SEED Labs. The project demonstrates fundamental networking and cybersecurity concepts including TUN/TAP interfaces, IP tunneling, routing, authentication, and TLS-based secure communication. The lab setup uses VirtualBox with three virtual machines (VPN Client, VPN Server, and Host V) to simulate real-world VPN scenarios and verify encrypted communication across isolated networks.

Key Features:

VPN setup using TLS/SSL and X.509 certificates

Manual network configuration using NAT and Internal Networks

TUN interface configuration and routing

Secure communication between isolated hosts

Tunnel-disruption testing to validate VPN dependency

Wireshark packet analysis for encrypted traffic

_____________________________________________________________________________________________________________________________________________________________

🔁 Return-to-libc Attack Lab | Stack-Based Buffer Overflow Exploit
This repository demonstrates a classic Return-to-libc attack, exploiting a buffer overflow vulnerability in a SET-UID C program. The objective is to bypass shellcode injection protections by redirecting the program's execution flow to existing libc functions such as system() and exit(), executing /bin/sh without injecting code.

Key Concepts Covered:

Buffer overflows and stack frame manipulation

Return-to-libc technique and exploitation without shellcode

Disabling ASLR to ensure predictable memory layout

Locating system(), exit(), and "/bin/sh" in memory

Overwriting return addresses using Python scripting

Debugging with GDB to calculate stack offsets

Manipulating environment variables to find static addresses

Lab Setup Includes:

Compiling and analyzing a vulnerable C program (retlib.c)

Creating a malicious payload using exploit.py

Configuring the Linux environment (disabling ASLR, modifying /bin/sh)

Using GDB for address discovery and memory analysis

Demonstrating successful shell access with escalated privileges

_____________________________________________________________________________________________________________________________________________________________

💥 SEED Labs: Buffer Overflow Attack | Exploiting SET-UID Vulnerabilities
This repository documents a series of hands-on experiments based on the SEED Labs Buffer Overflow Lab, where various buffer overflow attacks are carried out on vulnerable C programs to understand memory exploitation, stack layout manipulation, and system-level security mechanisms.

🔐 Key Concepts Explored:

Stack-based buffer overflow in 32-bit and 64-bit programs

Crafting and injecting shellcode

Exploiting SET-UID binaries to escalate privileges

Stack frame analysis using GDB (GNU Debugger)

Randomized brute-force attacks

Defeating protections like ASLR, StackGuard, and NX

🛠 Lab Tasks Overview:

Task 1: Shellcode basics using execve() for /bin/sh execution

Task 2: Understanding and compiling vulnerable programs

Task 3: Level 1 buffer overflow exploit on 32-bit binary

Task 4: Level 2 attack without knowing buffer size (pattern-spraying)

Task 5 & 6: 64-bit exploitation using return address manipulation

Task 7: Defeating dash shell countermeasures

Task 8: Brute-force scripting to defeat randomization

Task 9: Enabling and testing modern countermeasures (StackGuard, NX)

🧪 Environment Setup:

Disabling ASLR (kernel.randomize_va_space=0)

Linking /bin/sh to /bin/zsh to bypass privilege dropping

Manual debugging and offset calculation with GDB

Python scripting for payload creation and delivery (exploit.py)
_____________________________________________________________________________________________________________________________________________________________

🐚 SEED Labs: Shellshock Attack | Exploiting Bash Vulnerabilities
This repository contains the implementation and analysis of the Shellshock vulnerability (CVE-2014-6271) based on the SEED Labs Shellshock Lab. The lab demonstrates how this vulnerability can be exploited in real-world scenarios to execute unauthorized commands on a vulnerable system through environment variables passed to the Bash shell.

🔍 Key Learning Objectives:

Understand the root cause of the Shellshock vulnerability in Bash

Learn how environment variables can be abused to inject malicious code

Exploit CGI-based web servers using crafted HTTP requests

Analyze the attack using web server logs and Wireshark traffic capture

Understand and test security mitigations

🛠 Lab Highlights:

Environment setup using pre-configured SEED Ubuntu VM

Exploiting a CGI script running in Apache using malformed HTTP headers

Injecting system commands via User-Agent, Cookie, and Referer headers

Gaining remote shell access to the server via reverse shell payloads

Observing how Shellshock enables command execution even with restricted CGI setups

🧪 Technical Concepts Covered:

Bash function definitions via environment variables

CGI (Common Gateway Interface) vulnerabilities

HTTP header injection

Reverse shell exploitation

Server hardening and patch verification
_____________________________________________________________________________________________________________________________________________________________

🕒 SEED Labs: Race Condition Attack | Exploiting Time-of-Check to Time-of-Use (TOCTOU) Vulnerabilities
This repository demonstrates how race condition vulnerabilities can be exploited in Linux systems, based on the SEED Labs Race Condition Lab. The lab focuses on TOCTOU (Time-Of-Check to Time-Of-Use) attacks in SET-UID programs, where attackers manipulate file system states between access checks and operations.

🔐 Key Learning Objectives:

Understand how race conditions arise in privileged programs

Explore TOCTOU vulnerabilities using symbolic link manipulation

Use shell scripts and multithreading to trigger timing-based exploits

Gain unauthorized access by hijacking file operations

Examine real-world implications in system calls like access(), open(), and fopen()

🛠 Lab Tasks Include:

Setting up a vulnerable C program with SET-UID permissions

Writing race condition exploit scripts to repeatedly create and remove symbolic links

Redirecting file writes to sensitive system files like /etc/passwd

Validating privilege escalation by injecting root-level user entries

Exploring mitigations and secure programming practices to prevent such flaws

🧪 Concepts Covered:

Race conditions and concurrency issues

Privilege escalation attacks

File system exploitation (symlinks, hardlinks)

Linux file permission and security models

Defensive coding against TOCTOU attacks
_____________________________________________________________________________________________________________________________________________________________

🐮 Dirty COW (CVE-2016-5195) | SEED Labs Linux Kernel Race Condition Exploit
This repository demonstrates the exploitation of the Dirty COW vulnerability, a critical race condition in the Linux kernel's Copy-On-Write (COW) mechanism. The lab follows the SEED Labs format and provides hands-on experience in leveraging this vulnerability to modify read-only files and escalate privileges, including editing the /etc/passwd file to gain root access.

📚 Overview:
Discovered in October 2016, Dirty COW (CVE-2016-5195) impacts nearly all Linux-based systems. It allows unprivileged users to gain write access to read-only memory mappings by exploiting a race condition between the madvise() and write() system calls. This fundamental flaw in memory management enables attackers to bypass normal permission restrictions and alter protected files.

🎯 Lab Goals:

Understand the root cause of the Dirty COW vulnerability

Learn how race conditions affect memory and file access

Exploit the vulnerability to modify protected files

Gain root privileges by modifying the /etc/passwd file

🛠 Tasks Covered:

✅ Task 1: Modify a Dummy Read-Only File

Create a read-only file in /

Attempt and fail to modify it as a normal user

Use a Dirty COW exploit (cow_attack.c) to successfully modify the file's contents

✅ Task 2: Privilege Escalation via /etc/passwd

Create a non-root user (e.g., eg)

Backup and modify the /etc/passwd file using Dirty COW

Change the UID of the user to 0 (root) in the file

Gain root shell using the modified user account

🧠 Key Concepts:

Race conditions and concurrency flaws

Linux memory management (Copy-On-Write)

System call abuse (madvise, write, /proc/self/mem)

Privilege escalation and file permission bypass

Real-world impact of kernel-level vulnerabilities

_____________________________________________________________________________________________________________________________________________________________

📝 SEED Labs: Format String Vulnerability | Exploiting Input Validation Flaws
This repository demonstrates the exploitation of Format String Vulnerabilities based on the SEED Labs format. The lab highlights how improperly validated user input can lead to memory corruption, information disclosure, and potential code execution.

📚 Overview:
A Format String Vulnerability occurs when user input is improperly passed to functions like printf(), sprintf(), or snprintf() that expect format specifiers (e.g., %s, %x, %n) to control output formatting. When an attacker controls the format string, they can manipulate the program’s behavior, often leading to security exploits such as stack manipulation, leakage of sensitive data, and arbitrary code execution.

🎯 Lab Goals:

Understand the mechanics of format string vulnerabilities and how they arise from improper input validation

Learn to exploit format string bugs to read memory (e.g., stack contents)

Gain hands-on experience in using format specifiers to alter program control flow

Explore techniques for preventing format string vulnerabilities in C programs

🛠 Tasks Covered:

✅ Task 1: Identify Format String Vulnerabilities

Review and analyze the vulnerable C code that takes unfiltered user input for format functions (printf(), sprintf(), etc.)

Identify potential areas where user input can influence the output format and memory operations

Demonstrate how improper validation allows attackers to control the format string

✅ Task 2: Exploit the Format String Vulnerability

Use format specifiers (e.g., %x, %s, %n) to leak sensitive data such as stack addresses

Perform a stack-based buffer overflow using %n to write arbitrary values to memory addresses

Exploit the vulnerability to alter program behavior and gain unauthorized access

✅ Task 3: Prevent Format String Vulnerabilities

Implement safer input handling (e.g., using snprintf() with proper bounds checking)

Employ security measures like stack canaries and format string checks to mitigate risks

🧠 Key Concepts:

Format String Vulnerabilities: Understanding how format specifiers work and how improper input handling can lead to attacks

Stack Manipulation: Using format specifiers to leak or modify stack data

Arbitrary Code Execution: Exploiting the vulnerability to overwrite function pointers or return addresses

Memory Disclosure: Using %x or %s to read from arbitrary memory locations

Secure Coding Practices: Safely handling format strings and preventing user-controlled input from influencing format functions
_____________________________________________________________________________________________________________________________________________________________
