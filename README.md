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
