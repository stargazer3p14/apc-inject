# apc-inject
apc-inject demo

The project consists of two parts: APC injector program and injected shellcode. It demonstrates (one of the ways) how to inject an APC into another program, framework how to write shellcodes in C and capabilities of the injected code.

The base directory contains APC injector program.

Files:

* README.md
This file

* apc-inject-demo-pname.c
Injector program source

* cc.cmd
Simple compile script

In order to compile just run "cc.cmd"

shellcode/ subdirectory contains minimal framework to write shellcode programs in C and two sample shellcodes.

Files:

* cc.cmd
Script to compile shellcodes and build helper programs

* mc.cmd
Script to build runnable shellcodes: prepare valid compilable assembly source, assembly it to an EXE and dump .text section from it, producing an injectable shellcode.

* asm2valid.c
Fixes broken ASM output from VC to a valid .ASM source acceptable to MASM

* dump-text.c
Dumps .text section of a PE .EXE into a plain binary file. (NOTE: since the output is plain binary, without any header, APC entry point must be the first function in source. Also it may be not safe to link multiple sources into a single shellcode)

* peb-lookup.h
Contains functions to traverse PEB, looking up modules loaded into target (victim) program and exported functions

* func.h
Contains typedefs for used Windows API functions and _func structure that holds addresses of already resolved functions (and possibly additional data) to pass to created threads

* lib.h
Mini implementation of some handy libc functions

* shellcode-simple-msgbox.c
Sample shellcode that pops up a MessageBox, a visible POC. Has a funny effecr if injected into many instances of the target program

* shellcode-msgbox-no-params.c
Sample shellcode that pops up a MessageBox and then runs two threads than in loop dump SystemInformation about modules and communicate with each other. Demonstrates more complex functionality achievable by such shellcodes

In order to run - syntax of APC injector:

apc-inject-demo-pname -p <program_name> [-a] [-s <shellcode_name]

program_name: target running program

-a: specifies to inject into all threads of all instances of the target program

-s: specifies shellcode name (default is "shellcode1.txt")

Recommended to run in a VM
