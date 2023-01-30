## A quick word about syntax

For GNU Assembler:

- Comments start with `#`
- Global symbols declaration are in the form `.globl _mysymbol`
- To use the intel syntax for assembly instructions, add a `.intel_syntax noprefix` in the beginning of your assembly file

For nasm:

- Comments start with `;`
- Global symbols declaration are in the form `global _mysymbol`


## x86/x64 Assembler and Disassembler

This tool was inspired by https://defuse.ca/online-x86-assembler.htm


### Get the shellcode from the assembly instructions

Help:

```
┌─╼ arch [~/Tools/shellcoding-tools]
└╼ ./shellcode-assemble.py --help
Usage:

    If you want to paste the assembly code in stdin:
        ././shellcode-assemble.py

    If you want to specify a file that contains the assembly code:
        ././shellcode-assemble.py file-with-assembly.s


We assume that you are using the Intel syntax. If you want to use the AT&T syntax, start your assembly code with the following line:

.att_syntax noprefix


```

Usage example:

```
┌─╼ arch [~/Tools/shellcoding-tools]
└╼ ./shellcode-assemble.py 
Paste your assembly code below and then press CTRL+d:

mov eax, 0x10


Which architecture are you using?
1 - x86
2 - x64 (Default)

Select an option: 1


Assembling instructions for architecture -m32


---------- [ Objdump Output (Intel syntax) ]----------

00000000 <_main>:
   0:   b8 10 00 00 00          mov    eax,0x10


---------- [ Python Bytearray ]----------
shellcode = bytearray(
    b"\xb8\x10\x00\x00\x00"      # mov    eax,0x10
)

---------- [ C String ]----------
char shellcode[] = "\xb8\x10\x00\x00\x00"


```

Or:

```
┌─╼ arch [~/Tools/shellcoding-tools]
└╼ cat /tmp/shellcode.s 
mov eax, 0x10

┌─╼ arch [~/Tools/shellcoding-tools]
└────╼ ./shellcode-assemble.py /tmp/shellcode.s 

Which architecture are you using?
1 - x86
2 - x64 (Default)

Select an option: 2


Assembling instructions for architecture -m64


---------- [ Objdump Output (Intel syntax) ]----------

0000000000000000 <_main>:
   0:   b8 10 00 00 00          mov    eax,0x10


---------- [ Python Bytearray ]----------
shellcode = bytearray(
    b"\xb8\x10\x00\x00\x00"      # mov    eax,0x10
)

---------- [ C String ]----------
char shellcode[] = "\xb8\x10\x00\x00\x00"

```

### Get the assembly instructions from the shellcode

You can pass the shellcode in many different formats. Examples:

Python

```
b"\xb8\x10\x00\x00\x00"
```

Python bytearray:

```
bytearray(
    b"\xb8\x10\x00\x00\x00"
    b"\x90\x90\x90\x90\xcc"
)
```

C array:

```
{ 0xb8, 0x10, 0x00, 0x00, 0x00 }
```

Space separated:

```
b8 10 00 00 00
```

Hex chunk:

```
b81000000090909090909090cc90cc90cc
```

This is the usage:

```
┌─╼ arch [~/Tools/shellcoding-tools]
└────╼ ./shellcode-disassemble.py 
Paste your shellcode below and then press CTRL+d:

\xb8\x10\x00\x00\x00


Processing the following shellcode:
b8 10 00 00 00

Which architecture are you using?
1 - x86
2 - x64 (Default)

Select an option: 2



Disassembling for architecture i386:x86-64


---------- [ Objdump Output (Intel syntax) ]----------

0000000000000000 <.data>:
   0:   b8 10 00 00 00          mov    eax,0x10


```


## Assembling to ELF binaries

### Using nasm

You can use `nasm-ld-compile-32.sh` or `nasm-ld-compile-64.sh` to assemble instructions into an executable ELF binary.

Just run `./nasm-ld-compile-XX.sh my_source_file.s`

Make sure the name of your "main function" is named **_start**. 

#### 32bit skeleton

```
global _start

_start:
    mov eax, 1       ; exit syscall
    mov ebx, 0       ; return code
    int 0x80         ; invoke system call

```

#### 64bit skeleton

```
global _start

_start:
    mov rax, 60      ; exit syscall
    mov rdi, 0       ; return code
    syscall          ; invoke system call

```

### Using GNU Assembler

You can use `gcc-compile-32.sh` or `gcc-compile-64.sh` to assemble instructions into an executable ELF binary.

Just run `./gcc-compile-XX.sh my_source_file.s`

Make sure the name of your "main function" is named **_start**. 

#### 32bit skeleton

```
.intel_syntax noprefix

.globl _start

_start:
    mov eax, 1       # exit syscall
    mov ebx, 0       # return code
    int 0x80         # invoke system call

```

#### 64bit skeleton

```
.intel_syntax noprefix

.globl _start

_start:
    mov rax, 60      # exit syscall
    mov rdi, 0       # return code
    syscall          # invoke system call

```
