; Source-built, harmless Linux ELF execution prerequisite: exit status 42.
; ELF headers follow https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
; NASM -f bin -DARCH=64 (or32) native_exit.asm -o native-exit
%if ARCH = 64
BITS 64
ORG 0x400000
    db 0x7f, 'ELF', 2, 1, 1, 0
    times 8 db 0
    dw 2, 62                         ; ET_EXEC, EM_X86_64
    dd 1
    dq entry
    dq phdr - $$
    dq 0
    dd 0
    dw 64, 56, 1, 0, 0, 0
phdr:
    dd 1, 5                          ; PT_LOAD, readable/executable
    dq 0, $$, $$, size, size, 0x1000
entry:
    mov edi, 42
    mov eax, 60                      ; Linux x86_64 exit
    syscall
%elif ARCH = 32
BITS 32
ORG 0x08048000
    db 0x7f, 'ELF', 1, 1, 1, 0
    times 8 db 0
    dw 2, 3                          ; ET_EXEC, EM_386
    dd 1
    dd entry
    dd phdr - $$
    dd 0, 0
    dw 52, 32, 1, 0, 0, 0
phdr:
    dd 1, 0, $$, $$, size, size, 5, 0x1000
entry:
    mov ebx, 42
    mov eax, 1                       ; Linux i386 exit
    int 0x80
%else
%error ARCH must be 32 or64
%endif
size equ $ - $$
