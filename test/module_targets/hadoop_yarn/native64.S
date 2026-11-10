# Independent static ELF control; assembled by the target's own GNU binutils.
.section .rodata
message: .ascii "Native Linux x64 ELF\n"
length = . - message
.section .text
.global _start
_start:
  mov $1, %rax
  mov $1, %rdi
  lea message(%rip), %rsi
  mov $length, %rdx
  syscall
  mov $60, %rax
  xor %rdi, %rdi
  syscall
