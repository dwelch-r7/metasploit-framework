# Independent static ELF control; assembled by the target's own GNU binutils.
.section .rodata
message: .ascii "Native Linux x86 ELF\n"
length = . - message
.section .text
.global _start
_start:
  mov $4, %eax
  mov $1, %ebx
  mov $message, %ecx
  mov $length, %edx
  int $0x80
  mov $1, %eax
  xor %ebx, %ebx
  int $0x80
