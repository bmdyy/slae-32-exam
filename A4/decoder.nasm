; A4 - Custom Encoding Scheme
; William Moody
; PA-25640
; 28.12.2021

global _start
section .text

_start:

	jmp short call_decoder

decoder:
	
	pop edx						; EDX points to key
	lea esi, [edx +0x1]			; ESI points to shellcode
	xor eax, eax				; i = 0 -- offset to write location
	xor ebx, ebx				; j = 0 -- offset to read location

	; => EAX = i = 0
	; => EBX = j = 0
	; => EDX = *key
	; => ESI = *shellcode

decode_loop:

	mov cx, word [esi +eax]		; ch = shellcode[i], cl = shellcode[i+1]
	sub cx, 0x6161				; ch -= 97, ch -= 97
	shl cl, 0x4					; cl = 0xA -> 0xA0
	add cl, ch					; ch = 0xB -> cl = 0xAB
	xor cl, byte [edx]			; cl = 0xAB ^ key

	; => CL = decoded byte

	mov [esi +ebx], byte cl		; shellcode[j] = cl

	inc ebx						; j += 1
	add eax, 0x2				; i += 2

	; --- PASTE LENGTH (encoder.py) HERE ---
	cmp eax, 0x28
	; --- --- --- --- --- --- --- --- --- --
	jnae decode_loop			; Loop if i < len(shellcode)
	jmp short shellcode 		; Hand over control to decoded shellcode

call_decoder:
	
	call decoder

	; --- PASTE OUTPUT FROM encoder.py HERE ---
	key: db 0x0a
	shellcode: db "akalaiajaoapamanacadaaabagahaeafbkblbibj"
	; --- --- --- --- --- --- --- --- --- --- -

	; \x00 - \x20 with key \x06 (6)   => fails on \x11 (16) -- incorrectly decodes as \x17
	; \x00 - \x20 with key \x0a (10)  => fails on \x05 (5)  -- incorrectly decodes as \x0a
	; \x00 - \x20 with key \x0c (12)  => fails on \x07 (7)  -- incorrectly decodes as \x0c
	; \x00 - \x20 with key \x0e (14)  => fails on \x09 (9)  -- incorrectly decodes as \x0e
	; \x00 - \x20 with key \x10 (16)  => fails on \x0b (11) -- incorrectly decodes as \x01
	; \x00 - \x20 with key \x11 (17)  => fails on \x0c (12) -- incorrectly decodes as \x00
	; \x00 - \x20 with key \x13 (19)  => fails on \x0e (14) -- incorrectly decodes as \x02
	; \x00 - \x20 with key \x15 (21)  => fails on \x10 (16) -- incorrectly decodes as \x15
	; \x00 - \x20 with key \xff (255) => works correctly

	; Problem -> shellcodes byte in memory are incorrect (one byte is skipped). The decoding works correctly.
	;            This problem doesn't happen in `gdb ./decoder`, so maybe something is wrong with the compiling script?
	;		  -> For some reason `objdump -d decoder -M intel` gives two 0x61 in a row, need to see why
	;		  -> Work around: create a shellcode dumper with `hexdump`?
