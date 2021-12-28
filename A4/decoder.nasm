; A4 - Custom Encoding Scheme
; William Moody
; PA-25640
; 28.12.2021

global _start
section .text

_start:

	jmp short call_decoder

decoder:
	
	pop eax						; EAX points to key
	lea edi, [eax +0x1]			; EDI points to shellcode
	mov al, byte [eax]			; EAX contains value of key in right-most 2 bits
	and eax, 0xff				; Clear first 6 bits of EAX. EAX is now key
	mov esi, eax				; Store value of key in ESI

	; At this point:
	; => ESI = key
	; => EDI = *shellcode

	xor eax, eax				; i = 0
	xor ebx, ebx				; j = 0

decode_loop:

	mov cl, byte [edi +eax]		; l = enc_shellcode[i]
	mov dl, byte [edi +eax +1]	; r = enc_shellcode[i+1]

	sub cl, 97					; l_dec = l - 97
	sub dl, 97					; r_dec = r - 97

	shl cl, 0x4					; dec = .. l_dec << 4 ..
	add cl, dl					; dec = (..) + r_dec

	xor ecx, esi				; dec ^ key

	; At this point:
	; => CL = Decoded byte

	mov [edi +ebx], byte cl		; Write decoded byte to shellcode memory

	inc ebx						; j += 1
	add eax, 0x2				; i += 2

	; --- PASTE LENGTH (encoder.py) HERE ---
	cmp eax, 0x28
	; --- --- --- --- --- --- --- --- --- --
	jnae decode_loop			; Loop if i < len(enc_shellcode)

	jmp short shellcode 		; Hand over control to decoded shellcode

call_decoder:
	
	call decoder

	; --- PASTE OUTPUT FROM encoder.py HERE ---
	key: db 0x13
	shellcode: db "bdbcbbbabhbgbfbeblbkbjbibpbobnbmadacabaa"
	; --- --- --- --- --- --- --- --- --- --- -
