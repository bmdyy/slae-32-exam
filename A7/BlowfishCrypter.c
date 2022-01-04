/*
A7 - Custom Crypter
SLAE32 Exam
William Moody
PA-25640

References:
	https://www.schneier.com/academic/blowfish/download/
	https://www.design-reuse.com/articles/5922/encrypting-data-with-the-blowfish-algorithm.html
*/

#include <stdio.h>
#include <string.h>
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
	int s_len = 80;
	unsigned char *shellcode = \
	"\x31\xc0\xb0\x68\x50\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";	
	////////////////////////////////////////////

	int c_len = 0;
	unsigned char ciphertext[256];

	long unsigned int m_left;
	long unsigned int m_right;
	int blocklen;

	printf("[*] Encrypting shellcode...");

	int i = 0;
	while (i < s_len)
	{
		m_left = m_right = 0;

		for (blocklen = 0; blocklen < 4; blocklen++)
		{
			m_left = m_left << 8;
			if (i < s_len)
			{
				m_left += shellcode[i++];
			}
			else m_left += 0;
		}
		for (blocklen = 0; blocklen < 4; blocklen++)
		{
			m_right = m_right << 8;
			if (i < s_len)
			{
				m_right += shellcode[i++];
			}
			else m_right += 0;
		}

		Blowfish_Encrypt(&ctx, &m_left, &m_right);

		ciphertext[c_len++] = (unsigned char)(m_left >> 24);
		ciphertext[c_len++] = (unsigned char)(m_left >> 16);
		ciphertext[c_len++] = (unsigned char)(m_left >> 8);
		ciphertext[c_len++] = (unsigned char)(m_left);
		ciphertext[c_len++] = (unsigned char)(m_right >> 24);
		ciphertext[c_len++] = (unsigned char)(m_right >> 16);
		ciphertext[c_len++] = (unsigned char)(m_right >> 8);
		ciphertext[c_len++] = (unsigned char)(m_right);
	}

	printf("OK\n");
	printf("[*] Paste the following into the runner and compile:\n\n");

	printf("int c_len = %d;\n", c_len);
	printf("unsigned char *ciphertext = \\\n\"");
	for (i = 0; i < c_len; i++)
	{
		printf("\\x%02x", ciphertext[i]);
		if (!((i + 1) % 16)) 
		{
			printf("\"");
			if ((i + 1) < s_len) printf("\n\"");
		}
	}
	printf(";\n");
}
