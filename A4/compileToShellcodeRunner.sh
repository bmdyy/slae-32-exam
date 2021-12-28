#!/bin/bash
# William Moody
# 26.12.2021

if [[ $1 == *".nasm" ]]; then
	echo "[-] .nasm in filename! Aborting to avoid file-loss..."
	exit
fi

echo "[*] Assembling with NASM..."
if ! nasm -f elf32 -o $1.o $1.nasm; then
	echo "    -- ERROR"
	exit
fi

echo "[*] Linking with ld..."
if ! ld -o $1 $1.o; then
	echo "    -- ERROR"
	exit
fi

echo "[*] Dumping shellcode..."
shellcode=$(objdump -d $1|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g')

echo "[*] Writing shellcode runner source file (./shellcode_autogen.c)..."
body=$(cat << EOT > shellcode_autogen.c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
char shellcode[] = $shellcode;
void main()
{
char *buf;
int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
int flags = MAP_PRIVATE | MAP_ANONYMOUS;
buf = mmap(0, sizeof(shellcode), prot, flags, -1, 0);
memcpy(buf, shellcode, sizeof(shellcode));
((void (*)(void))buf)();    
}
EOT
)

echo "[*] Compiling shellcode runner..."
if ! gcc -o shellcode shellcode_autogen.c; then
	echo "    -- ERROR"
	exit
fi

echo "[+] All done! Shellcode runner at ./shellcode"
