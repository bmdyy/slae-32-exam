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

echo "[*] Creating shellcode dump script..."
echo -n aW1wb3J0IHN5cwp3aXRoIG9wZW4oc3lzLmFyZ3ZbMV0sICJyYiIpIGFzIGY6CglicyA9IGYucmVhZCgpCQoJaSA9IDB4MTAwMAoJYjEgPSAweGZmCgliMiA9IDB4ZmYKCXNoZWxsY29kZSA9ICIiCgl3aGlsZSBUcnVlOgoJCXNoZWxsY29kZSArPSAiXFx4JS4yeCIgJSBic1tpXQoJCWkgKz0gMQoJCWIxID0gYjIKCQliMiA9IGJzW2ldCgkJaWYgYjEgPT0gYjIgPT0gMHgwMDoKCQkJYnJlYWsKCXByaW50KCciJytzaGVsbGNvZGVbOi00XSsnIicpCg== | base64 -d > dumpShellcode.py

echo "[*] Dumping shellcode..."
shellcode=$(python3 dumpShellcode.py $1)

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
printf("[*] %d bytes\n", strlen(shellcode));
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

echo "[*] Removing temporary files..."
rm "$1.o"
rm "shellcode_autogen.c"
rm "dumpShellcode.py"
#rm "$1"

echo "[+] All done! Shellcode runner at ./shellcode"
