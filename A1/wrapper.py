#!/usr/bin/python3

# Wrapper script for compiling and linking shell_bind_tcp.nasm
# with a user-defined port number to listen on.

# William Moody
# 27.12.2021

import socket
import subprocess
import os

# Get the LPORT from user and calculate htons value

lport = input("[*] Please enter desired LPORT: ")

if not lport.isdigit():
	print("[-] Numeric value required!")
	exit(1)

lport = int(lport)
if lport < 0 or lport > 65355:
	print("[-] Invalid number for port!")
	exit(1)

lport_htons = socket.htons(lport)
print("    -- htons(%d) = 0x%x" % (lport, lport_htons))
print()

# Replace the placeholder in the file with the LPORT

orig = open("shell_bind_tcp.nasm", "r")
autogen = open("tmp.nasm", "w")

for line in orig:
	if "PLACEHOLDER" in line:
		line = line.replace("PLACEHOLDER", "0x%x" % lport_htons)
	autogen.write(line)

orig.close()
autogen.close()

# Assemble and link the file

print("[*] Assembling...", end="")
if subprocess.call("nasm -f elf32 -o tmp.o tmp.nasm", shell=True) > 0:
	print("ERROR")
	exit(1)
print("OK")

print("[*] Linking...", end="")
if subprocess.call("ld -o bind_shell_tcp tmp.o", shell=True) > 0:
	print("ERROR")
	exit(1)
print("OK")

# Delete temporary files

os.remove("tmp.nasm")
os.remove("tmp.o")

# Dump shellcode

print("[*] Dumping shellcode...", end="")
proc = subprocess.Popen("""objdump -d bind_shell_tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""", shell=True, stdout=subprocess.PIPE)
shellcode = proc.stdout.read().rstrip().decode()
print("OK")

# Print some statistics about the shellcode

print("\n%s\n" % shellcode)
print("[*] Length: %d bytes" % (len(shellcode.replace("\\x","")) / 2))
print("[*] Contains NULL bytes?: %s" % ("YES" if "00" in shellcode else "NO"))
