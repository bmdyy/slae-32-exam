# A6 - Polymorphic Shellcodes

1. execve("/bin/sh") + exit(0), #811, 28 bytes: [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-811.php)
	- Polymorphic: 29 bytes

2. mkdir("hacked", 0755) + exit(0), #542, 36 bytes: [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-542.php)
	- Polymorphic: 29 bytes

3. Add a passwordless account to /etc/passwd, #543, 177 bytes: [shell-storm.org](http://shell-storm.org/shellcode/files/shellcode-543.php)
	- Polymorphic: 139 bytes

To test, run `./compile.sh 811_mod` or whichever shellcode you want and then `./shellcode`
