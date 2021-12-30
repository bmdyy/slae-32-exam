# A4 - Custom Encoding Scheme

Run `./compile.sh decoder` to get `./shellcode` which lets you run the decoder shellcode. To get the shellcode of decoder itself, you will need to edit `compile.sh` to not delete the temporary files and then dump the shellcode of `./decoder` with this command: `python3 dumpShellcode.py decoder`.
