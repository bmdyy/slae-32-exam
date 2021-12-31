# A4 - Custom Encoding Scheme

Paste whatever shellcode you want in `encoder.py` and run it to get some lines you need to paste into `decoder.nasm`. They are well marked in the source file.

Run `./compile.sh decoder` to get `./shellcode` which lets you run the decoder shellcode. To get the shellcode of decoder itself, you will need to edit `compile.sh` to not delete the temporary files and then dump the shellcode of `./decoder` with this command: `python3 dumpShellcode.py decoder`.
