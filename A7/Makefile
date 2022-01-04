CC=gcc
CFLAGS=-I.
DEPS=blowfish.h
OBJ_CRYPT=BlowfishCrypter.o blowfish.o
OBJ_EXEC=BlowfishExecShellcode.o blowfish.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

BlowfishCrypter: $(OBJ_CRYPT)
	$(CC) -o $@ $^ $(CFLAGS)

BlowfishExecShellcode: $(OBJ_EXEC)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean
clean:
	rm *.o BlowfishCrypter BlowfishExecShellcode
