TARGET = create-keys encrypt-message decrypt-message
CC=gcc
CFLAGS = -lsodium

all : $(TARGET)
init: create-keys.c
	$(CC) -o create-keys create-keys.c $(CFLAGS)

encrypt: encrypt-message.c
	$(CC) -o encrypt-message encrypt-message.c $(CFLAGS)

decrypt: decrypt-message.c
	$(CC) -o decrypt-message decrypt-message.c $(CFLAGS)

clean:
	rm -f *.o *~ core* $(TARGET)
	rm plaintext.txt signed-ciphertext.bin keys/*	
