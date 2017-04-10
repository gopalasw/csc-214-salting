# csc-214-salting
Compile all files with `make`  
  Clean with `make clean`

### Creating keys
Run create-keys with `./create-keys`
Enter `1` at prompt for sender keys, and `2` for reciever keys.

### Encrypting files
Run `./encrypt-message [filename]` to encrypt a file.

### Decrypting files
Run `./decrypt-message [filename]` to decrypt a file.
By default, encryption of all files using `./encrypt-message` are written to the file `signed-ciphertext.bin`.
