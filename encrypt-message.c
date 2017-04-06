#include <sodium.h>
#include <stdio.h>
#include <string.h>

FILE* open_file(char* filename, char* type) {

  FILE* file = fopen(filename, type);
  if(file == NULL) {
    perror("opening file");
    exit(2);
  }

  return file;
}

void write_bin(char* filename, unsigned char* bin_str, size_t bin_length) {

  FILE* file = open_file(filename, "wb");
  fwrite(bin_str, sizeof(unsigned char), bin_length, file);
  fclose(file);
  
}

void read_key(char* filename, unsigned char* key, size_t size) {

  FILE* file = open_file(filename, "rb");
  fread(key, sizeof(unsigned char), size, file);
  fclose(file);
  
}

int count_chars(FILE* file) {
  int count = 0;
  char cur = fgetc(file);
  
  while(cur != EOF) {
    count++;
    cur = fgetc(file);
  }

  fclose(file);
  return count;
  
}

void read_file(char* filename, unsigned char* plaintext, int size) {
  FILE* file = open_file(filename, "r");
  int index = 0;
  char cur = fgetc(file);
  while(cur != EOF) {
    plaintext[index] = cur;
    index++;
    cur = fgetc(file);
  }
  fclose(file);

}

int main(int argc, char* argv[]) {

  if(sodium_init() == -1) {
    return 1;
  }

  if(argc != 2) {
    fprintf(stderr, "usage: encrypt-message [filename]\n");
    exit(EXIT_FAILURE);
  }
  
  FILE* plaintext_file = open_file(argv[1], "r");

  // declare/define all needed lengths, char arrays
  unsigned long long nonce_len = crypto_box_NONCEBYTES;
  unsigned long long plaintext_len = count_chars(plaintext_file);
  unsigned long long ciphertext_len = crypto_box_MACBYTES + plaintext_len
                                      + nonce_len;
  unsigned long long signed_len;
  
  unsigned char nonce[nonce_len];
  unsigned char plaintext[plaintext_len];
  unsigned char ciphertext[ciphertext_len];
  unsigned char signed_ciphertext[crypto_sign_BYTES + ciphertext_len];
  
  unsigned char r_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char s_decryption_key[crypto_box_SECRETKEYBYTES];
  unsigned char sig_constr[crypto_sign_SECRETKEYBYTES];

  // read in original plaintext file
  read_file(argv[1], plaintext, plaintext_len);
  
  // read in keys from file
  read_key("keys/e-key-recipt.bin", r_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_key("keys/d-key-sender.bin", s_decryption_key,
           crypto_box_SECRETKEYBYTES);
  read_key("keys/sig-constr-sender.bin", sig_constr,
           crypto_sign_SECRETKEYBYTES);

  // choose a random nonce
  randombytes_buf(nonce, sizeof nonce);

  // encrypt plaintext with random nonce
  if(crypto_box_easy(&ciphertext[nonce_len], plaintext, plaintext_len,
		  nonce, r_encryption_key, s_decryption_key) != 0) {
    perror("Not a valid encryption.");
    exit(2);
  }

  // add nonce to beginning of ciphertext
  strncpy(ciphertext, nonce, nonce_len);

  // sign the ciphertext
  if(crypto_sign(signed_ciphertext, &signed_len, ciphertext,
              ciphertext_len, sig_constr) != 0) {
    perror("Error signing.");
    exit(2);
  }

  // write signed ciphertext to binary file
  write_bin("bin/signed-ciphertext.bin", signed_ciphertext, signed_len);

  return 0;
}
