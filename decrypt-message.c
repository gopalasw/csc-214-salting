#include <sodium.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

FILE* open_file(char* filename, char* type) {

  FILE* file = fopen(filename, type);
  if(file == NULL) {
    perror(filename);
    exit(2);
  }

  return file;
}

void write(char* filename, unsigned char* message) {

  FILE* file = open_file(filename, "w");
  fputs(message, file);
  fclose(file);
  
}

void read_bin(char* filename, unsigned char* key, size_t len) {

  FILE* file = open_file(filename, "rb");
  if(file == NULL) {
    perror(filename);
    exit(2);
  }
  //read from file
  fread(key, sizeof(unsigned char), len, file);
  fclose(file);
  
}

int main(int argc, char* argv[]) {

  if(sodium_init() == -1) {
    return 1;
  }

  if(argc != 2) {
    fprintf(stderr, "usage: decrypt-message [filename]\n");
    exit(EXIT_FAILURE);
  }

  // Find the size of the input file
  struct stat st;
  stat(argv[1], &st);
  unsigned long long signed_len = st.st_size;

  // declare/define all needed lengths, char arrays
  unsigned long long nonce_len = crypto_box_NONCEBYTES;
  unsigned long long ciphertext_len = signed_len - crypto_sign_BYTES;
  unsigned long long plaintext_len = ciphertext_len - crypto_box_MACBYTES
                                     - nonce_len;

  unsigned char nonce[nonce_len];
  unsigned char plaintext[plaintext_len];
  unsigned char ciphertext[ciphertext_len];
  unsigned char signed_ciphertext[signed_len];
  
  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];
  unsigned char s_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char r_decryption_key[crypto_box_SECRETKEYBYTES];
  
  // read in the signed ciphertext
  read_bin(argv[1], signed_ciphertext, signed_len);

  // read in keys from file
  read_bin("keys/sig-verify-sender.bin", sig_verif,
           crypto_sign_PUBLICKEYBYTES);
  read_bin("keys/e-key-sender.bin", s_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_bin("keys/d-key-recipt.bin", r_decryption_key,
           crypto_box_SECRETKEYBYTES);

  // verify the signature
  if(crypto_sign_open(ciphertext, &ciphertext_len, signed_ciphertext,
                   signed_len, sig_verif) != 0) {
    perror("Could not verify signature.");
    exit(2);

  }

  // copy over the nonce from the ciphertext
  strncpy(nonce, ciphertext, nonce_len);

  // decrypt using nonce
  if(crypto_box_open_easy(plaintext, &(ciphertext[nonce_len]),
                          ciphertext_len - nonce_len, nonce,
                          s_encryption_key, r_decryption_key) !=0) {
    perror("Not a valid decryption.");
    exit(2);
  }

  // write final plaintext to file
  write("plaintext.txt", plaintext);
  return 0;
}
