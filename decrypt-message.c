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

void write_bin(char* filename, unsigned char* bin_str, size_t bin_length) {

  FILE* file = open_file(filename, "wb");
  fwrite(bin_str, sizeof(unsigned char), bin_length, file);
  fclose(file);
  
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


int main(int argc, char* argv[]) {

  if(sodium_init() == -1) {
    return 1;
  }

  // Find the size of the file
  struct stat st;
  stat(argv[1], &st);
  unsigned long long signed_len = st.st_size;

  int nonce_size = crypto_box_NONCEBYTES;
  unsigned char nonce[nonce_size];
  // calculate the size of ciphertext and plaintext from the file

  unsigned long long ciphertext_len = signed_len - crypto_sign_BYTES;
  unsigned long long plaintext_len = ciphertext_len - crypto_box_MACBYTES;

  unsigned char plaintext[plaintext_len];
  unsigned char ciphertext[ciphertext_len];
  unsigned char signed_message[signed_len];
  read_bin(argv[1], signed_message, signed_len);
  read_bin("bin/nonce.bin", nonce, nonce_size);

  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];
  read_bin("keys/sig-verify-sender.bin", sig_verif, crypto_sign_PUBLICKEYBYTES);
  if(crypto_sign_open(ciphertext, &ciphertext_len, signed_message,
                   signed_len, sig_verif) != 0) {
    perror("Could not verify signature.");
    exit(2);

  }

  write_bin("bin/read-signed-ciphertext.bin", signed_message, signed_len);
  unsigned char s_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char r_decryption_key[crypto_box_SECRETKEYBYTES];
  //strncpy(nonce, ciphertext, nonce_size);
  //printf("%s\n", ciphertext);
  write_bin("bin/read-ciphertext.bin", ciphertext, ciphertext_len);

  read_bin("keys/e-key-sender.bin", s_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_bin("keys/d-key-recipt.bin", r_decryption_key,
           crypto_box_SECRETKEYBYTES);

  if(crypto_box_open_easy(plaintext, ciphertext,
                          ciphertext_len, nonce,
                          s_encryption_key, r_decryption_key) !=0) {
    perror("Not a valid decryption.");
    exit(2);
  }

  write("plaintext.txt", plaintext);
  return 0;
}
