#include <sodium.h>
#include <stdio.h>
#include <sys/stat.h>

int nonce_length = 10;

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
  int signed_len = st.st_size;

  // calculate the size of ciphertext and plaintext from the file
  unsigned long long ciphertext_len = signed_len - crypto_sign_BYTES;
  int plaintext_len = ciphertext_len - crypto_box_MACBYTES - nonce_length;

  unsigned char plaintext[plaintext_len];
  unsigned char ciphertext[ciphertext_len];
  unsigned char signed_message[signed_len];
  read_bin(argv[1], signed_message, signed_len);


  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];
  read_bin("keys/sig-verify-sender.bin", sig_verif, crypto_sign_PUBLICKEYBYTES);
  int i = crypto_sign_open(ciphertext, &ciphertext_len, signed_message,
                   signed_len, sig_verif);

  unsigned char s_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char r_decryption_key[crypto_box_SECRETKEYBYTES];
  unsigned char nonce[crypto_box_NONCEBYTES];
  strncpy(nonce, ciphertext, nonce_length);

  read_bin("keys/e-key-sender.bin", s_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_bin("keys/d-key-recipt.bin", r_decryption_key,
           crypto_box_SECRETKEYBYTES);
  //randombytes_buf(nonce, sizeof nonce);

  if(crypto_box_open_easy(plaintext, ciphertext[nonce_length],
                          ciphertext_len - nonce_length, nonce,
                          s_encryption_key, r_decryption_key) !=0) {
    perror("Not a valid decryption.");
    exit(2);
  }

  write("plaintext.txt", plaintext);
  return 0;
}
