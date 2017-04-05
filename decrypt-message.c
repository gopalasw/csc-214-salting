#include <sodium.h>
#include <stdio.h>

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

void write(char* filename, unsigned char* message) {

  FILE* file = open_file(filename, "w");
  fputs(message, file);
  fclose(file);
  
}

void read_bin(char* filename, unsigned char* key, size_t len) {

  FILE* file = open_file(filename, "rb");
  //read from file
  fread(key, sizeof(unsigned char), len, file);
  fclose(file);
  
}


int main(int argc, char* argv[]) {

  if(sodium_init() == -1) {
    return 1;
  }

  int plaintext_len = 21;
  unsigned long long ciphertext_len = crypto_box_MACBYTES + plaintext_len;
  int signed_len = crypto_sign_BYTES + ciphertext_len;


  unsigned char plaintext[plaintext_len];
  unsigned char ciphertext[ciphertext_len];
  unsigned char signed_message[signed_len];
  read_bin(argv[1], signed_message, signed_len);


  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];
  //unsigned long long ciphertext_len;
  read_bin("sig-verify-sender.bin", sig_verif, crypto_sign_PUBLICKEYBYTES);
  int i = crypto_sign_open(ciphertext, &ciphertext_len, signed_message,
                   signed_len, sig_verif);
  printf("Did signing work? : %d\n", i);
  /*
  FILE* signed_file = open_file(argv[1], "rb");
  int signed_len = count_chars(signed_file);
  // int ciphertext_len = crypto_box_MACBYTES + plaintext_len;
  unsigned char signed_message[signed_len + 1];
  read_file(signed_file, signed_message, signed_len);

  */

  //FILE* ciphertext_file = open_file(argv[1], "rb");

  unsigned char s_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char r_decryption_key[crypto_box_SECRETKEYBYTES];
  unsigned char nonce[crypto_box_NONCEBYTES] = "0";

  read_bin("e-key-sender.bin", s_encryption_key, crypto_box_PUBLICKEYBYTES);
  read_bin("d-key-recipt.bin", r_decryption_key, crypto_box_SECRETKEYBYTES);
  //randombytes_buf(nonce, sizeof nonce);

  if(crypto_box_open_easy(plaintext, ciphertext,
                          ciphertext_len, nonce,
                          s_encryption_key, r_decryption_key) !=0) {
    perror("Not a valid decryption.");
    exit(2);
  }

  write("plaintext.txt", plaintext);
  return 0;
}
