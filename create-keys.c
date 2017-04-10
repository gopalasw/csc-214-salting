#include <sodium.h>
#include <stdio.h>

FILE* open_file(char* filename, char* type) {

  FILE* file = fopen(filename, type);
  if(file == NULL) {
    perror(filename);
    exit(2);
  }

  return file;
}

void write_bin(char* filename, unsigned char* key, size_t key_length) {
  FILE* file = open_file(filename, "wb+");
 
  fwrite(key, sizeof(unsigned char), key_length, file);

  fclose(file);
}

void write_keypairs(int option, unsigned char* encryption_key,
                    unsigned char* decryption_key, unsigned char* sig_constr,
                    unsigned char* sig_verify) {
  if(option == 1) {
    write_bin("keys/e-key-sender.bin", encryption_key, crypto_box_PUBLICKEYBYTES);
    write_bin("keys/d-key-sender.bin", decryption_key, crypto_box_SECRETKEYBYTES);
    write_bin("keys/sig-constr-sender.bin", sig_constr, crypto_sign_SECRETKEYBYTES);
    write_bin("keys/sig-verify-sender.bin", sig_verify, crypto_sign_PUBLICKEYBYTES);
  }
  else if(option == 2) {
    write_bin("keys/e-key-recipt.bin", encryption_key, crypto_box_PUBLICKEYBYTES);
    write_bin("keys/d-key-recipt.bin", decryption_key, crypto_box_SECRETKEYBYTES);
    write_bin("keys/sig-constr-recipt.bin", sig_constr, crypto_sign_SECRETKEYBYTES);
    write_bin("keys/sig-verify-recipt.bin", sig_verify, crypto_sign_PUBLICKEYBYTES);
  }
  else {
    printf("Please enter a valid option.\n");
  }

}


int main() {

  if(sodium_init() == -1) {
    return 1;
  }

  int option;
  printf("If you want to generate sender keys, input 1.\nIf you want to generate reciever keys, input 2:\n ");
  scanf("%d", &option);

  unsigned char encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char decryption_key[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(encryption_key, decryption_key);

  unsigned char sig_constr[crypto_sign_SECRETKEYBYTES];
  unsigned char sig_verify[crypto_sign_PUBLICKEYBYTES];
  crypto_sign_keypair(sig_verify, sig_constr);
  
  write_keypairs(option, encryption_key, decryption_key,
                 sig_constr, sig_verify);

  return 0;
}
