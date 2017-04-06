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
  //read from file
  fread(key, sizeof(unsigned char), size, file);
 // fgets(key, size, file);
 // ("%s\n", key);
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

void read_file(char* filename, unsigned char* plaintext, int size) {
  FILE* file = open_file(filename, "r");
  //read from file
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
  
  FILE* plaintext_file = open_file(argv[1], "r");
  int plaintext_len = count_chars(plaintext_file); 
  unsigned char nonce[crypto_box_NONCEBYTES];
  int nonce_size = sizeof nonce;
  unsigned long long ciphertext_len = crypto_box_MACBYTES + plaintext_len;
  unsigned char plaintext[plaintext_len];
  read_file(argv[1], plaintext, plaintext_len);
  unsigned char r_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char s_decryption_key[crypto_box_SECRETKEYBYTES];
  unsigned char ciphertext[ciphertext_len];
  
  read_key("keys/e-key-recipt.bin", r_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_key("keys/d-key-sender.bin", s_decryption_key,
           crypto_box_SECRETKEYBYTES);
  randombytes_buf(nonce, sizeof nonce);
  
  int j = crypto_box_easy(ciphertext, plaintext, plaintext_len,
		  nonce, r_encryption_key, s_decryption_key);

  //strncpy(ciphertext, nonce, nonce_size);
  write_bin("bin/ciphertext.bin", ciphertext, ciphertext_len);
  write_bin("bin/nonce.bin", nonce, nonce_size);
  printf("%s\n", nonce);

  unsigned char sig_constr[crypto_sign_SECRETKEYBYTES];
  unsigned char signed_message[crypto_sign_BYTES + ciphertext_len];
  unsigned long long signed_message_len;
  read_key("keys/sig-constr-sender.bin", sig_constr,
           crypto_sign_SECRETKEYBYTES);
  
  if(crypto_sign(signed_message, &signed_message_len, ciphertext,
              ciphertext_len, sig_constr) != 0) {
    perror("Error signing.");
    exit(2);
  }

  write_bin("bin/signed-ciphertext.bin", signed_message, signed_message_len);


  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];
  read_bin("keys/sig-verify-sender.bin", sig_verif,
		 crypto_sign_PUBLICKEYBYTES);
  if(crypto_sign_open(ciphertext, &ciphertext_len, signed_message,
                   signed_message_len, sig_verif) != 0) {
    perror("Could not verify signature.");
    exit(2);

  }



  unsigned char s_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char r_decryption_key[crypto_box_SECRETKEYBYTES];
  //strncpy(nonce, ciphertext, nonce_size);
  printf("%d\n", ciphertext_len);

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



  return 0;
}
