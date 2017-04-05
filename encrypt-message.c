#include <sodium.h>
#include <stdio.h>

#define MESSAGE (const unsigned char*) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

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
/*
void write_info(char* filename, unsigned char* message[], int size) {

  FILE* file = open_file(filename, "w");
  int i = 0;
  for(i = 0; i < size; i++) {
    fputs(message[i], file);
    fputs("\n", file);
  }
  fclose(file);
  
}
*/
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
    printf("%c", cur);
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
  unsigned long long ciphertext_len = crypto_box_MACBYTES + plaintext_len;
  unsigned char plaintext[plaintext_len];
  read_file(argv[1], plaintext, plaintext_len);

  unsigned char r_encryption_key[crypto_box_PUBLICKEYBYTES];
  unsigned char s_decryption_key[crypto_box_SECRETKEYBYTES];
  unsigned char nonce[crypto_box_NONCEBYTES] = "0";
  unsigned char ciphertext[ciphertext_len];
  
  read_key("keys/e-key-recipt.bin", r_encryption_key,
           crypto_box_PUBLICKEYBYTES);
  read_key("keys/d-key-sender.bin", s_decryption_key,
           crypto_box_SECRETKEYBYTES);
  //randombytes_buf(nonce, sizeof nonce);
  //unsigned char decrypted[MESSAGE_LEN];

  int j = crypto_box_easy(ciphertext, plaintext, plaintext_len, nonce,
                  r_encryption_key, s_decryption_key);

  write_bin("bin/ciphertext.bin", ciphertext, ciphertext_len);

  unsigned char sig_verif[crypto_sign_PUBLICKEYBYTES];

  unsigned char sig_constr[crypto_sign_SECRETKEYBYTES];
  unsigned char signed_message[crypto_sign_BYTES + plaintext_len];
  unsigned long long signed_message_len;
  read_key("keys/sig-constr-sender.bin", sig_constr,
           crypto_sign_SECRETKEYBYTES);
  crypto_sign(signed_message, &signed_message_len, ciphertext,
              ciphertext_len, sig_constr);

  write_bin("signed-ciphertext.bin", signed_message, signed_message_len);

  return 0;
}
