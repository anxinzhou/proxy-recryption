#ifndef BLS_H
#define BLS_H
#include <pbc.h>
#include <pbc_test.h>
#include <string.h>
#endif

// init curve 
void init();

//  gen private key return length
int gen_private_key(unsigned char *buffer);

// gen recryption_key   return length
// require delegator private key, delegatee public key.
int gen_recryption_key(unsigned char * recryption_key_buffer,unsigned char *delegatee_public_key_buffer, unsigned char *delegator_private_key_buffer, unsigned char *delegator_sign_key_buffer);

// get public key from private key for delegatee  return length;
int delegatee_publickey_from_private_key(unsigned char *public_key_buffer,unsigned char *private_key_buffer);


// make sure message length=128;
// encryption message for first level, share1 and share2 used to store ciphertext.
// delegator sign key is needed.
void enc_first_level(unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *message_buffer, unsigned char * sign_key_buffer);

// decryption for first level and store result in message_buffer
// delegator sign key is needed.
void dec_first_level(unsigned char * message_buffer,unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *sign_key_buffer);

// make sure message length=128;
//  encryption message for second level, share1 and share2 used to store ciphertext
void enc_second_level(unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *message_buffer, unsigned char * private_key_buffer ,unsigned char * sign_key_buffer);

//  decryption for second level and store result in message_buffer;
void dec_second_level(unsigned char *message_buffer, unsigned char * share1_buffer, unsigned char * share2_buffer, unsigned char * private_key_buffer, unsigned char * sign_key_buffer);

// recryption ciphertext(share1,share2)  to ciphertext(recrypt share1, recrypt share2);
void enc_recryption(unsigned char *recrypt_share1_buffer, unsigned char *recrypt_share2_buffer, unsigned char *old_share1_buffer, unsigned char *old_share2_buffer, unsigned char *recryption_key_buffer);

// decrypt encrypted message(share1,share2);
// require delegatee private key; 
void dec_recryption(unsigned char * message_buffer, unsigned char * share1_buffer, unsigned char * share2_buffer, unsigned char * private_key_buffer);

// quick test for recryption scheme;
void proxy_encryption_test();
