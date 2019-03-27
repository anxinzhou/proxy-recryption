// Boneh-Lynn-Shacham short signatures demo.
//
// See the PBC_sig library for a practical implementation.
//
// Ben Lynn
#include "proxy.h"

pairing_t pairing;
element_t g, h, z;
const int ZR_LEN = 20;
const int G1_LEN = 128;
const int G2_LEN = 128;
const int GT_LEN = 128;

void init() {
  char *s="type a \
  q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791 \
  h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776 \
  r 730750818665451621361119245571504901405976559617 \
  exp2 159 \
  exp1 107 \
  sign1 1 \
  sign0 1";
  pairing_init_set_str(pairing,s);
  element_init_G1(g, pairing);
  element_init_G2(h, pairing);
  element_init_GT(z, pairing);
  element_from_hash(g, "g generator", 11);
  element_from_hash(h, "h generator", 11);
  element_pairing(z,g,h);
}

int gen_private_key(unsigned char *buffer) {
  element_t private_key;
  element_init_Zr(private_key, pairing);
  element_random(private_key);
  int t = element_to_bytes(buffer,private_key);

  element_clear(private_key);
  return t;
}

int gen_recryption_key(unsigned char * recryption_key_buffer,unsigned char *delegatee_public_key_buffer, unsigned char *delegator_private_key_buffer, unsigned char *delegator_sign_key_buffer) {
  element_t public_key;
  element_init_G2(public_key,pairing);
  element_from_bytes(public_key,delegatee_public_key_buffer);

  element_t private_key;
  element_init_Zr(private_key,pairing);
  element_from_bytes(private_key,delegator_private_key_buffer);

  element_t sign_key;
  element_init_Zr(sign_key,pairing);
  element_from_bytes(sign_key,delegator_sign_key_buffer);

  element_t recryption_key;
  element_init_G2(recryption_key,pairing);

  element_t coeff;
  element_init_Zr(coeff,pairing);
  element_invert(coeff, private_key);
  element_mul(coeff,coeff,sign_key);

  element_pow_zn(recryption_key,public_key,coeff);
  int t= element_to_bytes(recryption_key_buffer,recryption_key);

  element_clear(public_key);
  element_clear(private_key);
  element_clear(sign_key);
  element_clear(recryption_key);
  element_clear(coeff);
  return t;
}

int delegatee_publickey_from_private_key(unsigned char *public_key_buffer,unsigned char *private_key_buffer) {
  element_t private_key;
  element_init_Zr(private_key,pairing);
  element_from_bytes(private_key,private_key_buffer);

  element_t public_key;
  element_init_G2(public_key, pairing);
  element_pow_zn(public_key,h,private_key);
  int t = element_to_bytes(public_key_buffer,public_key);

  element_clear(private_key);
  element_clear(public_key);
  return t;
}

void enc_first_level(unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *message_buffer, unsigned char * sign_key_buffer) {
    element_t k;
    element_init_Zr(k,pairing);
    element_random(k);

    element_t sign_key;
    element_init_Zr(sign_key,pairing);
    element_from_bytes(sign_key,sign_key_buffer);

    element_mul(sign_key,k,sign_key);

    element_t share1;
    element_init_GT(share1,pairing);
    element_pow_zn(share1,z,sign_key);
    element_to_bytes(share1_buffer,share1);

    element_t message;
    element_init_GT(message,pairing);
    element_from_bytes(message,message_buffer);

    element_t share2;
    element_init_GT(share2, pairing);
    element_pow_zn(share2,z,k);
    element_mul(share2,share2,message);
    element_to_bytes(share2_buffer,share2);

    element_clear(k);
    element_clear(sign_key);
    element_clear(share1);
    element_clear(message);
    element_clear(share2);
}

void dec_first_level(unsigned char * message_buffer,unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *sign_key_buffer) {
    element_t sign_key;
    element_init_Zr(sign_key,pairing);
    element_from_bytes(sign_key,sign_key_buffer);

    element_t share1;
    element_init_GT(share1,pairing);
    element_from_bytes(share1,share1_buffer);

    element_t share2;
    element_init_GT(share2,pairing);
    element_from_bytes(share2,share2_buffer);

    element_invert(sign_key,sign_key);
    element_pow_zn(share1,share1,sign_key);

    element_t m;
    element_init_GT(m,pairing);
    element_div(m,share2,share1);
    element_to_bytes(message_buffer,m);

    element_clear(sign_key);
    element_clear(share1);
    element_clear(share2);
    element_clear(m);
}

void enc_second_level(unsigned char *share1_buffer, unsigned char *share2_buffer, unsigned char *message_buffer, unsigned char * private_key_buffer ,unsigned char * sign_key_buffer) {
    element_t k;
    element_init_Zr(k,pairing);
    element_random(k);

    // share 1

    element_t share1;
    element_init_G1(share1, pairing);

    element_t private_key;
    element_init_Zr(private_key, pairing);
    element_from_bytes(private_key, private_key_buffer);
    element_mul(private_key,private_key,k);
    element_pow_zn(share1,g,private_key);
    element_to_bytes(share1_buffer,share1);

    // share2 
    element_t sign_key;
    element_init_Zr(sign_key,pairing);
    element_from_bytes(sign_key,sign_key_buffer);
    element_mul(sign_key,k,sign_key);

    element_t share2;
    element_init_GT(share2,pairing);
    element_pow_zn(share2,z,sign_key);

    element_t message;
    element_init_GT(message,pairing);
    element_from_bytes(message,message_buffer);
    element_mul(share2,share2,message);
    element_to_bytes(share2_buffer,share2);

    element_clear(k);
    element_clear(private_key);
    element_clear(sign_key);
    element_clear(share1);
    element_clear(message);
    element_clear(share2);
}

void dec_second_level(unsigned char *message_buffer, unsigned char * share1_buffer, unsigned char * share2_buffer, unsigned char * private_key_buffer, unsigned char * sign_key_buffer) {
    element_t private_key;
    element_init_Zr(private_key, pairing);
    element_from_bytes(private_key, private_key_buffer);

    element_t sign_key;
    element_init_Zr(sign_key, pairing);
    element_from_bytes(sign_key, sign_key_buffer);

    element_invert(private_key,private_key);
    element_mul(sign_key,sign_key,private_key);

    element_t share1;
    element_init_G1(share1, pairing);
    element_from_bytes(share1,share1_buffer);
    element_pow_zn(share1,share1,sign_key);

    // z^ark = pair(g^ark, h)
    element_t zark;
    element_init_GT(zark, pairing);
    element_pairing(zark,share1,h);

    element_t share2;
    element_init_GT(share2, pairing);
    element_from_bytes(share2,share2_buffer);

    element_t m;
    element_init_GT(m,pairing);
    element_div(m,share2,zark);
    element_to_bytes(message_buffer,m);

    element_clear(private_key);
    element_clear(sign_key);
    element_clear(share1);
    element_clear(zark);
    element_clear(share2);
    element_clear(m);
}

void enc_recryption(unsigned char *recrypt_share1_buffer, unsigned char *recrypt_share2_buffer, unsigned char *old_share1_buffer, unsigned char *old_share2_buffer, unsigned char *recryption_key_buffer) {
    element_t recryption_key;
    element_init_G2(recryption_key,pairing);
    element_from_bytes(recryption_key,recryption_key_buffer);

    element_t old_share1;
    element_init_G1(old_share1,pairing);
    element_from_bytes(old_share1,old_share1_buffer);

    element_t old_share2;
    element_init_GT(old_share2,pairing);
    element_from_bytes(old_share2, old_share2_buffer);


    // recryption share1;
    element_t recrypt_share1;
    element_init_GT(recrypt_share1, pairing);
    element_pairing(recrypt_share1, old_share1, recryption_key);
    element_to_bytes(recrypt_share1_buffer,recrypt_share1);

    // // recryption share2;
    element_t recrypt_share2;
    element_init_GT(recrypt_share2,pairing);
    element_set(recrypt_share2,old_share2);
    element_to_bytes(recrypt_share2_buffer,recrypt_share2);

    element_clear(recryption_key);
    element_clear(old_share1);
    element_clear(old_share2);
    element_clear(recrypt_share1);
    element_clear(recrypt_share2);
}

void dec_recryption(unsigned char * message_buffer, unsigned char * share1_buffer, unsigned char * share2_buffer, unsigned char * private_key_buffer) {
    // use delegatee private key to decrypt

    element_t share1;
    element_init_GT(share1,pairing);
    element_from_bytes(share1, share1_buffer);

    element_t share2;
    element_init_GT(share2,pairing);
    element_from_bytes(share2, share2_buffer);

    element_t private_key;
    element_init_Zr(private_key, pairing);
    element_from_bytes(private_key, private_key_buffer);
    element_invert(private_key,private_key);
    element_pow_zn(share1, share1, private_key);

    element_t m;
    element_init_GT(m,pairing);
    element_div(m,share2,share1);

    element_to_bytes(message_buffer,m);

    element_clear(share1);
    element_clear(share2);
    element_clear(private_key);
    element_clear(m);
}

void __bytes_to_hex(unsigned char *buffer) {
   unsigned char *p= buffer;
   while(*p) {
      printf("%X",*p);
      p++;
   }
}

void printPoint(unsigned char*buffer,void(*initFunc)(element_t,pairing_t)) {
  element_t m;
  initFunc(m,pairing);
  element_from_bytes(m,buffer);
  element_printf("point :%B\n",m);
  element_clear(m);
}

void testElementFromBytes() {
   unsigned char c[128];
   element_t m;
   element_init_GT(m,pairing);
   element_from_bytes(m,c);
   element_printf("point :%B\n",m);
   element_clear(m);
}


void proxy_encryption_test() {
  // init pairing
  init();

  // gen delegator key
  unsigned char delegator_private_key_buffer[ZR_LEN];
  gen_private_key(delegator_private_key_buffer);

  unsigned char delegator_sign_key_buffer[ZR_LEN];
  gen_private_key(delegator_sign_key_buffer);


  // gen delegatee key
  unsigned char delegatee_private_key_buffer[ZR_LEN];
  gen_private_key(delegatee_private_key_buffer);
  unsigned char delegatee_public_key_buffer[G2_LEN];
  delegatee_publickey_from_private_key(delegatee_public_key_buffer, delegatee_private_key_buffer);


  // gen recryption key
  unsigned char recryption_key_buffer[G2_LEN];
  gen_recryption_key(recryption_key_buffer, delegatee_public_key_buffer, delegator_private_key_buffer, delegator_sign_key_buffer);


  // printf("first level encryption:\n");
  unsigned char first_share1_buffer[GT_LEN];
  unsigned char first_share2_buffer[GT_LEN];
  unsigned char first_raw_message_buffer[GT_LEN]="1";
  enc_first_level(first_share1_buffer,first_share2_buffer,first_raw_message_buffer,delegator_sign_key_buffer);
  unsigned char first_recovered_message_buffer[GT_LEN];
  dec_first_level(first_recovered_message_buffer, first_share1_buffer, first_share2_buffer, delegator_sign_key_buffer);

  // printPoint(first_raw_message_buffer,element_init_GT);
  // printPoint(first_recovered_message_buffer,element_init_GT);
  if(!strcmp((const char *)first_raw_message_buffer, (const char *)first_recovered_message_buffer)) {
    printf("first level encryption pass test!! ok\n");
  } else {
    printf("!! fail, first level can not pass, fail\n");
  }
  printf("first level raw message: %s\n",first_raw_message_buffer);
  printf("decrypted first level message:%s\n",first_recovered_message_buffer);

    
  // test recryption
  // second level encryption
  unsigned char second_share1_buffer[G1_LEN];
  unsigned char second_share2_buffer[GT_LEN];
  unsigned char second_raw_message_buffer[GT_LEN]="32142341";
  enc_second_level(second_share1_buffer, second_share2_buffer, second_raw_message_buffer, delegator_private_key_buffer , delegator_sign_key_buffer);

  // decrypt second level encryption
  unsigned char second_recovered_message_buffer[GT_LEN];
  dec_second_level(second_recovered_message_buffer, second_share1_buffer,second_share2_buffer,delegator_private_key_buffer, delegator_sign_key_buffer);
  // printPoint(second_raw_message_buffer,element_init_GT);
  // printPoint(second_recovered_message_buffer,element_init_GT);
  if(!strcmp((const char *)second_raw_message_buffer, (const char *)second_recovered_message_buffer)) {
    printf("second level encryption pass test!! ok\n");
  } else {
    printf("!! fail, second level can not pass!! fail\n");
  }
  printf("second level raw message: %s\n",second_raw_message_buffer);
  printf("decrypted second level message:%s\n",second_recovered_message_buffer);

  // recryption
  unsigned char recrypt_share1_buffer[GT_LEN];
  unsigned char recrypt_share2_buffer[GT_LEN];
  enc_recryption(recrypt_share1_buffer, recrypt_share2_buffer, second_share1_buffer, second_share2_buffer, recryption_key_buffer);

  // decrypt recryption
  unsigned char recryption_recovered_message_buffer[GT_LEN];
  dec_recryption(recryption_recovered_message_buffer, recrypt_share1_buffer, recrypt_share2_buffer, delegatee_private_key_buffer);
  // printPoint(second_raw_message_buffer,element_init_GT);
  // printPoint(recryption_recovered_message_buffer,element_init_GT);
  if(!strcmp((const char *)second_raw_message_buffer, (const char *)recryption_recovered_message_buffer)) {
    printf("reencryption pass test!!, ok\n");
  } else {
    printf("!! fail, recryption can not pass, fail\n");
  }
  printf("second level raw message: %s\n",second_raw_message_buffer);
  printf("after recryption decrpytion, message:%s\n",recryption_recovered_message_buffer);
}

int main() {
  proxy_encryption_test();
}
