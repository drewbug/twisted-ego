#include <stdbool.h>
#include <stdio.h>

#include <openssl/sha.h>

#include "ed25519-donna/ed25519.h"

static char *hex_encode(const uint8_t *buf, size_t len);

int main(void) {
  unsigned char gpg_packet[54] = {
    0x99, // "the octet 0x99"
    0x00, 0x33, // "the two-octet packet length"
    0x04, // "A one-octet version number (4)"
    0x53, 0xF3, 0x5F, 0x0B, // "A four-octet number denoting the time that the key was created"
    0x16, // "A one-octet number denoting the public-key algorithm of this key"
    0x09, // "a one-octet size of the following field"
    0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01, // "octets representing a curve OID"
    0x01, 0x07, // "a two-octet scalar that is the length of the MPI in bits"
    0x40 // "the 0x40 prefix octet"
  };

  unsigned char fingerprint[20];

  fprintf(stderr, "Going...\n");

  ed25519_secret_key d;
  arc4random_buf(&d, 32);

  bool match = false;

  while (!match) {
    (*(__uint128_t *) d)--;

    ed25519_publickey(d, &gpg_packet[22]);

#pragma clang diagnostic push 
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SHA1(gpg_packet, 54, fingerprint);
#pragma clang diagnostic pop

    match = (fingerprint[16] == 0x0B) && (fingerprint[17] == 0xAD) && (fingerprint[18] == 0xBE) && (fingerprint[19] == 0xEF);
  }

  fprintf(stderr, "%s\n", hex_encode(d, sizeof(d)));
  fprintf(stderr, "%s\n", hex_encode(gpg_packet, sizeof(gpg_packet)));
  fprintf(stderr, "%s\n", hex_encode(fingerprint, sizeof(fingerprint)));

  return 0;
}

static char * hex_encode(const uint8_t *buf, size_t len) {
  char *ret = calloc((len * 2) + 1, 1);

  for (size_t i = 0; i < len; i++) {
    sprintf(ret + (i * 2), "%02X", buf[i]);
  }

  return ret;
}
