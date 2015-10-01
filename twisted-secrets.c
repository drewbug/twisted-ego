#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/sha.h>

extern void curve25519_donna(uint8_t *output, const uint8_t *secret, const uint8_t *bp);

static char *hex_encode(const uint8_t *buf, size_t len);

int main(void) {
  unsigned char gpg_packet[59] = {
    0x99, // "the octet 0x99"
    0x00, 0x38, // "the two-octet packet length"
    0x04, // "A one-octet version number (4)"
    0x55, 0xFD, 0xDE, 0x8F, // "A four-octet number denoting the time that the key was created"
    0x12, // "A one-octet number denoting the public-key algorithm of this key"
    0x0A, // "a one-octet size of the following field"
    0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01, // "octets representing a curve OID"
    0x01, 0x07, // "a two-octet scalar that is the length of the MPI in bits"
    0x40 // "the 0x40 prefix octet"
  };

  gpg_packet[55] = 0x03; // "a one-octet size of the following fields"
  gpg_packet[56] = 0x01; // "a one-octet value 01"
  gpg_packet[57] = 0x08; // "a one-octet hash function ID used with the KDF"
  gpg_packet[58] = 0x09; // "a one-octet algorithm ID for the symmetric algorithm used to wrap the symmetric key for message encryption"

  unsigned char fingerprint[20];

  fprintf(stderr, "Going...\n");

  unsigned char d[32];
  arc4random_buf(&d, 32);

  static const uint8_t basepoint[32] = {9};

  bool match = false;

  while (!match) {
    (*(__uint128_t *) &d[1])--; // HACK: Workaround curve25519_donna()'s bit masking

    curve25519_donna(&gpg_packet[23], d, basepoint);

#pragma clang diagnostic push 
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SHA1(gpg_packet, 59, fingerprint);
#pragma clang diagnostic pop

    match = (fingerprint[16] == 0x0B) && (fingerprint[17] == 0xAD) && (fingerprint[18] == 0xBE) && (fingerprint[19] == 0xEF);
  }

  d[0] &= 248; d[31] &= 127; d[31] |= 64; // Bitmask

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
