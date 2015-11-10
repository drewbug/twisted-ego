#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/sha.h>

#include "curve25519-donna/curve25519.h"

static void swap_bytes(unsigned char *buf, size_t len);
static char *hex_encode(const uint8_t *buf, size_t len);

int main(void) {
  unsigned char gpg_packet[96] = {
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

  curve25519_key d;
  arc4random_buf(&d, 32);

  bool match = false;

  while (!match) {
    (*(__uint128_t *) &d[1])--; // HACK: Workaround clamping of lower & upper bits

    curve25519_donna_basepoint(&gpg_packet[23], d);

#pragma clang diagnostic push 
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SHA1(gpg_packet, 59, fingerprint);
#pragma clang diagnostic pop

    match = (fingerprint[16] == 0x0B) && (fingerprint[17] == 0xAD) && (fingerprint[18] == 0xBE) && (fingerprint[19] == 0xEF);
  }

  gpg_packet[1] = 0x94; // secret key packet tag

  gpg_packet[2] = 0x5D; // "one-octet Body Length header"

  d[0] &= 248; d[31] &= 127; d[31] |= 64;
  fprintf(stderr, "%s\n", hex_encode(d, sizeof(d)));
  fprintf(stderr, "%s\n", hex_encode(gpg_packet, sizeof(gpg_packet)));
  fprintf(stderr, "%s\n", hex_encode(fingerprint, sizeof(fingerprint)));

  gpg_packet[59] = 0x00; // "One octet indicating string-to-key usage conventions"

  swap_bytes(d, 32);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  unsigned short bits = BN_num_bits(BN_bin2bn(d, 32, NULL));
#pragma clang diagnostic pop

  // "a two-octet scalar that is the length of the MPI in bits"
  gpg_packet[60] = (unsigned char)(bits >> 8) & 0xff;
  gpg_packet[61] = (unsigned char)(bits) & 0xff;

  memcpy(&gpg_packet[62], d, 32); // "an integer representing the secret key, which is a scalar of the public EC point"

  // a two-octet checksum of the plaintext of the algorithm-specific portion
  unsigned short checksum = 0;
  for (int i = 0; i < 34; i++) { checksum += gpg_packet[60+i]; }
  gpg_packet[94] = (unsigned char)(checksum >> 8) & 0xff;
  gpg_packet[95] = (unsigned char)(checksum) & 0xff;

  fwrite(&gpg_packet[1], sizeof(unsigned char), 95, stdout);

  return 0;
}

static void swap_bytes(unsigned char *buf, size_t len) {
  unsigned char *lo = buf;
  unsigned char *hi = buf + len - 1;
  unsigned char swap;

  while (lo < hi) {
    swap = *lo;
    *lo++ = *hi;
    *hi-- = swap;
  }
}

static char * hex_encode(const uint8_t *buf, size_t len) {
  char *ret = calloc((len * 2) + 1, 1);

  for (size_t i = 0; i < len; i++) {
    sprintf(ret + (i * 2), "%02X", buf[i]);
  }

  return ret;
}
