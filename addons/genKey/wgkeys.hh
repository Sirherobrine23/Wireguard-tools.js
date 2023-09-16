#ifndef _WGKEY_
#define _WGKEY_
#include <string>

const int WG_KEY_LENGTH = 32, B64_WG_KEY_LENGTH = ((WG_KEY_LENGTH + 2) / 3) * 4;
typedef unsigned char wg_key[WG_KEY_LENGTH];
typedef char wg_key_b64_string[B64_WG_KEY_LENGTH + 1];
typedef long long fe[16];

namespace wgKeys {
  /* Convert wg_key to std::string */
  std::string toString(const wg_key key);

  /* base64 to wg_key */
  void stringToKey(wg_key key, std::string keyBase64);

  // bool key_is_zero(wg_key key);

  /* Generate preshared key */
  void generatePreshared(wg_key key);

  /* Generate private key (based on generatePreshared) */
  void generatePrivate(wg_key private_key);

  /* Get public key from private key */
  void generatePublic(wg_key public_key, const wg_key private_key);
}

#endif