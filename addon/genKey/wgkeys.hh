#ifndef _WGKEY_
#define _WGKEY_
#include <string>

const int WG_KEY_LENGTH = 32, B64_WG_KEY_LENGTH = ((WG_KEY_LENGTH + 2) / 3) * 4;
const int wgKeyLength = 32, Base64WgKeyLength = ((wgKeyLength + 2) / 3) * 4, HexWgKeyLength = wgKeyLength * 2;

typedef unsigned char wg_key[wgKeyLength];
typedef char wg_key_b64_string[Base64WgKeyLength + 1];
typedef long long fe[16];

namespace wgKeys {
  // Convert wg_key to std::string in base64
  std::string toString(const wg_key key);

  // Convert base64 to hex key
  std::string toHex(const std::string keyBase64);

  // Convert hex to base64
  std::string HextoBase64(const std::string keyHex);

  // Convert base64 to wg_key
  void stringToKey(wg_key key, std::string keyBase64);

  // Generate preshared key
  void generatePreshared(wg_key key);

  // Generate private key
  void generatePrivate(wg_key private_key);

  // Get public key from private key
  void generatePublic(wg_key public_key, const wg_key private_key);

  std::string generatePublic(const std::string private_key);
}

#endif