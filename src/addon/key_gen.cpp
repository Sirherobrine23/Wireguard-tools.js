// Base
#include <napi.h>
using namespace Napi;
// Wireguard embedded library
extern "C" {
  #include "wgEmbed/wireguard.h"
}

Napi::Value presharedKey(const Napi::CallbackInfo& info) {
  wg_key interfacePresharedKey;
  wg_generate_preshared_key(interfacePresharedKey);
  wg_key_b64_string pskString;
  wg_key_to_base64(pskString, interfacePresharedKey);
  return Napi::String::New(info.Env(), pskString);
}

Napi::Value privateKey(const Napi::CallbackInfo& info) {
  wg_key interfacePublicKey;
  wg_generate_private_key(interfacePublicKey);
  wg_key_b64_string privString;
  wg_key_to_base64(privString, interfacePublicKey);
  return Napi::String::New(info.Env(), privString);
}

Napi::Value publicKey(const Napi::CallbackInfo& info) {
  const Napi::String privKey = info[0].As<Napi::String>();
  if (privKey.IsEmpty()) return Napi::String::New(info.Env(), "Invalid private key");

  // base64 to wg_key
  wg_key interfacePrivateKey;
  wg_key_from_base64(interfacePrivateKey, privKey.Utf8Value().c_str());

  // Create public key
  wg_key interfacePublicKey;
  wg_generate_public_key(interfacePublicKey, interfacePrivateKey);

  // Convert to base64
  wg_key_b64_string pubString;
  wg_key_to_base64(pubString, interfacePublicKey);

  // Return public key
  return Napi::String::New(info.Env(), pubString);
}
