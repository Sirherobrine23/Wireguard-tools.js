#define NAPI_DISABLE_CPP_EXCEPTIONS
#include <time.h>
#include <string>
#include <napi.h>

// Wireguard embedded library.
#ifdef __cplusplus
extern "C" {
  #include "wgEmbed/wireguard.h"
}
#endif

Napi::Object getPeers(const Napi::CallbackInfo& info) {
  char *device_names, *device_name;
  size_t len;
  device_names = wg_list_device_names();
  if (!device_names) {
    perror("Unable to get device names");
    exit(1);
  }

  Napi::Object DevicesObj = Napi::Object::New(info.Env());
  wg_for_each_device_name(device_names, device_name, len) {
    wg_device *device;
    wg_peer *peer;

    if (wg_get_device(&device, device_name) < 0) continue;
    Napi::Object DeviceObj = Napi::Object::New(info.Env());

    // Set device public key
    wg_key_b64_string interfacePublicKey; wg_key_to_base64(interfacePublicKey, device->public_key);
    DeviceObj.Set(Napi::String::New(info.Env(), "publicKey"), Napi::String::New(info.Env(), interfacePublicKey));

    // Set device private key
    wg_key_b64_string interfaceprivateKey; wg_key_to_base64(interfaceprivateKey, device->private_key);
    DeviceObj.Set(Napi::String::New(info.Env(), "privateKey"), Napi::String::New(info.Env(), interfaceprivateKey));

    // Peers
    Napi::Object PeerRoot = Napi::Object::New(info.Env());
    wg_for_each_peer(device, peer) {
      Napi::Object PeerObj = Napi::Object::New(info.Env());
      // if preshared set
      if (peer->preshared_key) {
        wg_key_b64_string presharedKey; wg_key_to_base64(presharedKey, peer->preshared_key);
        PeerObj.Set(Napi::String::New(info.Env(), "presharedKey"), Napi::String::New(info.Env(), presharedKey));
      }

      // Keep interval alive
      if (peer->persistent_keepalive_interval) PeerObj.Set(Napi::String::New(info.Env(), "keepInterval"), Napi::Number::New(info.Env(), peer->persistent_keepalive_interval));

      // Bytes sent and received
      if (peer->rx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "rxBytes"), Napi::Number::New(info.Env(), peer->rx_bytes));
      if (peer->tx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "txBytes"), Napi::Number::New(info.Env(), peer->tx_bytes));

      // Latest handshake
      if (peer->last_handshake_time.tv_sec) {
        time_t now = time(NULL);
        double lastHandshake = peer->last_handshake_time.tv_sec - now;
        PeerObj.Set(Napi::String::New(info.Env(), "lastHandshake"), Napi::Date::New(info.Env(), lastHandshake));
      }

      // Public key
      wg_key_b64_string peerPublicKey;
      wg_key_to_base64(peerPublicKey, peer->public_key);
      PeerRoot.Set(Napi::String::New(info.Env(), peerPublicKey), PeerObj);
    }
    DeviceObj.Set(Napi::String::New(info.Env(), "peers"), PeerRoot);
    DevicesObj.Set(Napi::String::New(info.Env(), device_name), DeviceObj);
    wg_free_device(device);
  }
  free(device_names);
  return DevicesObj;
}

Napi::Number addDevice(const Napi::CallbackInfo& info) {
  const char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), wg_add_device(device_name));
};

Napi::Number addNewDevice(const Napi::CallbackInfo& info) {
  char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  uint16_t portListen = info[1].As<Napi::Number>().Int32Value();
  wg_peer new_peer = {
    .flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS
  };
  wg_device new_device = {
    .name = device_name,
    .listen_port = portListen,
    // .flags = WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT,
    .first_peer = &new_peer,
		.last_peer = &new_peer
  };
  if (wg_add_device(new_device.name) < 0) {
    return Napi::Number::New(info.Env(), -1);
  }
  if (wg_set_device(&new_device) < 0) {
    return Napi::Number::New(info.Env(), -2);
  }
  return Napi::Number::New(info.Env(), 0);
}

Napi::Number delDevie(const Napi::CallbackInfo& info) {
  const char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), wg_del_device(device_name));
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("addDevice", Napi::Function::New(env, addDevice));
  exports.Set("delDevice", Napi::Function::New(env, delDevie));
  exports.Set("getPeers", Napi::Function::New(env, getPeers));
  exports.Set("addNewDevice", Napi::Function::New(env, addNewDevice));
  return exports;
}
NODE_API_MODULE(addon, Init)