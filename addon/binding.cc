#define NAPI_DISABLE_CPP_EXCEPTIONS
#include <napi.h>
#include <uv.h>
#ifdef __cplusplus
extern "C" {
  #include "wgEmbed/wireguard.h"
}
#endif

/*
int wg_set_device(wg_device *dev);
int wg_get_device(wg_device **dev, const char *device_name);
int wg_add_device(const char *device_name); OK
int wg_del_device(const char *device_name); OK
char *wg_list_device_names(void); OK

void wg_key_to_base64(wg_key_b64_string base64, const wg_key key);
int wg_key_from_base64(wg_key key, const wg_key_b64_string base64);
bool wg_key_is_zero(const wg_key key);
*/

// get all device names
Napi::Object getDeviceNames(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Napi::Object obj = Napi::Object::New(env);
  char *device_names = wg_list_device_names();
  if (device_names) {
    char *name = device_names;
    int i = 0;
    while (name) {
      obj.Set(Napi::String::New(env, std::to_string(i).c_str()), Napi::String::New(env, name));
      name = strchr(name, '\n');
      if (name) {
        name++;
      }
      i++;
    }
    free(device_names);
  }
  return obj;
}

Napi::Object getPeers(const Napi::CallbackInfo& info) {
  char *device_names = wg_list_device_names();
  Napi::Object Devices = Napi::Object::New(info.Env());
  if (device_names) {
    char *name = device_names;
    int i = 0;
    while (name) {
      if (strcmp(name, info[0].As<Napi::String>().Utf8Value().c_str()) == 0) {
        wg_device *dev = NULL;
        if (wg_get_device(&dev, name) == 0) {
          Napi::Object PeerObj = Napi::Object::New(info.Env());
          struct wg_peer *peer;
          struct wg_allowedip *allowedip;
          for (peer = dev->first_peer; (peer); peer = peer->next_peer) {
            PeerObj.Set(Napi::String::New(info.Env(), "publicKey"), Napi::String::New(info.Env(), wg_key_to_base64(peer->public_key)));
            if (peer->preshared_key) PeerObj.Set(Napi::String::New(info.Env(), "presharedKey"), Napi::String::New(info.Env(), wg_key_to_base64(peer->preshared_key)));
            if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
              PeerObj.Set(Napi::String::New(info.Env(), "endpoint"), Napi::Array::New(info.Env(), 2));
              if (peer->endpoint.addr4) PeerObj.Get(Napi::String::New(info.Env(), "endpoint")).As<Napi::Array>().Set(0, Napi::String::New(info.Env(), peer->endpoint.addr4.sin_addr+":"+peer->endpoint.addr4.sin_port));
              if (peer->endpoint.addr6) PeerObj.Get(Napi::String::New(info.Env(), "endpoint")).As<Napi::Array>().Set(1, Napi::String::New(info.Env(), peer->endpoint.addr6.sin6_addr+":"+peer->endpoint.addr6.sin6_port));
            }
            PeerObj.Set(Napi::String::New(info.Env(), "allowedIPs"), Napi::Array::New(info.Env()));
            for (allowedip = peer->first_allowedip; (allowedip); allowedip = allowedip->next_allowedip) {
              PeerObj.Get(Napi::String::New(info.Env(), "allowedIPs")).As<Napi::Array>().Set(Napi::String::New(info.Env(), allowedip->ip6.__in6_u.__u6_addr32), Napi::String::New(info.Env(), allowedip->ip4.s_addr));
            }
            if (peer->last_handshake_time) PeerObj.Set(Napi::String::New(info.Env(), "lastHandshakeTime"), Napi::Date::New(info.Env(), peer->last_handshake_time));
            if (peer->rx_bytes || peer->tx_bytes) {
              Napi::Object TrafficObj = Napi::Object::New(info.Env());
              TrafficObj.Set(Napi::String::New(info.Env(), "rxBytes"), Napi::Number::New(info.Env(), peer->rx_bytes));
              TrafficObj.Set(Napi::String::New(info.Env(), "txBytes"), Napi::Number::New(info.Env(), peer->tx_bytes));
              PeerObj.Set(Napi::String::New(info.Env(), "traffic"), TrafficObj);
            }
            if (peer->persistent_keepalive_interval) PeerObj.Set(Napi::String::New(info.Env(), "persistentKeepaliveInterval"), Napi::Number::New(info.Env(), peer->persistent_keepalive_interval));
            Devices.Set(Napi::String::New(info.Env(), std::to_string(i).c_str()), PeerObj);
          }
        }
      }
      name = strchr(name, '\n');
      if (name) {
        name++;
      }
      i++;
    }
    free(device_names);
  }
  return Devices;
}

Napi::Number addDevice(const Napi::CallbackInfo& info) {
  const char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), wg_add_device(device_name));
};

Napi::Number delDevie(const Napi::CallbackInfo& info) {
  const char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), wg_del_device(device_name));
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("addDevice", Napi::Function::New(env, addDevice));
  exports.Set("delDevice", Napi::Function::New(env, delDevie));
  exports.Set("getDeviceNames", Napi::Function::New(env, getDeviceNames));
  exports.Set("getPeers", Napi::Function::New(env, getPeers));
  return exports;
}
NODE_API_MODULE(addon, Init)