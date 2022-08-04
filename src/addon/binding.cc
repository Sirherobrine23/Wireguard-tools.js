#define NAPI_DISABLE_CPP_EXCEPTIONS
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <string>

// N-API
#include <napi.h>

// Wireguard embedded library.
extern "C" {
  #include "wgEmbed/wireguard.h"
}

// Stability: stable
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

    // Wireguard interface port listen
    if (device->listen_port) DeviceObj.Set(Napi::String::New(info.Env(), "portListen"), Napi::Number::New(info.Env(), device->listen_port));

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

      // Endoints
      if (peer->endpoint.addr.sa_family == AF_INET||peer->endpoint.addr.sa_family == AF_INET6) {
        const struct sockaddr *addr = &peer->endpoint.addr;
        char host[4096 + 1];
        char service[512 + 1];
        static char buf[sizeof(host) + sizeof(service) + 4];
        int ret;
        socklen_t addr_len = 0;

        memset(buf, 0, sizeof(buf));
        if (addr->sa_family == AF_INET)
          addr_len = sizeof(struct sockaddr_in);
        else if (addr->sa_family == AF_INET6)
          addr_len = sizeof(struct sockaddr_in6);

        ret = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST);
        if (ret) {
          strncpy(buf, gai_strerror(ret), sizeof(buf) - 1);
          buf[sizeof(buf) - 1] = '\0';
        } else snprintf(buf, sizeof(buf), (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
        PeerObj.Set(Napi::String::New(info.Env(), "endpoint"), Napi::String::New(info.Env(), buf));
      }

      // Allowed IPs
      Napi::Array AllowedIPs = Napi::Array::New(info.Env());
      wg_allowedip *allowedip;
      if (peer->first_allowedip) {
        wg_for_each_allowedip(peer, allowedip) {
          static char buf[INET6_ADDRSTRLEN + 1];
          memset(buf, 0, INET6_ADDRSTRLEN + 1);
          if (allowedip->family == AF_INET) inet_ntop(AF_INET, &allowedip->ip4, buf, INET6_ADDRSTRLEN);
          else if (allowedip->family == AF_INET6) inet_ntop(AF_INET6, &allowedip->ip6, buf, INET6_ADDRSTRLEN);
          AllowedIPs.Set(AllowedIPs.Length(), Napi::String::New(info.Env(), buf));
        }
        PeerObj.Set(Napi::String::New(info.Env(), "allowedIPs"), AllowedIPs);
      }

      // Bytes sent and received
      if (peer->rx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "rxBytes"), Napi::Number::New(info.Env(), peer->rx_bytes));
      if (peer->tx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "txBytes"), Napi::Number::New(info.Env(), peer->tx_bytes));

      // Latest handshake
      // sec: 1659573014
      // nsec: 334757073
      if (peer->last_handshake_time.tv_sec) PeerObj.Set(Napi::String::New(info.Env(), "lastHandshake"), Napi::Date::New(info.Env(), peer->last_handshake_time.tv_sec*1000));

      // Public key
      wg_key_b64_string peerPublicKey;
      wg_key_to_base64(peerPublicKey, peer->public_key);
      PeerRoot.Set(Napi::String::New(info.Env(), peerPublicKey), PeerObj);
    }
    DeviceObj.Set(Napi::String::New(info.Env(), "peers"), PeerRoot);
    DevicesObj.Set(Napi::String::New(info.Env(), (char *)device->name), DeviceObj);
    wg_free_device(device);
  }
  free(device_names);
  return DevicesObj;
}

Napi::Value addNewDevice(const Napi::CallbackInfo& info) {
  const Napi:: Object Config = info[0].As<Napi::Object>();
  if (Config.IsEmpty()) return Napi::Number::New(info.Env(), -255);
  if (Config["name"].IsEmpty()) return Napi::Number::New(info.Env(), -254);
  wg_device wgDevice = {};
  // Copy name to device struct.
  strncpy(wgDevice.name, Config["name"].As<Napi::String>().Utf8Value().c_str(), sizeof(info[0].As<Napi::String>().Utf8Value().c_str()));

  // Private key
  wg_key_from_base64(wgDevice.private_key, Config["privateKey"].As<Napi::String>().Utf8Value().c_str());
  wgDevice.flags = (wg_device_flags)WGDEVICE_HAS_PRIVATE_KEY;

  // public key
  if (Config["publicKey"].IsString()) {
    wg_key_from_base64(wgDevice.public_key, Config["publicKey"].As<Napi::String>().Utf8Value().c_str());
    wgDevice.flags = (wg_device_flags)(wgDevice.flags|WGDEVICE_HAS_PUBLIC_KEY);
  }

  if (Config["portListen"].IsNumber()) {
    if ((uint16_t)Config["portListen"].As<Napi::Number>().Int32Value() > 0 ) {
      wgDevice.flags = (wg_device_flags)(wgDevice.flags|WGDEVICE_HAS_LISTEN_PORT);
      wgDevice.listen_port = (uint16_t)Config["portListen"].As<Napi::Number>().Int32Value();
    } else fprintf(stderr, "Invalid listen port\n");
  }

  // Add interface
  int res = wg_add_device(wgDevice.name);
  if (res == -17);
  else if (res < 0) return Napi::Number::New(info.Env(), -1);

  // Add peers
  const Napi::Array Peers = Config["peers"].As<Napi::Array>();
  if (Peers.Length() > 0) {
    for (int i = 0; i < Peers.Length(); i++) {
      if (Peers[i].IsObject() == 0) continue;
      const Napi::Object peer = Peers[i].As<Napi::Object>();
      wg_peer peerAdd = {
        flags: (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY,
      };
      Napi::String Pubkey = peer["pubKey"].As<Napi::String>();
      wg_key_from_base64(peerAdd.public_key, Pubkey.Utf8Value().c_str());

      // Preshared key
      if (peer["presharedKey"].IsString()) {
        Napi::String PresharedKey = peer["presharedKey"].As<Napi::String>();
        wg_key_from_base64(peerAdd.preshared_key, PresharedKey.Utf8Value().c_str());
        peerAdd.flags = (wg_peer_flags)(peerAdd.flags|WGPEER_HAS_PRESHARED_KEY);
      }

      // Keep alive
      if (peer["keepInterval"].IsNumber()) {
        const uint16_t keepalive = (uint16_t)peer["keepInterval"].As<Napi::Number>().Int32Value();
        if (keepalive > 0) {
          peerAdd.persistent_keepalive_interval = keepalive;
          peerAdd.flags = (wg_peer_flags)(peerAdd.flags|WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL);
        }
      }

      // Allowed IPs
      Napi::Array allowedIPs = peer["allowedIPs"].As<Napi::Array>();
      wg_allowedip Allowes[allowedIPs.Length()];
      if (peer["allowedIPs"].IsArray()) {
        peerAdd.flags = (wg_peer_flags)(peerAdd.flags|WGPEER_REPLACE_ALLOWEDIPS);
        peerAdd.first_allowedip = NULL;
        peerAdd.last_allowedip = NULL;
        for (int a = 0; a<allowedIPs.Length(); a++) {
          const Napi::String Ip = allowedIPs.Get(a).As<Napi::String>();
          unsigned long cidr = 0;
          wg_allowedip newAllowedIP = {
            family: AF_UNSPEC,
          };
          if (strchr(Ip.Utf8Value().c_str(), ':')) {
            if (inet_pton(AF_INET6, Ip.Utf8Value().c_str(), &newAllowedIP.ip6) == 1) {
              newAllowedIP.family = AF_INET6;
              cidr = 128;
            }
          } else {
            if (inet_pton(AF_INET, Ip.Utf8Value().c_str(), &newAllowedIP.ip4) == 1) {
              newAllowedIP.family = AF_INET;
              cidr = 32;
            }
          }
          if (newAllowedIP.family == AF_UNSPEC || cidr == 0) continue;
          newAllowedIP.cidr = cidr;
          // Add to Peer struct
          Allowes[a] = newAllowedIP;
        }
        for (int a = 0; a < sizeof(Allowes)/sizeof(wg_allowedip); a++) {
          wg_allowedip *newAllowedIP = &Allowes[a];
          newAllowedIP->next_allowedip = peerAdd.first_allowedip;
          peerAdd.first_allowedip = newAllowedIP;
          if (peerAdd.last_allowedip == NULL) peerAdd.last_allowedip = newAllowedIP;
        }
      }

      // Endpoint
      // if (peer["endpoint"].IsString()) {
      //   const Napi::String Endpoint = peer["endpoint"].As<Napi::String>();
      // }

      // Add peer to device
      wgDevice.first_peer = &peerAdd;
      if (wg_set_device(&wgDevice) < 0) return Napi::Number::New(info.Env(), -2);
    }
  }
  return Napi::Number::New(info.Env(), 0);
}

Napi::Number delDevie(const Napi::CallbackInfo& info) {
  const char *device_name = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), wg_del_device(device_name));
};

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("addNewDevice", Napi::Function::New(env, addNewDevice));
  exports.Set("delDevice", Napi::Function::New(env, delDevie));
  exports.Set("getPeers", Napi::Function::New(env, getPeers));
  return exports;
}
NODE_API_MODULE(addon, Init)
