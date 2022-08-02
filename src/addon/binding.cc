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
        } else
          snprintf(buf, sizeof(buf), (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
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
          AllowedIPs.Set(AllowedIPs.Length()+1, Napi::String::New(info.Env(), buf));
        }
        PeerObj.Set(Napi::String::New(info.Env(), "allowedIPs"), AllowedIPs);
      }

      // Bytes sent and received
      if (peer->rx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "rxBytes"), Napi::Number::New(info.Env(), peer->rx_bytes));
      if (peer->tx_bytes) PeerObj.Set(Napi::String::New(info.Env(), "txBytes"), Napi::Number::New(info.Env(), peer->tx_bytes));

      // Latest handshake
      if (peer->last_handshake_time.tv_sec) {
        // time_t now = time(NULL);
        double lastHandshake = peer->last_handshake_time.tv_sec * 1000;
        PeerObj.Set(Napi::String::New(info.Env(), "lastHandshake"), Napi::Date::New(info.Env(), lastHandshake));
      }

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

Napi::Number addNewDevice(const Napi::CallbackInfo& info) {
  wg_device wgDevice = {
    flags: (wg_device_flags)WGDEVICE_HAS_LISTEN_PORT,
    listen_port: (uint16_t)info[1].As<Napi::Number>().Int32Value(),
  };
  // Copy name to device struct.
  strncpy(wgDevice.name, info[0].As<Napi::String>().Utf8Value().c_str(), sizeof(info[0].As<Napi::String>().Utf8Value().c_str()));
  wg_key_from_base64(wgDevice.private_key, info[2].As<Napi::String>().Utf8Value().c_str());
  wgDevice.flags = (wg_device_flags)(wgDevice.flags|WGDEVICE_HAS_PRIVATE_KEY);

  // Add peers
  int peerNumber = info.Length()-3;
  if (peerNumber > 0) {
    for (int i = 0; i < peerNumber; i++) {
      const Napi::Object peer = info[i+3].As<Napi::Object>();
      wg_peer new_peer = {
        flags: (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY,
      };
      if (!peer["pubKey"].As<Napi::String>().Utf8Value().c_str()) return Napi::Number::New(info.Env(), -3);
      wg_key_from_base64(new_peer.public_key, peer["pubKey"].As<Napi::String>().Utf8Value().c_str());
      // Preshared key
      if (!!peer["presharedKey"].As<Napi::String>().Utf8Value().c_str()) {
        wg_key_from_base64(new_peer.preshared_key, peer["presharedKey"].As<Napi::String>().Utf8Value().c_str());
        new_peer.flags = (wg_peer_flags)(new_peer.flags|WGPEER_HAS_PRESHARED_KEY);
      }

      const uint16_t keepalive = (uint16_t)peer["keepalive"].As<Napi::Number>().Int32Value();
      if (keepalive > 0) {
        new_peer.persistent_keepalive_interval = keepalive;
        new_peer.flags = (wg_peer_flags)(new_peer.flags|WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL);
      }

      // Allowed IPs
      Napi::Array allowedIPs = peer["allowedIPs"].As<Napi::Array>();
      if (allowedIPs.Length() > 0) {
        new_peer.flags = (wg_peer_flags)(new_peer.flags|WGPEER_REPLACE_ALLOWEDIPS);
        for (int a = 0; a<allowedIPs.Length(); a++) {
          const Napi::String allowedIP = allowedIPs.Get(a).As<Napi::String>();
          // Create allowed IP struct
          wg_allowedip newAllowedIP = {};
          newAllowedIP.family = AF_UNSPEC;
          if (strchr(allowedIP.Utf8Value().c_str(), ':')) {
            if (inet_pton(AF_INET6, allowedIP.Utf8Value().c_str(), &newAllowedIP.ip6) == 1) newAllowedIP.family = AF_INET6;
          } else {
            if (inet_pton(AF_INET, allowedIP.Utf8Value().c_str(), &newAllowedIP.ip4) == 1) newAllowedIP.family = AF_INET;
          }
          if (newAllowedIP.family == AF_UNSPEC) {
            fprintf(stderr, "Unable to parse IP address: `%s'\n", allowedIP.Utf8Value().c_str());
            continue;
          }

          // Add cidr
          unsigned long cidr;
          if (newAllowedIP.family == AF_INET) cidr = 32;
          else if (newAllowedIP.family == AF_INET6) cidr = 128;
          newAllowedIP.cidr = cidr;

          // Add to Peer struct
          if (!new_peer.first_allowedip) new_peer.first_allowedip = &newAllowedIP;
          else {
            if (new_peer.last_allowedip) newAllowedIP.next_allowedip = new_peer.last_allowedip;
            new_peer.last_allowedip = &newAllowedIP;
          }
        }
      }

      // Next peer
      if (!wgDevice.first_peer) wgDevice.first_peer = &new_peer;
      else {
        if (!wgDevice.last_peer) wgDevice.last_peer = &new_peer;
        else new_peer.next_peer = wgDevice.last_peer;
        wgDevice.last_peer = &new_peer;
      }
    }
  }

  if (wg_add_device(wgDevice.name) < 0) return Napi::Number::New(info.Env(), -1);
  if (wg_set_device(&wgDevice) < 0) return Napi::Number::New(info.Env(), -2);
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
