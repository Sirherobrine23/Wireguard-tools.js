// N-API
#include <napi.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>

// Wireguard embedded library.
extern "C" {
  #include "wgEmbed/wireguard.h"
}
using namespace Napi;

Napi::Value parseWgDevice(const Napi::CallbackInfo& info, wg_device *device) {
  wg_peer *peer;
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
  wg_free_device(device);
  return DeviceObj;
}