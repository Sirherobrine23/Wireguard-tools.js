// N-API
#include <napi.h>
using namespace Napi;
#include <time.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <cerrno>
#include <ifaddrs.h>
#include <string>
#include <sysexits.h>
#include <sys/types.h>
extern "C" {
  #include "linux/wireguard.h"
}

const char* getHostAddress(bool addPort, const sockaddr* addr) {
  char host[4096 + 1], service[512 + 1];
  static char buf[sizeof(host) + sizeof(service) + 4];
  memset(buf, 0, sizeof(buf));
  int ret;
  socklen_t addr_len = 0;
  if (addr->sa_family == AF_INET) addr_len = sizeof(struct sockaddr_in);
  else if (addr->sa_family == AF_INET6) addr_len = sizeof(struct sockaddr_in6);

  ret = getnameinfo(addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST);
  if (ret) {
    strncpy(buf, gai_strerror(ret), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
  } else {
    if (addPort) snprintf(buf, sizeof(buf), (addr->sa_family == AF_INET6 && strchr(host, ':')) ? "[%s]:%s" : "%s:%s", host, service);
    else snprintf(buf, sizeof(buf), "%s", host);
  }
  return buf;
}

Napi::Value parseWgDevice(const Napi::CallbackInfo& info, wg_device *device, const char *interfaceName) {
  wg_peer *peer;
  const Napi::Object DeviceObj = Napi::Object::New(info.Env());

  // Wireguard interface port listen
  if (device->listen_port) DeviceObj.Set(Napi::String::New(info.Env(), "portListen"), Napi::Number::New(info.Env(), device->listen_port));

  // Set device public key
  if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
    wg_key_b64_string interfacePublicKey;
    wg_key_to_base64(interfacePublicKey, device->public_key);
    DeviceObj.Set(Napi::String::New(info.Env(), "publicKey"), Napi::String::New(info.Env(), interfacePublicKey));
  }

  // Set device private key
  if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
    wg_key_b64_string interfaceprivateKey;
    wg_key_to_base64(interfaceprivateKey, device->private_key);
    DeviceObj.Set(Napi::String::New(info.Env(), "privateKey"), Napi::String::New(info.Env(), interfaceprivateKey));
  }

  // Set Address array and get interface ip addresses
  DeviceObj.Set(Napi::String::New(info.Env(), "Address"), Napi::Array::New(info.Env()));
  ifaddrs* ptr_ifaddrs = nullptr;
  if(getifaddrs(&ptr_ifaddrs) < 0) return Napi::String::New(info.Env(), "Error getting interface addresses");
  for (ifaddrs* ptr_entry = ptr_ifaddrs; ptr_entry != nullptr; ptr_entry = ptr_entry->ifa_next) {
    if (ptr_entry->ifa_addr == nullptr) continue;
    if (strcmp(ptr_entry->ifa_name, interfaceName) != 0) continue;
    if (ptr_entry->ifa_addr->sa_family == AF_INET) DeviceObj.Get(Napi::String::New(info.Env(), "Address")).As<Napi::Array>().Set(DeviceObj.Get(Napi::String::New(info.Env(), "Address")).As<Napi::Array>().Length(), Napi::String::New(info.Env(), getHostAddress(false, ptr_entry->ifa_addr)));
    else if (ptr_entry->ifa_addr->sa_family == AF_INET6) DeviceObj.Get(Napi::String::New(info.Env(), "Address")).As<Napi::Array>().Set(DeviceObj.Get(Napi::String::New(info.Env(), "Address")).As<Napi::Array>().Length(), Napi::String::New(info.Env(), getHostAddress(false, ptr_entry->ifa_addr)));
  }
  freeifaddrs(ptr_ifaddrs);

  // Peers
  Napi::Object PeerRoot = Napi::Object::New(info.Env());
  wg_for_each_peer(device, peer) {
    Napi::Object PeerObj = Napi::Object::New(info.Env());
    // if preshared set
    if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
      wg_key_b64_string presharedKey;
      wg_key_to_base64(presharedKey, peer->preshared_key);
      PeerObj.Set(Napi::String::New(info.Env(), "presharedKey"), Napi::String::New(info.Env(), presharedKey));
    }

    // Keep interval alive
    if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) PeerObj.Set(Napi::String::New(info.Env(), "keepInterval"), Napi::Number::New(info.Env(), peer->persistent_keepalive_interval));

    // Endoints
    if (peer->endpoint.addr.sa_family == AF_INET||peer->endpoint.addr.sa_family == AF_INET6) PeerObj.Set(Napi::String::New(info.Env(), "endpoint"), Napi::String::New(info.Env(), getHostAddress(true, &peer->endpoint.addr)));

    // Allowed IPs
    Napi::Array AllowedIPs = Napi::Array::New(info.Env());
    wg_allowedip *allowedip;
    if (peer->first_allowedip) {
      wg_for_each_allowedip(peer, allowedip) {
        static char buf[INET6_ADDRSTRLEN + 1];
        memset(buf, 0, INET6_ADDRSTRLEN + 1);
        if (allowedip->family == AF_INET) inet_ntop(AF_INET, &allowedip->ip4, buf, INET6_ADDRSTRLEN);
        else if (allowedip->family == AF_INET6) inet_ntop(AF_INET6, &allowedip->ip6, buf, INET6_ADDRSTRLEN);
        snprintf(buf + strlen(buf), INET6_ADDRSTRLEN - strlen(buf), "/%d", allowedip->cidr);
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