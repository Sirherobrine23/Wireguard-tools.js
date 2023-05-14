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

Napi::Value listDevices(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  char *device_name, *devicesList;
  size_t len;
  devicesList = wg_list_device_names();
  if (!devicesList) {
    Napi::Error::New(env, "Unable to get device names").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  const Napi::Array devicesArray = Napi::Array::New(env);
  wg_for_each_device_name(devicesList, device_name, len) {
    wg_device *device;
    if (wg_get_device(&device, device_name) < 0) continue;
    devicesArray.Set(devicesArray.Length(), Napi::String::New(env, device_name));
    wg_free_device(device);
  }
  free(devicesList);
  return devicesArray;
}

Napi::Value parseWgDeviceV2(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  wg_device *device; wg_peer *peer;
  if (!(info[0].IsString())) {
    Napi::Error::New(env, "Set interface name!").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  char* device_name = strdup(info[0].ToString().Utf8Value().c_str());
  if (wg_get_device(&device, device_name) < 0) {
    Napi::Error::New(env, "Cannot get wireguard device!").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  const Napi::Object DeviceObj = Napi::Object::New(env);
  // Wireguard interface port listen
  if (device->listen_port) DeviceObj.Set("portListen", Napi::Number::New(env, device->listen_port));

  // Set device public key
  if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) {
    wg_key_b64_string interfacePublicKey;
    wg_key_to_base64(interfacePublicKey, device->public_key);
    DeviceObj.Set("publicKey", Napi::String::New(env, interfacePublicKey));
  }

  // Set device private key
  if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
    wg_key_b64_string interfaceprivateKey;
    wg_key_to_base64(interfaceprivateKey, device->private_key);
    DeviceObj.Set("privateKey", Napi::String::New(env, interfaceprivateKey));
  }

  // Set Address array and get interface ip addresses
  ifaddrs* ptr_ifaddrs = nullptr;
  if(getifaddrs(&ptr_ifaddrs) < 0) {Napi::Error::New(env, "Error getting interface addresses").ThrowAsJavaScriptException(); return env.Undefined();}
  const Napi::Array Addresseds = Napi::Array::New(env);
  for (ifaddrs* ptr_entry = ptr_ifaddrs; ptr_entry != nullptr; ptr_entry = ptr_entry->ifa_next) {
    if (ptr_entry->ifa_addr == nullptr) continue;
    else if (strcmp(ptr_entry->ifa_name, device_name) != 0) continue;
    else if (ptr_entry->ifa_addr->sa_family == AF_INET) Addresseds.Set(Addresseds.Length(), Napi::String::New(env, getHostAddress(false, ptr_entry->ifa_addr)));
    else if (ptr_entry->ifa_addr->sa_family == AF_INET6) Addresseds.Set(Addresseds.Length(), Napi::String::New(env, getHostAddress(false, ptr_entry->ifa_addr)));
  }
  freeifaddrs(ptr_ifaddrs);
  DeviceObj.Set("Address", Addresseds);

  // Peers
  Napi::Object PeerRoot = Napi::Object::New(env);
  wg_for_each_peer(device, peer) {
    Napi::Object PeerObj = Napi::Object::New(env);
    // if preshared set
    if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
      wg_key_b64_string presharedKey;
      wg_key_to_base64(presharedKey, peer->preshared_key);
      PeerObj.Set("presharedKey", Napi::String::New(env, presharedKey));
    }

    // Keep interval alive
    if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) PeerObj.Set("keepInterval", Napi::Number::New(env, peer->persistent_keepalive_interval));

    // Endoints
    if (peer->endpoint.addr.sa_family == AF_INET||peer->endpoint.addr.sa_family == AF_INET6) PeerObj.Set("endpoint", Napi::String::New(env, getHostAddress(true, &peer->endpoint.addr)));

    // Allowed IPs
    Napi::Array AllowedIPs = Napi::Array::New(env);
    wg_allowedip *allowedip;
    if (peer->first_allowedip) {
      wg_for_each_allowedip(peer, allowedip) {
        static char buf[INET6_ADDRSTRLEN + 1];
        memset(buf, 0, INET6_ADDRSTRLEN + 1);
        if (allowedip->family == AF_INET) inet_ntop(AF_INET, &allowedip->ip4, buf, INET6_ADDRSTRLEN);
        else if (allowedip->family == AF_INET6) inet_ntop(AF_INET6, &allowedip->ip6, buf, INET6_ADDRSTRLEN);
        snprintf(buf + strlen(buf), INET6_ADDRSTRLEN - strlen(buf), "/%d", allowedip->cidr);
        AllowedIPs.Set(AllowedIPs.Length(), Napi::String::New(env, buf));
      }
      PeerObj.Set("allowedIPs", AllowedIPs);
    }

    // Bytes sent and received
    if (peer->rx_bytes > 0) PeerObj.Set("rxBytes", Napi::Number::New(env, peer->rx_bytes));
    if (peer->tx_bytes > 0) PeerObj.Set("txBytes", Napi::Number::New(env, peer->tx_bytes));

    // Latest handshake
     if (peer->last_handshake_time.tv_sec) PeerObj.Set("lastHandshake", Napi::Date::New(env, peer->last_handshake_time.tv_sec*1000));

    // Public key
    wg_key_b64_string peerPublicKey;
    wg_key_to_base64(peerPublicKey, peer->public_key);
    PeerRoot.Set(peerPublicKey, PeerObj);
  }
  DeviceObj.Set("peers", PeerRoot);
  wg_free_device(device);
  return DeviceObj;
}