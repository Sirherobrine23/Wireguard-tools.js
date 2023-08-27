#include <napi.h>
#include <unistd.h>
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
#include "wginterface.hh"
extern "C" {
  #include "linux/wireguard.h"
}

int maxName() {
  return IFNAMSIZ;
}

Napi::Value registerInterface(const Napi::Env env, const Napi::String interfaceName, const Napi::Boolean Add) {
  if (!(interfaceName.IsString() && (interfaceName.Utf8Value().length() > 0 && interfaceName.Utf8Value().length() < IFNAMSIZ))) {
    Napi::Error::New(env, "Set valid interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  int res = Add.Value() ? wg_add_device(interfaceName.Utf8Value().c_str()) : wg_del_device(interfaceName.Utf8Value().c_str());
  if (res < 0) {
    if (res == -ENOMEM) Napi::Error::New(env, "Out of memory").ThrowAsJavaScriptException();
    else if (res == -errno) Napi::Error::New(env, "Cannot add device").ThrowAsJavaScriptException();
    else {
      std::string err = "Error code: ";
      Napi::Error::New(env, err.append(std::to_string(res)).c_str()).ThrowAsJavaScriptException();
    }
  }
  return env.Undefined();
}

Napi::Value listDevicesSync(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  size_t len;
  char *device_name, *devicesList = wg_list_device_names();
  if (!devicesList) {
    Napi::Error::New(env, "Unable to get device names").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  const Napi::Array devicesArray = Napi::Array::New(env);
  for ((device_name) = (devicesList), (len) = 0; ((len) = strlen(device_name)); (device_name) += (len) + 1) devicesArray.Set(devicesArray.Length(), Napi::String::New(env, device_name));
  free(devicesList);
  return devicesArray;
}

Napi::Value addEndpoint(wg_peer *peerStruct, Napi::Env env, Napi::String EndpointString) {
  sockaddr endpoint;
  int ret, retries;
  char *begin, *end;
  char *Endpoint = strdup(EndpointString.Utf8Value().c_str());
  if (Endpoint[0] == '[') {
    begin = &Endpoint[1];
    end = strchr(Endpoint, ']');
    if (!end) {
      free(Endpoint);
      return Napi::Error::New(env, "Unable to find matching brace of endpoint").Value();
    }
    *end++ = '\0';
    if (*end++ != ':' || !*end) {
      free(Endpoint);
      return Napi::Error::New(env, "Unable to find port of endpoint").Value();
    }
  } else {
    begin = Endpoint;
    end = strrchr(Endpoint, ':');
    if (!end || !*(end + 1)) {
      free(Endpoint);
      return Napi::Error::New(env, "Unable to find port of endpoint").Value();
    }
    *end++ = '\0';
  }
  addrinfo *resolved;
  addrinfo hints = {
    ai_family: AF_UNSPEC,
    ai_socktype: SOCK_DGRAM,
    ai_protocol: IPPROTO_UDP
  };
  #define min(a, b) ((a) < (b) ? (a) : (b))
  for (unsigned int timeout = 1000000;; timeout = min(20000000, timeout * 6 / 5)) {
    ret = getaddrinfo(begin, end, &hints, &resolved);
    if (!ret) break;
    if (ret == EAI_NONAME || ret == EAI_FAIL ||
      #ifdef EAI_NODATA
        ret == EAI_NODATA ||
      #endif
        (retries >= 0 && !retries--)) {
      free(Endpoint);
      fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), EndpointString.Utf8Value().c_str());
      return Napi::Error::New(env, "Unable to resolve endpoint").Value();
    }
    fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), EndpointString.Utf8Value().c_str(), timeout / 1000000.0);
    usleep(timeout);
  }
  if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(sockaddr_in6))) {
    memcpy(&endpoint, resolved->ai_addr, resolved->ai_addrlen);
    memccpy(&peerStruct->endpoint.addr, &endpoint, 0, sizeof(peerStruct->endpoint.addr));
    if (resolved->ai_family == AF_INET) {
      peerStruct->endpoint.addr4.sin_addr.s_addr = ((sockaddr_in *)&endpoint)->sin_addr.s_addr;
      peerStruct->endpoint.addr4.sin_port = ((sockaddr_in *)&endpoint)->sin_port;
      peerStruct->endpoint.addr4.sin_family = AF_INET;
    } else {
      peerStruct->endpoint.addr6.sin6_addr = ((struct sockaddr_in6 *)&endpoint)->sin6_addr;
      peerStruct->endpoint.addr6.sin6_port = ((struct sockaddr_in6 *)&endpoint)->sin6_port;
      peerStruct->endpoint.addr6.sin6_family = AF_INET6;
    }
  } else {
    freeaddrinfo(resolved);
    free(Endpoint);
    return Napi::Error::New(env, "Neither IPv4 nor IPv6 address found").Value();
  }
  freeaddrinfo(resolved);
  free(Endpoint);
  return env.Undefined();
}

Napi::Value mountAllowedIps(wg_peer *peerStruct, Napi::Env env, const Napi::Array allowedIPs) {
  peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REPLACE_ALLOWEDIPS);
  for (unsigned int allowIndex = 0; allowIndex < allowedIPs.Length(); allowIndex++) {
    const Napi::String Ip = allowedIPs.Get(allowIndex).As<Napi::String>();
    unsigned long cidr = 0;
    wg_allowedip *newAllowedIP = new wg_allowedip({family: AF_UNSPEC});
    if (strchr(Ip.Utf8Value().c_str(), ':')) {
      if (inet_pton(AF_INET6, Ip.Utf8Value().c_str(), &newAllowedIP->ip6) == 1) {
        newAllowedIP->family = AF_INET6;
        cidr = 128;
      }
    } else {
      if (inet_pton(AF_INET, Ip.Utf8Value().c_str(), &newAllowedIP->ip4) == 1) {
        newAllowedIP->family = AF_INET;
        cidr = 32;
      }
    }
    if (newAllowedIP->family == AF_UNSPEC || cidr == 0) continue;
    newAllowedIP->cidr = cidr;

    // Add to Peer struct
    if (allowIndex > 0) newAllowedIP->next_allowedip = peerStruct->first_allowedip;
    peerStruct->first_allowedip = newAllowedIP;
  }
  return env.Undefined();
}

void setConfig::Execute() {
  SetError("Not implemented in Linux");
}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  const Napi::String interfaceName = info[0].As<Napi::String>();
  if (!(info[0].IsString())) {
    Napi::Error::New(env, "Require interface name!").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (interfaceName.Utf8Value().length() > IFNAMSIZ) {
    Napi::Error::New(env, "Interface name long!").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  size_t len;
  char *device_name, *devicesList = wg_list_device_names();
  if (!!devicesList) {
    auto createInterface = true;
    for ((device_name) = (devicesList), (len) = 0; ((len) = strlen(device_name)); (device_name) += (len) + 1) {
      if (device_name == interfaceName.Utf8Value().c_str()) {
        createInterface = false;
        break;
      }
    }
    free(devicesList);
    if (createInterface) {
      Napi::Value registerStatus = registerInterface(env, interfaceName, Napi::Boolean::New(env, true));
      if (!(registerStatus.IsUndefined())) return registerStatus;
    }
  }

  const Napi::Object deviceConfig = info[1].As<Napi::Object>();
  if (!(info[1].IsObject())) {
    Napi::Error::New(env, "Require interface config!").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  // Peers config
  const Napi::Object Peers = deviceConfig["peers"].As<Napi::Object>();
  if (!(Peers.IsObject())) {
    Napi::Error::New(env, "Require peers object!").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  const Napi::Array Keys = Peers.GetPropertyNames();

  // Set device struct
  wg_device *deviceStruct = new wg_device({});
  strncpy(deviceStruct->name, interfaceName.Utf8Value().c_str(), interfaceName.Utf8Value().length());

  // Set private key if set
  const Napi::String privateKey = deviceConfig["privateKey"].As<Napi::String>();
  if (!(privateKey.IsString())) {
    Napi::Error::New(env, "Private key is empty").ThrowAsJavaScriptException();
    return env.Undefined();
  } else wg_key_from_base64(deviceStruct->private_key, privateKey.Utf8Value().c_str());
  deviceStruct->flags = (wg_device_flags)WGDEVICE_HAS_PRIVATE_KEY;

  // Set public key if set
  const Napi::String publicKey = deviceConfig["publicKey"].As<Napi::String>();
  if (publicKey.IsString()) {
    wg_key_from_base64(deviceStruct->public_key, publicKey.Utf8Value().c_str());
    deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_HAS_PUBLIC_KEY);
  }

  // Port listenings
  const Napi::Number portListen = deviceConfig["portListen"].As<Napi::Number>();
  if (portListen.IsNumber() && (portListen.Int32Value() > 0 && 25565 < portListen.Int32Value())) {
    deviceStruct->listen_port = (uint16_t)portListen.Int32Value();
    deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_HAS_LISTEN_PORT);
  }

  // Replace Peers
  const Napi::Boolean replacePeers = deviceConfig["replacePeers"].As<Napi::Boolean>();
  if (replacePeers.IsBoolean() && replacePeers.Value()) deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_REPLACE_PEERS);

  // Peers Mount
  for (unsigned int peerIndex = 0; peerIndex < Keys.Length(); peerIndex++) {
    const Napi::Object peerConfig = Peers.Get(Keys[peerIndex]).As<Napi::Object>();
    const Napi::String peerPubKey = Keys[peerIndex].As<Napi::String>();
    wg_peer *peerStruct = new wg_peer({});
    // Set public key
    wg_key_from_base64(peerStruct->public_key, peerPubKey.Utf8Value().c_str());
    peerStruct->flags = (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY;

    // Remove Peer
    const Napi::Boolean removeMe = peerConfig["removeMe"].As<Napi::Boolean>();
    if (removeMe.IsBoolean() && removeMe.Value()) peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REMOVE_ME);
    else {
      // Set preshared key if present
      if (peerConfig["presharedKey"].IsString()) {
        Napi::String PresharedKey = peerConfig["presharedKey"].As<Napi::String>();
        wg_key_from_base64(peerStruct->preshared_key, PresharedKey.Utf8Value().c_str());
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_HAS_PRESHARED_KEY);
      }

      // Set Keepalive
      const Napi::Number keepInterval = peerConfig["keepInterval"].As<Napi::Number>();
      if (keepInterval.IsNumber() && keepInterval.Int32Value() > 0) {
        peerStruct->persistent_keepalive_interval = (uint16_t)keepInterval.Int32Value();
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL);
      }

      // Set endpoint
      const Napi::String EndpointString = peerConfig["endpoint"].As<Napi::String>();
      if (EndpointString.IsString()) {
        const Napi::Value Endpoint = addEndpoint(peerStruct, info.Env(), EndpointString);
        if (!(Endpoint.IsUndefined())) {
          Endpoint.As<Napi::Error>().ThrowAsJavaScriptException();
          return env.Undefined();
        }
      }

      // Set allowed IPs
      Napi::Array allowedIPs = peerConfig["allowedIPs"].As<Napi::Array>();
      if (allowedIPs.IsArray() && allowedIPs.Length() > 0) {
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REPLACE_ALLOWEDIPS);
        const Napi::Value AllowedIPs = mountAllowedIps(peerStruct, info.Env(), allowedIPs);
        if (!(AllowedIPs.IsUndefined())) {
          AllowedIPs.As<Napi::Error>().ThrowAsJavaScriptException();
          return env.Undefined();
        }
      }
    }

    // Add to Peer struct
    if (peerIndex > 0) peerStruct->next_peer = deviceStruct->first_peer;
    deviceStruct->first_peer = peerStruct;
  }

  // Deploy device
  int setDevice;
  if ((setDevice = wg_set_device(deviceStruct)) < 0) {
    if (setDevice == -ENODEV) Napi::Error::New(env, "No such device").ThrowAsJavaScriptException();
    else if (setDevice == -EINVAL) Napi::Error::New(env, "Invalid argument").ThrowAsJavaScriptException();
    else if (setDevice == -ENOSPC) Napi::Error::New(env, "No space left on device").ThrowAsJavaScriptException();
    else Napi::Error::New(env, "Unknown error").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  return env.Null();
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

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {
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