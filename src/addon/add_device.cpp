// Base
#include <unistd.h>
#include <napi.h>
using namespace Napi;

// Networking
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
extern "C" {
  #include "linux/wireguard.h"
}


/*
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63

[#] ip -4 address add 10.240.0.1/32 dev wg0
[#] ip -6 address add 2002:0AF0:0001::/128 dev wg0

[#] ip link set mtu 1420 up dev wg0

[#] ip -4 route add 192.168.15.88/32 dev wg0
[#] ip -6 route add 2002:c0a8:feb::/128 dev wg0
*/

namespace ipAddress {
  const char* sucessMessage = "Sucess";
  struct setAddress {
    struct nlmsghdr nlh;
    struct ifaddrmsg ifa;
    char buf[256];
  };
  bool setUp(const char *devName, int rootFlags = IFF_UP) {
    int fd;
    int res;
    ifreq ifr;
    ifr.ifr_flags = rootFlags;
    strncpy(ifr.ifr_name, devName, IFNAMSIZ);
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) return false;
    if ((res = ioctl(fd, SIOCSIFFLAGS, &ifr)) < 0) return false;
    close(fd);
    return true;
  }
  const char* setInterfaceAddress(const char *devName, const Napi::String ipaddr, int flags = 0) {
    int res = 0;
    bool is_ipv6 = false;
    if (strchr(ipaddr.Utf8Value().c_str(), ':')) is_ipv6 = true;

    setAddress req;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_index = if_nametoindex(devName);
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|flags;
    req.ifa.ifa_scope = RT_SCOPE_LINK;
    req.ifa.ifa_family = AF_INET;
    req.ifa.ifa_prefixlen = 32;
    if (is_ipv6) {
      req.ifa.ifa_family = AF_INET6;
      req.ifa.ifa_prefixlen = 128;
    }

    sockaddr_nl addr;
    addr.nl_pid = getpid();
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (is_ipv6) addr.nl_groups != RTMGRP_IPV6_IFADDR|RTMGRP_IPV6_ROUTE;
    else addr.nl_groups |= RTMGRP_IPV4_IFADDR|RTMGRP_IPV4_ROUTE;

    rtattr* rta_addr = (rtattr *)req.buf;
    rta_addr->rta_len = RTA_LENGTH(req.ifa.ifa_prefixlen);
    rta_addr->rta_type = IFA_LOCAL;
    inet_pton(req.ifa.ifa_family, ipaddr.Utf8Value().c_str(), RTA_DATA(rta_addr));

    if (req.ifa.ifa_index == 0) {
      res = -1;
      goto out;
    }
    int fd;
    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
      res = -2;
      goto out;
    }
    if (bind(fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
      res = -3;
      goto out;
    }

    // send request
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
      res = -4;
      goto out;
    }
  out:
    close(fd);
    if (res == 0) return sucessMessage;
    else if (res == -1) return "Unable to find interface";
    else if (res == -2) return "Unable to bind socket";
    else if (res == -3) return "Unable to send request";
    return "unknown error";
  }
  const char* config(const char *devName, Napi::Array Address) {
    int rootFlags = IFF_UP|IFF_RUNNING|IFF_POINTOPOINT|IFF_NOARP;
    // Set Address
    for (int i = 0; i < Address.Length(); i++) {
      const Napi::String ipaddr = Address.Get(i).As<Napi::String>();
      const char* err;
      if ((err = setInterfaceAddress(devName, ipaddr, IFF_UP)) != sucessMessage) return err;
    }
    if (!setUp(devName, rootFlags)) return "Cannot set up";
    return NULL;
  }
}


Napi::Number registerInterface(const CallbackInfo& info) {
  return Napi::Number::New(info.Env(), wg_add_device(info[0].As<Napi::String>().Utf8Value().c_str()));
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
      return Napi::String::New(env, "Unable to find matching brace of endpoint");
    }
    *end++ = '\0';
    if (*end++ != ':' || !*end) {
      free(Endpoint);
      return Napi::String::New(env, "Unable to find port of endpoint");
    }
  } else {
    begin = Endpoint;
    end = strrchr(Endpoint, ':');
    if (!end || !*(end + 1)) {
      free(Endpoint);
      return Napi::String::New(env, "Unable to find port of endpoint");
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
      return Napi::String::New(env, "Unable to resolve endpoint");
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
    return Napi::String::New(env, "Neither IPv4 nor IPv6 address found");
  }
  freeaddrinfo(resolved);
  free(Endpoint);
  return Napi::Number::New(env, 0);
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
  return Napi::Number::New(env, 0);
}

Napi::Value setupInterface(const CallbackInfo& info) {
  const Napi::String interfaceName = info[0].As<Napi::String>();
  // Check if interface already exists
  if (interfaceName.IsEmpty()) return Napi::String::New(info.Env(), "Interface name is empty");
  else if (!interfaceName.IsString()) return Napi::String::New(info.Env(), "Interface name is not a string");
  // Device config
  const Napi::Object deviceConfig = info[1].As<Napi::Object>();

  // Set ip addreses
  const Napi::Array ipAddresses = deviceConfig.Get("Address").As<Napi::Array>();
  if (ipAddresses.Length() > 0) {
    const char *error;
    if ((error = ipAddress::config(interfaceName.Utf8Value().c_str(), ipAddresses)) != NULL) return Napi::String::New(info.Env(), error);
  }

  // Peers config
  const Napi::Object Peers = deviceConfig["peers"].As<Napi::Object>();
  const Napi::Array Keys = Peers.GetPropertyNames();

  // Set device struct
  wg_device *deviceStruct = new wg_device({});
  // Set device name
  if (interfaceName.Utf8Value().length() > sizeof(deviceStruct->name) >= interfaceName.Utf8Value().length()) return Napi::String::New(info.Env(), "Interface name is too long");
  strncpy(deviceStruct->name, interfaceName.Utf8Value().c_str(), interfaceName.Utf8Value().length());

  // Set private key if set
  const Napi::String privateKey = deviceConfig["privateKey"].As<Napi::String>();
  if (privateKey.IsEmpty()) return Napi::String::New(info.Env(), "Private key is empty");
  wg_key_from_base64(deviceStruct->private_key, privateKey.Utf8Value().c_str());
  deviceStruct->flags = (wg_device_flags)WGDEVICE_HAS_PRIVATE_KEY;

  // Set public key if set
  const Napi::String publicKey = deviceConfig["publicKey"].As<Napi::String>();
  if (publicKey.IsString()) {
    wg_key_from_base64(deviceStruct->public_key, publicKey.Utf8Value().c_str());
    deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_HAS_PUBLIC_KEY);
  }

  // Port listenings
  const Napi::Number portListen = deviceConfig["portListen"].As<Napi::Number>();
  if (deviceConfig["portListen"].IsNumber() && portListen.Int32Value() > 0) {
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
        if (Endpoint.IsString()) return Endpoint;
      }

      // Set allowed IPs
      Napi::Array allowedIPs = peerConfig["allowedIPs"].As<Napi::Array>();
      if (allowedIPs.IsArray() && allowedIPs.Length() > 0) {
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REPLACE_ALLOWEDIPS);
        const Napi::Value AllowedIPs = mountAllowedIps(peerStruct, info.Env(), allowedIPs);
        if (AllowedIPs.IsString()) return AllowedIPs;
      }
    }

    // Add to Peer struct
    if (peerIndex > 0) peerStruct->next_peer = deviceStruct->first_peer;
    deviceStruct->first_peer = peerStruct;
  }

  // Deploy device
  int setDevice = 0;
  if ((setDevice = wg_set_device(deviceStruct)) < 0) {
    if (setDevice == -ENODEV) return Napi::String::New(info.Env(), "No such device");
    else if (setDevice == -EINVAL) return Napi::String::New(info.Env(), "Invalid argument");
    else if (setDevice == -ENOSPC) return Napi::String::New(info.Env(), "No space left on device");
    printf("Error code: %d\n", setDevice);
    return Napi::String::New(info.Env(), "Unknown error");
  }

  return Napi::Number::New(info.Env(), 0);
}
