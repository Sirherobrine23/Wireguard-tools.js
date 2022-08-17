// Base
#include <unistd.h>
#include <napi.h>
using namespace Napi;

// Networking
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

// Wireguard embedded library
extern "C" {
  #include "wgEmbed/wireguard.h"
}

auto setAddrAndUp(const char *devName, Napi::Array Address) {
  int rootFlags = IFF_UP|IFF_RUNNING|IFF_POINTOPOINT|IFF_NOARP;
  for (int i = 0; i < Address.Length(); i++) {
    const Napi::String ipaddr = Address.Get(i).As<Napi::String>();
    bool is_ipv6 = false;
    if (strchr(ipaddr.Utf8Value().c_str(), ':')) is_ipv6 = true;
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK | is_ipv6 ? RTMGRP_IPV6_IFADDR|RTMGRP_IPV6_ROUTE:RTMGRP_IPV4_IFADDR|RTMGRP_IPV4_ROUTE;
    addr.nl_pid = getpid();
    struct {
      struct nlmsghdr nlh;
      struct ifaddrmsg ifa;
      char buf[256];
    } req;
    memset(&req, 0, sizeof(req));
    rtattr *rta_addr = (rtattr *)req.buf;
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_NEWADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|rootFlags;
    req.ifa.ifa_scope = RT_SCOPE_LINK;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_index = if_nametoindex(devName);
    if (req.ifa.ifa_index == 0) return "Unable to find interface";

    req.ifa.ifa_family = is_ipv6 ? AF_INET6:AF_INET;
    req.ifa.ifa_prefixlen = req.ifa.ifa_family == AF_INET6 ? 128:32;
    rta_addr->rta_type = IFA_LOCAL;
    rta_addr->rta_len = RTA_LENGTH(16);
    inet_pton(req.ifa.ifa_family, ipaddr.Utf8Value().c_str(), RTA_DATA(rta_addr));

    // set broadcast address
    rtattr *rta_broadcast = (rtattr *)(((char *)rta_addr) + RTA_ALIGN(rta_addr->rta_len));
    rta_broadcast->rta_type = is_ipv6 ? IFA_ADDRESS:IFA_BROADCAST;
    rta_broadcast->rta_len = rta_addr->rta_len;
    inet_pton(req.ifa.ifa_family, ipaddr.Utf8Value().c_str(), RTA_DATA(rta_broadcast));

    // set destination address
    rtattr *rta_dstaddr = (rtattr *)(((char *)rta_broadcast) + RTA_ALIGN(rta_broadcast->rta_len));
    rta_dstaddr->rta_type = is_ipv6 ? IFA_ADDRESS:IFA_BROADCAST;
    rta_dstaddr->rta_len = rta_addr->rta_len;
    inet_pton(req.ifa.ifa_family, ipaddr.Utf8Value().c_str(), RTA_DATA(rta_dstaddr));

    // Set route to interface
    rtattr *rta_dst = (rtattr *)(((char *)rta_dstaddr) + RTA_ALIGN(rta_dstaddr->rta_len));
    rta_dst->rta_type = is_ipv6 ? IFA_ADDRESS:IFA_BROADCAST;
    rta_dst->rta_len = rta_addr->rta_len;
    inet_pton(req.ifa.ifa_family, ipaddr.Utf8Value().c_str(), RTA_DATA(rta_dst));

    int fd;
    if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) return "Unable to create socket";
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      close(fd);
      return "Unable to bind socket";
    }
    // send request
    if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
      close(fd);
      return "Unable to send request";
    }
    close(fd);
  }

  return "";
}

Napi::Number registerInterface(const CallbackInfo& info) {
  return Napi::Number::New(info.Env(), wg_add_device(info[0].As<Napi::String>().Utf8Value().c_str()));
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
    const char *error = setAddrAndUp(interfaceName.Utf8Value().c_str(), ipAddresses);
    if (error[0] != '\0') return Napi::String::New(info.Env(), error);
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

  // Peers Mount
  for (unsigned int peerIndex = 0; peerIndex < Keys.Length(); peerIndex++) {
    const Napi::Object peerConfig = Peers.Get(Keys[peerIndex]).As<Napi::Object>();
    const Napi::String peerPubKey = Keys[peerIndex].As<Napi::String>();
    wg_peer *peerStruct = new wg_peer({});
    // Set public key
    wg_key_from_base64(peerStruct->public_key, peerPubKey.Utf8Value().c_str());
    peerStruct->flags = (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY;

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
      sockaddr endpoint;
      int ret, retries;
      char *begin, *end;
      char *Endpoint = strdup(EndpointString.Utf8Value().c_str());
      if (Endpoint[0] == '[') {
        begin = &Endpoint[1];
        end = strchr(Endpoint, ']');
        if (!end) {
          free(Endpoint);
          return Napi::String::New(info.Env(), "Unable to find matching brace of endpoint");
        }
        *end++ = '\0';
        if (*end++ != ':' || !*end) {
          free(Endpoint);
          return Napi::String::New(info.Env(), "Unable to find port of endpoint");
        }
      } else {
        begin = Endpoint;
        end = strrchr(Endpoint, ':');
        if (!end || !*(end + 1)) {
          free(Endpoint);
          return Napi::String::New(info.Env(), "Unable to find port of endpoint");
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
          return Napi::String::New(info.Env(), "Unable to resolve endpoint");
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
        return Napi::String::New(info.Env(), "Neither IPv4 nor IPv6 address found");
      }
      freeaddrinfo(resolved);
      free(Endpoint);
    }

    // Set allowed IPs
    Napi::Array allowedIPs = peerConfig["allowedIPs"].As<Napi::Array>();
    wg_allowedip* Allowes[allowedIPs.Length()+1];
    if (allowedIPs.IsArray()) {
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