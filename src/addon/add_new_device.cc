#include <unistd.h>
#include <string.h>
#include <napi.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
extern "C" {
  #include "wgEmbed/wireguard.h"
}

Napi::Value addNewDevice(const Napi::CallbackInfo& info) {
  const Napi:: Object Config = info[0].As<Napi::Object>();
  if (Config.IsEmpty()) return Napi::String::New(info.Env(), "Settings are empty");
  const Napi::String interfaceName = Config["name"].As<Napi::String>();
  wg_device wgDevice = {};
  // Copy name to device struct.
  if (interfaceName.IsEmpty()) return Napi::String::New(info.Env(), "Interface name is empty");
  if (interfaceName.Utf8Value().length() > sizeof(wgDevice.name) >= interfaceName.Utf8Value().length()) return Napi::String::New(info.Env(), "Interface name is too long");
  strncpy(wgDevice.name, interfaceName.Utf8Value().c_str(), interfaceName.Utf8Value().length());

  // Add interface
  int res = wg_add_device(wgDevice.name);
  if (res == -17);
  else if (res < 0) return Napi::String::New(info.Env(), "Error adding device");

  // Set IP addressess
  if (Config["Address"].IsArray()) {
    // set interface up with ioctl
    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, wgDevice.name, sizeof(ifr.ifr_name));
    ifr.ifr_flags = IFF_UP|IFF_RUNNING|IFF_POINTOPOINT|IFF_NOARP;
    int fd;
    if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
      if ((fd = socket(PF_PACKET, SOCK_DGRAM, 0)) < 0) {
        if ((fd = socket(PF_INET6, SOCK_DGRAM, 0)) < 0) return Napi::String::New(info.Env(), "Unable to create socket");
      }
    }
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
      close(fd);
      return Napi::String::New(info.Env(), "Unable to set interface up");
    }
    close(fd);

    // set interface address
    Napi::Array Address = Config["Address"].As<Napi::Array>();
    for (int i = 0; i < Address.Length(); i++) {
      if (Address.Get(i).IsString()) {
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
        req.nlh.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL|ifr.ifr_flags;
        req.ifa.ifa_scope = RT_SCOPE_LINK;
        req.nlh.nlmsg_pid = getpid();
        req.ifa.ifa_index = if_nametoindex(wgDevice.name);
        if (req.ifa.ifa_index == 0) return Napi::String::New(info.Env(), "Unable to find interface");

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

        if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) return Napi::String::New(info.Env(), "Unable to create socket");
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
          close(fd);
          return Napi::String::New(info.Env(), "Unable to bind socket");
        }
        // send request
        if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0) {
          close(fd);
          return Napi::String::New(info.Env(), "Unable to send request");
        }
        close(fd);
      }
    }
  }

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

  // Add peers
  const Napi::Object Peers = Config["peers"].As<Napi::Object>();
  const Napi::Array Keys = Peers.GetPropertyNames();
  if (Keys.Length() > 0) {
    for (int i = 0; i < Keys.Length(); i++) {
      const Napi::Object peer = Peers.Get(Keys[i]).As<Napi::Object>();
      // Set peer publicKey
      wg_peer peerAdd = {
        flags: (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY,
      };
      wg_key_from_base64(peerAdd.public_key, Keys[i].As<Napi::String>().Utf8Value().c_str());

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
      if (peer["endpoint"].IsString()) {
        sockaddr endpoint;
        int ret, retries;
        char *begin, *end;
        char *Endpoint = strdup(peer["endpoint"].As<Napi::String>().Utf8Value().c_str());
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
            fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), peer["endpoint"].As<Napi::String>().Utf8Value().c_str());
            return Napi::String::New(info.Env(), "Unable to resolve endpoint");
          }
          fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), peer["endpoint"].As<Napi::String>().Utf8Value().c_str(), timeout / 1000000.0);
          usleep(timeout);
        }
        if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(sockaddr_in6))) {
          memcpy(&endpoint, resolved->ai_addr, resolved->ai_addrlen);
          memccpy(&peerAdd.endpoint.addr, &endpoint, 0, sizeof(peerAdd.endpoint.addr));
          if (resolved->ai_family == AF_INET) {
            peerAdd.endpoint.addr4.sin_addr.s_addr = ((sockaddr_in *)&endpoint)->sin_addr.s_addr;
            peerAdd.endpoint.addr4.sin_port = ((sockaddr_in *)&endpoint)->sin_port;
            peerAdd.endpoint.addr4.sin_family = AF_INET;
          } else {
            peerAdd.endpoint.addr6.sin6_addr = ((struct sockaddr_in6 *)&endpoint)->sin6_addr;
            peerAdd.endpoint.addr6.sin6_port = ((struct sockaddr_in6 *)&endpoint)->sin6_port;
            peerAdd.endpoint.addr6.sin6_family = AF_INET6;
          }
        } else {
          freeaddrinfo(resolved);
          free(Endpoint);
          return Napi::String::New(info.Env(), "Neither IPv4 nor IPv6 address found");
        }
        freeaddrinfo(resolved);
        free(Endpoint);
      }

      // Add peer to device
      wgDevice.first_peer = &peerAdd;
      if (wg_set_device(&wgDevice) < 0) return Napi::String::New(info.Env(), "Unable to add peer");
    }
  }
  return Napi::Number::New(info.Env(), 0);
}