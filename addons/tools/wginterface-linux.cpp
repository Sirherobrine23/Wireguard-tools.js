#include <napi.h>
#include <iostream>
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
#include "linux/set_ip.cpp"
extern "C" {
  #include "linux/wireguard.h"
}

#define SETCONFIG 1
#define GETCONFIG 1
#define LISTDEV 1
#define DELIFACE 1

unsigned long maxName() {
  return IFNAMSIZ;
}

std::string versionDrive() {
  return "Kernel";
}

void listDevices::Execute() {
  char *device_name, *devicesList = wg_list_device_names();
  if (!devicesList) return SetError("Unable to get device names");
  size_t len;
  for ((device_name) = (devicesList), (len) = 0; ((len) = strlen(device_name)); (device_name) += (len) + 1) deviceNames[std::string(device_name)] = "kernel";
  free(devicesList);
}

int setInterface(std::string wgName) {
  size_t len = 0;
  char *device_name, *devicesList = wg_list_device_names();
  if (!!devicesList) {
    auto createInterface = true;
    for ((device_name) = (devicesList), (len) = 0; ((len) = strlen(device_name)); (device_name) += (len) + 1) {
      if (device_name == wgName.c_str()) {
        createInterface = false;
        break;
      }
    }
    free(devicesList);
    len = 0;
    if (createInterface) len = wg_add_device(wgName.c_str());
  }

  return len;
}

void deleteInterface::Execute() {
  size_t len = 0;
  char *device_name, *devicesList = wg_list_device_names();
  if (!!devicesList) {
    for ((device_name) = (devicesList), (len) = 0; ((len) = strlen(device_name)); (device_name) += (len) + 1) {
      if (device_name == wgName.c_str()) {
        if ((len = wg_add_device(wgName.c_str())) < 0) {
          std::string err = "Error code: ";
          err = err.append(std::to_string(len));
          if (len == -ENOMEM) err = "Out of memory";
          else if (len == -errno) err = ((std::string)"Cannot add device, code: ").append(std::to_string(len));
          SetError(err);
        }
        break;
      }
    }
    free(devicesList);
  }
}

void setConfig::Execute() {
  int res = setInterface(wgName);
  if (res < 0) {
    std::string err = "Error code: ";
    err = err.append(std::to_string(res));
    if (res == -ENOMEM) err = "Out of memory";
    else if (res == -errno) err = ((std::string)"Cannot add device, code: ").append(std::to_string(res));
    SetError(err);
    return;
  }

  // Set device struct
  auto deviceStruct = new wg_device({});
  strncpy(deviceStruct->name, wgName.c_str(), wgName.length());

  // Set private key
  wg_key_from_base64(deviceStruct->private_key, privateKey.c_str());
  deviceStruct->flags = (wg_device_flags)WGDEVICE_HAS_PRIVATE_KEY;

  // Set public key
  if (publicKey.length() > 0) {
    wg_key_from_base64(deviceStruct->public_key, publicKey.c_str());
    deviceStruct->flags = (wg_device_flags)WGDEVICE_HAS_PUBLIC_KEY;
  }

  // Port listenings
  if (portListen > 0 && 25565 < portListen) {
    deviceStruct->listen_port = portListen;
    deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_HAS_LISTEN_PORT);
  }

  // Linux firewall mark
  if (fwmark >= 0) {
    deviceStruct->fwmark = fwmark;
    deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_HAS_FWMARK);
  }

  // Replace Peers
  if (replacePeers) deviceStruct->flags = (wg_device_flags)(deviceStruct->flags|WGDEVICE_REPLACE_PEERS);

  unsigned int peerIndex = 0;
  for (auto it = peersVector.begin(); it != peersVector.end(); ++it) {
    const std::string peerPubKey = it->first;
    auto peerConfig = it->second;
    peerIndex++;

    wg_peer *peerStruct = new wg_peer({});
    // Set public key
    wg_key_from_base64(peerStruct->public_key, peerPubKey.c_str());
    peerStruct->flags = (wg_peer_flags)WGPEER_HAS_PUBLIC_KEY;

    // Remove Peer
    if (peerConfig.removeMe) peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REMOVE_ME);
    else {
      // Set preshared key if present
      if (peerConfig.presharedKey.length() > 0) {
        wg_key_from_base64(peerStruct->preshared_key, peerConfig.presharedKey.c_str());
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_HAS_PRESHARED_KEY);
      }

      // Set Keepalive
      if (peerConfig.keepInterval > 0) {
        peerStruct->persistent_keepalive_interval = peerConfig.keepInterval;
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL);
      }

      // Set endpoint
      if (peerConfig.endpoint.length() > 0) {
        sockaddr endpoint;
        int ret, retries;
        char *begin, *end;
        char *Endpoint = strdup(peerConfig.endpoint.c_str());
        if (Endpoint[0] == '[') {
          begin = &Endpoint[1];
          end = strchr(Endpoint, ']');
          if (!end) {
            free(Endpoint);
            SetError("Unable to find matching brace of endpoint");
            return;
          }
          *end++ = '\0';
          if (*end++ != ':' || !*end) {
            free(Endpoint);
            SetError("Unable to find port of endpoint");
            return;
          }
        } else {
          begin = Endpoint;
          end = strrchr(Endpoint, ':');
          if (!end || !*(end + 1)) {
            free(Endpoint);
            SetError("Unable to find port of endpoint");
            return;
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
            fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), peerConfig.endpoint.c_str());
            SetError("Unable to resolve endpoint");
            return;
          }
          fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), peerConfig.endpoint.c_str(), timeout / 1000000.0);
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
          SetError("Neither IPv4 nor IPv6 address found");
          return;
        }
        freeaddrinfo(resolved);
        free(Endpoint);
      }

      // Set allowed IPs
      if (peerConfig.allowedIPs.size() > 0) {
        peerStruct->flags = (wg_peer_flags)(peerStruct->flags|WGPEER_REPLACE_ALLOWEDIPS);
        for (unsigned int allowIndex = 0; allowIndex < peerConfig.allowedIPs.size(); allowIndex++) {
          auto ip = peerConfig.allowedIPs[allowIndex];
          unsigned long cidr = 0;
          if (ip.find("/") != std::string::npos) {
            cidr = std::stoi(ip.substr(ip.find("/")+1));
            ip = ip.substr(0, ip.find("/"));
          }
          wg_allowedip *newAllowedIP = new wg_allowedip({family: AF_UNSPEC});
          if (strchr(ip.c_str(), ':')) {
            if (inet_pton(AF_INET6, ip.c_str(), &newAllowedIP->ip6) == 1) {
              newAllowedIP->family = AF_INET6;
              if (cidr == 0) cidr = 128;
            }
          } else {
            if (inet_pton(AF_INET, ip.c_str(), &newAllowedIP->ip4) == 1) {
              newAllowedIP->family = AF_INET;
              if (cidr == 0) cidr = 32;
            }
          }
          if (newAllowedIP->family == AF_UNSPEC || cidr <= 0) continue;
          newAllowedIP->cidr = cidr;
          if (allowIndex > 0) newAllowedIP->next_allowedip = peerStruct->first_allowedip;
          peerStruct->first_allowedip = newAllowedIP;
        }
      }
    }

    // Add to Peer struct
    if (peerIndex > 0) peerStruct->next_peer = deviceStruct->first_peer;
    deviceStruct->first_peer = peerStruct;
  }

  // Set interface config
  if ((res = wg_set_device(deviceStruct)) < 0) {
    std::string err = "Set wireguard config Error code: ";
    err = err.append(std::to_string(res));
    if (res == -ENODEV) err = "No such device";
    else if (res == -EINVAL) err = "Invalid argument";
    else if (res == -ENOSPC) err = "No space left on device";
    SetError(err);
  }

  if (res >= 0) {
    auto res = setIps(wgName, Address);
    if (res.length() > 0) SetError(res);
  }
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

std::string keyTo64(const uint8_t *key) {
  wg_key_b64_string strKey;
  wg_key_to_base64(strKey, key);
  return strKey;
}

void getConfig::Execute() {
  int res; wg_device *device;
  if ((res = wg_get_device(&device, strdup(wgName.c_str()))) < 0) {
    std::string err = "Cannot get wireguard device, Error code ";
    err = err.append(std::to_string(res));
    SetError(err);
    return;
  }

  if (device->flags & WGDEVICE_HAS_PRIVATE_KEY) privateKey = keyTo64(device->private_key);
  if (device->flags & WGDEVICE_HAS_PUBLIC_KEY) publicKey = keyTo64(device->public_key);
  if (device->listen_port > 0) portListen = device->listen_port;

  // Set Address array and get interface ip addresses
  ifaddrs* ptr_ifaddrs = nullptr;
  if(getifaddrs(&ptr_ifaddrs) > 0) {
    for (ifaddrs* ptr_entry = ptr_ifaddrs; ptr_entry != nullptr; ptr_entry = ptr_entry->ifa_next) {
      if (ptr_entry->ifa_addr == nullptr) continue;
      else if (strcmp(ptr_entry->ifa_name, wgName.c_str()) != 0) continue;
      else if (ptr_entry->ifa_addr->sa_family == AF_INET) Address.push_back(getHostAddress(false, ptr_entry->ifa_addr));
      else if (ptr_entry->ifa_addr->sa_family == AF_INET6) Address.push_back(getHostAddress(false, ptr_entry->ifa_addr));
    }
    freeifaddrs(ptr_ifaddrs);
  }

  wg_peer *peer;
  for ((peer) = (device)->first_peer; (peer); (peer) = (peer)->next_peer) {
    auto PeerConfig = Peer();
    if (peer->flags & WGPEER_HAS_PRESHARED_KEY) PeerConfig.presharedKey = keyTo64(peer->preshared_key);
    if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL && peer->persistent_keepalive_interval > 0) PeerConfig.keepInterval = peer->persistent_keepalive_interval;
    if (peer->endpoint.addr.sa_family == AF_INET||peer->endpoint.addr.sa_family == AF_INET6) PeerConfig.endpoint = getHostAddress(true, &peer->endpoint.addr);
    if (peer->last_handshake_time.tv_sec > 0) PeerConfig.last_handshake = peer->last_handshake_time.tv_sec*1000;
    if (peer->rx_bytes > 0) PeerConfig.rxBytes = peer->rx_bytes;
    if (peer->tx_bytes > 0) PeerConfig.txBytes = peer->tx_bytes;
    if (peer->first_allowedip) {
      wg_allowedip *allowedip;
      for ((allowedip) = (peer)->first_allowedip; (allowedip); (allowedip) = (allowedip)->next_allowedip) {
        static char buf[INET6_ADDRSTRLEN + 1];
        memset(buf, 0, INET6_ADDRSTRLEN + 1);
        if (allowedip->family == AF_INET) inet_ntop(AF_INET, &allowedip->ip4, buf, INET6_ADDRSTRLEN);
        else if (allowedip->family == AF_INET6) inet_ntop(AF_INET6, &allowedip->ip6, buf, INET6_ADDRSTRLEN);
        snprintf(buf + strlen(buf), INET6_ADDRSTRLEN - strlen(buf), "/%d", allowedip->cidr);
        PeerConfig.allowedIPs.push_back(buf);
      }
    }

    peersVector[keyTo64(peer->public_key)] = PeerConfig;
  }
}