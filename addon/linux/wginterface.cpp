#include "wginterface.hh"
#include "genKey/wgkeys.hh"
extern "C" {
#include "wireguard.h"
}
#include <string>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <filesystem>
#include <fstream>

std::string getWireguardVersion() {
  #ifdef WIREGUARD_VERSION
  return std::string(WIREGUARD_VERSION);
  #endif

  std::string version = "Unknown";
  
  // /sys/module/wireguard/version - for kernel module
  if (std::filesystem::exists("/sys/module/wireguard/version")) {
    std::ifstream file("/sys/module/wireguard/version");
    file >> version;
    file.close();
  }

  return version;
}

std::string driveLoad(std::map<std::string, std::string> load) {}

void WireguardDevices::getInterfaces() {
  size_t len; char *device_name, *devicesList = wg_list_device_names();

  if (!devicesList) throw std::string("Unable to get device names");

  // Clear list
  this->clear();

  // Set new devices
  for (device_name = devicesList, len = 0; (len = strlen(device_name)); device_name += len + 1) this->push_back(std::string(device_name));

  // Free memory
  free(devicesList);
}

void WireguardDevices::deleteInterface(std::string wgName) {
  // Check if exist, if not skip
  if (this->exist(wgName)) {
    int status = wg_del_device(wgName.c_str());
    if (status < 0) throw std::string("Cannot delete interface, code: ").append(std::to_string(status));
  }
}

std::string HostAdresses(bool addPort, const sockaddr* addr) {
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
  return std::string(buf);
};

void WireguardConfig::getWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Set wireguard name!");
  else if (this->name.length() > IFNAMSIZ) throw std::string("Wireguard interface name is long, max name length is ").append(std::to_string(IFNAMSIZ));
  else if (!(WireguardDevices().exist(this->name))) throw std::string("Wireguard interface not exist");
  int status; wg_device *devConfig; wg_peer *peer;
  if ((status = wg_get_device(&devConfig, this->name.c_str())) < 0) throw std::string("It was not possible to get the Wireguard interface settings, code: ").append(std::to_string(status));
  if (devConfig->flags & WGDEVICE_HAS_PRIVATE_KEY) this->privateKey = wgKeys::toString(devConfig->private_key);
  if (devConfig->flags & WGDEVICE_HAS_PUBLIC_KEY) this->publicKey = wgKeys::toString(devConfig->public_key);
  if (!!devConfig->listen_port && devConfig->listen_port > 0) this->portListen = devConfig->listen_port;
  this->interfaceAddress.GetInInterface(this->name);

  for ((peer) = (devConfig)->first_peer; (peer); (peer) = (peer)->next_peer) {
    auto PeerConfig = Peer();
    if (peer->flags & WGPEER_HAS_PRESHARED_KEY) PeerConfig.presharedKey = wgKeys::toString(peer->preshared_key);
    if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) PeerConfig.keepInterval = peer->persistent_keepalive_interval;
    if (peer->endpoint.addr.sa_family == AF_INET||peer->endpoint.addr.sa_family == AF_INET6) PeerConfig.endpoint = HostAdresses(true, &peer->endpoint.addr);

    PeerConfig.lastHandshake = peer->last_handshake_time.tv_sec*1000;
    PeerConfig.rxBytes = peer->rx_bytes;
    PeerConfig.txBytes = peer->tx_bytes;

    wg_allowedip *allowedip;
    for ((allowedip) = (peer)->first_allowedip; (allowedip); (allowedip) = (allowedip)->next_allowedip) {
      static char buf[INET6_ADDRSTRLEN + 1];
      memset(buf, 0, INET6_ADDRSTRLEN + 1);
      if (allowedip->family == AF_INET) inet_ntop(AF_INET, &allowedip->ip4, buf, INET6_ADDRSTRLEN);
      else if (allowedip->family == AF_INET6) inet_ntop(AF_INET6, &allowedip->ip6, buf, INET6_ADDRSTRLEN);
      PeerConfig.allowedIPs.push_back(std::string(buf).append("/").append(std::to_string(allowedip->cidr)));
    }
    this->Peers[wgKeys::toString(peer->public_key)] = PeerConfig;
  }
}

void WireguardConfig::setWireguardConfig() {
  int status;
  if (this->name.length() > IFNAMSIZ) throw std::string("Wireguard interface name is long, max name length is ").append(std::to_string(IFNAMSIZ));
  else if (!(WireguardDevices().exist(this->name)) && (status = wg_add_device(this->name.c_str())) < 0) throw std::string("Unable to create Wireguard interface, code: ").append(std::to_string(status));
  if (this->privateKey.length() != Base64WgKeyLength) throw std::string("Set Wireguard interface private key!");

  auto wgConfig = new wg_device({});
  if (!wgConfig) throw std::string("Cannot alloc memory to set interface configuration!");
  strncpy(wgConfig->name, this->name.c_str(), this->name.length());

  wgConfig->flags = wg_device_flags::WGDEVICE_HAS_PRIVATE_KEY;
  wgKeys::stringToKey(wgConfig->private_key, this->privateKey);

  if (this->replacePeers) wgConfig->flags = (wg_device_flags)(wgConfig->flags|wg_device_flags::WGDEVICE_REPLACE_PEERS);

  if (this->publicKey.length() == Base64WgKeyLength) {
    wgConfig->flags = (wg_device_flags)(wgConfig->flags|wg_device_flags::WGDEVICE_HAS_PUBLIC_KEY);
    wgKeys::stringToKey(wgConfig->public_key, this->publicKey);
  }

  if (this->portListen >= 0) {
    wgConfig->flags = (wg_device_flags)(wgConfig->flags|wg_device_flags::WGDEVICE_HAS_LISTEN_PORT);
    wgConfig->listen_port = this->portListen;
  }

  if (this->fwmark >= 0) {
    wgConfig->flags = (wg_device_flags)(wgConfig->flags|wg_device_flags::WGDEVICE_HAS_FWMARK);
    wgConfig->fwmark = this->fwmark;
  }

  for (auto &PeerConfig : this->Peers) {
    auto peer = new wg_peer({});
    peer->flags = wg_peer_flags::WGPEER_HAS_PUBLIC_KEY;
    wgKeys::stringToKey(peer->public_key, PeerConfig.first);
    if (PeerConfig.second.removeMe) peer->flags = (wg_peer_flags)(peer->flags|wg_peer_flags::WGPEER_REMOVE_ME);
    else {
      if (PeerConfig.second.presharedKey.length() == Base64WgKeyLength) {
        peer->flags = (wg_peer_flags)(peer->flags|wg_peer_flags::WGPEER_HAS_PRESHARED_KEY);
        wgKeys::stringToKey(peer->preshared_key, PeerConfig.second.presharedKey);
      }

      if (PeerConfig.second.keepInterval > 0) {
        peer->flags = (wg_peer_flags)(peer->flags|wg_peer_flags::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL);
        peer->persistent_keepalive_interval = PeerConfig.second.keepInterval;
      }

      if (PeerConfig.second.endpoint.length() > 0) {
        sockaddr endpoint; int ret, retries;
        char *begin, *end, *Endpoint = strdup(PeerConfig.second.endpoint.c_str());
        if (Endpoint[0] == '[') {
          begin = &Endpoint[1];
          end = strchr(Endpoint, ']');
          if (!end) {
            for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
            delete wgConfig;
            free(Endpoint);
            throw std::string("Unable to find matching brace of endpoint");
            return;
          }
          *end++ = '\0';
          if (*end++ != ':' || !*end) {
            for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
            delete wgConfig;
            free(Endpoint);
            throw std::string("Unable to find port of endpoint");
            return;
          }
        } else {
          begin = Endpoint;
          end = strrchr(Endpoint, ':');
          if (!end || !*(end + 1)) {
            for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
            delete wgConfig;
            free(Endpoint);
            throw std::string("Unable to find port of endpoint");
          }
          *end++ = '\0';
        }
        addrinfo *resolved, hints = { ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM, ai_protocol: IPPROTO_UDP };
        for (unsigned int timeout = 1000000;; timeout = ((20000000) < (timeout * 6 / 5) ? (20000000) : (timeout * 6 / 5))) {
          ret = getaddrinfo(begin, end, &hints, &resolved);
          if (!ret) break;
          if (ret == EAI_NONAME || ret == EAI_FAIL ||
            #ifdef EAI_NODATA
              ret == EAI_NODATA ||
            #endif
          (retries >= 0 && !retries--)) {
            for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
            delete wgConfig;
            free(Endpoint);
            fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), PeerConfig.second.endpoint.c_str());
            throw std::string("Unable to resolve endpoint");
            return;
          }
          fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), PeerConfig.second.endpoint.c_str(), timeout / 1000000.0);
          usleep(timeout);
        }
        if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(sockaddr_in6))) {
          memcpy(&endpoint, resolved->ai_addr, resolved->ai_addrlen);
          memccpy(&peer->endpoint.addr, &endpoint, 0, sizeof(peer->endpoint.addr));
          if (resolved->ai_family == AF_INET) {
            peer->endpoint.addr4.sin_addr.s_addr = ((sockaddr_in *)&endpoint)->sin_addr.s_addr;
            peer->endpoint.addr4.sin_port = ((sockaddr_in *)&endpoint)->sin_port;
            peer->endpoint.addr4.sin_family = AF_INET;
          } else {
            peer->endpoint.addr6.sin6_addr = ((struct sockaddr_in6 *)&endpoint)->sin6_addr;
            peer->endpoint.addr6.sin6_port = ((struct sockaddr_in6 *)&endpoint)->sin6_port;
            peer->endpoint.addr6.sin6_family = AF_INET6;
          }
        } else {
          freeaddrinfo(resolved);
          for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
          delete wgConfig;
          free(Endpoint);
          throw std::string("Neither IPv4 nor IPv6 address found");
        }

        freeaddrinfo(resolved);
        // Free memory
        for ((peer) = (wgConfig)->first_peer; (peer); (peer) = (peer)->next_peer) { delete peer; }
        delete wgConfig;
        free(Endpoint);
      }

      for (const auto Ip : PeerConfig.second.allowedIPs.getIpParsed()) {
        if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS) peer->flags = (wg_peer_flags)(peer->flags|WGPEER_REPLACE_ALLOWEDIPS);
        auto newAllowedIP = new wg_allowedip({});
        newAllowedIP->cidr = Ip.Mask;
        if (Ip.Proto == 6 && inet_pton(AF_INET6, Ip.Address.c_str(), &newAllowedIP->ip6) == 1) newAllowedIP->family = AF_INET6;
        else if (Ip.Proto == 4 && inet_pton(AF_INET, Ip.Address.c_str(), &newAllowedIP->ip4) == 1) newAllowedIP->family = AF_INET;
        else {
          delete newAllowedIP;
          continue;
        }

        if (peer->first_allowedip) newAllowedIP->next_allowedip = peer->first_allowedip;
        peer->first_allowedip = newAllowedIP;
      }
    }

    if (wgConfig->first_peer) peer->next_peer = wgConfig->first_peer;
    wgConfig->first_peer = peer;
  }

  // Set config
  status = wg_set_device(wgConfig);

  // Free memory
  for (wg_peer* peer = wgConfig->first_peer; peer; peer = peer->next_peer) {
    for (wg_allowedip *newAllowedIP = peer->first_allowedip; newAllowedIP; newAllowedIP = newAllowedIP->next_allowedip) delete newAllowedIP;
    delete peer;
  }
  delete wgConfig;

  // Return status to tool
  if (status < 0) throw std::string("Unable to configure settings, code: ").append(std::to_string(status));
  else {
    this->interfaceAddress.SetInInterface(this->name);
  }
}

void IpManeger::GetInInterface(std::string interfaceName) {
  ifaddrs* ptr_ifaddrs = nullptr;
  if(getifaddrs(&ptr_ifaddrs) >= 0) {
    for (ifaddrs* ptr_entry = ptr_ifaddrs; ptr_entry != nullptr; ptr_entry = ptr_entry->ifa_next) {
      if (ptr_entry->ifa_addr == nullptr) continue;
      else if (strcmp(ptr_entry->ifa_name, interfaceName.c_str()) != 0) continue;
      else if (ptr_entry->ifa_addr->sa_family == AF_INET) this->addIPMask(HostAdresses(false, ptr_entry->ifa_addr));
      else if (ptr_entry->ifa_addr->sa_family == AF_INET6) this->addIPMask(HostAdresses(false, ptr_entry->ifa_addr));
    }
    freeifaddrs(ptr_ifaddrs);
  }
}

struct rtnl_handle {
  int fd;
  struct sockaddr_nl local;
  struct sockaddr_nl peer;
  __u32 seq;
  __u32 dump;
};

typedef struct {
  __u8 family;
  __u8 bytelen;
  __s16 bitlen;
  __u32 flags;
  __u32 data[8];
} inet_prefix;

// This function is to open the netlink socket as the name suggests.
void netlink_open(struct rtnl_handle* rth) {
  int addr_len;
  memset(rth, 0, sizeof(rth));

  // Creating the netlink socket of family NETLINK_ROUTE

  rth->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (rth->fd < 0) throw std::string("cannot open netlink socket");
  memset(&rth->local, 0, sizeof(rth->local));
  rth->local.nl_family = AF_NETLINK;
  rth->local.nl_groups = 0;

  // Binding the netlink socket
  if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) throw std::string("cannot bind netlink socket");

  addr_len = sizeof(rth->local);
  if (getsockname(rth->fd, (struct sockaddr*)&rth->local, (socklen_t*) &addr_len) < 0) throw std::string("cannot getsockname");
  if (addr_len != sizeof(rth->local)) throw std::string("wrong address lenght").append(std::to_string(addr_len));
  if (rth->local.nl_family != AF_NETLINK) throw std::string("wrong address family").append(std::to_string(rth->local.nl_family));

  rth->seq = time(NULL);
}

// This function does the actual reading and writing to the netlink socket
int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n, pid_t peer, unsigned groups, struct nlmsghdr *answer) {
  int status;
  struct nlmsghdr *h;
  struct sockaddr_nl nladdr;
  // Forming the iovector with the netlink packet.
  struct iovec iov = { (void*)n, n->nlmsg_len };
  char buf[8192];
  // Forming the message to be sent.
  struct msghdr msg = { (void*)&nladdr, sizeof(nladdr), &iov, 1, NULL, 0, 0 };
  // Filling up the details of the netlink socket to be contacted in the
  // kernel.
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_pid = peer;
  nladdr.nl_groups = groups;
  n->nlmsg_seq = ++rtnl->seq;
  if (answer == NULL) n->nlmsg_flags |= NLM_F_ACK;
  // Actual sending of the message, status contains success/failure
  return sendmsg(rtnl->fd, &msg, 0);
  // if (status < 0) return -1;
}

// This is the utility function for adding the parameters to the packet.
int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen) {
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen)
    return -1;
  rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
  return 0;
}

void IpManeger::SetInInterface(std::string interfaceName) {
  if (this->size() == 0) return;
  if (!(WireguardDevices().exist(interfaceName))) throw std::string("Wireguard interface not exists!");
  int status;
  unsigned int ifa_index;
  wg_device *devConfig;

  if ((status = wg_get_device(&devConfig, interfaceName.c_str())) < 0) throw std::string("It was not possible to get the Wireguard interface settings, code: ").append(std::to_string(status));

  ifa_index = devConfig->ifindex;
  free(devConfig);

  for (const auto ip : this->getIpParsed()) {
    struct rtnl_handle * rth;
    rth = (rtnl_handle*)malloc(sizeof(rtnl_handle));
    netlink_open(rth);
    int err;
    inet_prefix lcl;

    // structure of the netlink packet.
    struct {
      struct nlmsghdr n;
      struct ifaddrmsg ifa;
      char buf[1024];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.n.nlmsg_type = RTM_NEWADDR;
    req.n.nlmsg_flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST;

    req.ifa.ifa_family = ip.Proto == 4 ? AF_INET : AF_INET6;
    req.ifa.ifa_prefixlen = ip.Mask;
    req.ifa.ifa_index = ifa_index ; // get the loopback index
    req.ifa.ifa_scope = 0;

    memset(&lcl, 0, sizeof(lcl));
    lcl.family = req.ifa.ifa_family;
    lcl.bytelen = (req.ifa.ifa_family == AF_INET) ? 4 : 16;
    lcl.bitlen = (req.ifa.ifa_family == AF_INET) ? 32 : 128;

    if (inet_pton(req.ifa.ifa_family, ip.Address.c_str(), &lcl.data) <= 0) throw std::string("Invalid IP address: ").append(ip.Address);
    if (req.ifa.ifa_family == AF_UNSPEC) req.ifa.ifa_family = lcl.family;

    addattr_l(&req.n, sizeof(req), IFA_LOCAL, &lcl.data, lcl.bytelen);
    if ((err = rtnl_talk(rth, &req.n, 0, 0, NULL)) < 0) throw std::string("Cannot set interface IP, code: ").append(std::to_string(err));
  }

  // Get INET socket
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) throw std::string("Error creating socket to set interface flags");

  struct ifreq ifr;
  strcpy(ifr.ifr_name, interfaceName.c_str());

  // Set interface flags
  ifr.ifr_flags = IFF_POINTOPOINT | IFF_NOARP | IFF_UP | IFF_RUNNING;
  if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
    close(sockfd);
    throw std::string("Error setting interface flags");
  }

  close(sockfd);
}