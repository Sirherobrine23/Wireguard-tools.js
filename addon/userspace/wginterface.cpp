#include "wginterface.hh"
#include "userspace/wg-go.h"
#include "genKey/wgkeys.hh"
#include <cstring>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <vector>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

void IpManeger::SetInInterface(std::string interfaceName) {}
void IpManeger::GetInInterface(std::string interfaceName) {}

// Ignore if required to windows
std::string driveLoad(std::map<std::string, std::string> load) { return ""; }

std::string getWireguardVersion() {
  return std::string(wgVersion());
}

void WireguardDevices::getInterfaces() {
  size_t len; char *device_name, *devicesList = listInternalTuns();
  for (device_name = devicesList, len = 0; (len = strlen(device_name)); device_name += len + 1) this->push_back(std::string(device_name));
}

void WireguardDevices::deleteInterface(std::string wgName) {
  auto status = stopWg((char*)wgName.c_str());
  if (!!status.r1) throw std::string(status.r1);
}

bool char_is_digit(int c) {
	return (unsigned int)(('0' - 1 - c) & (c - ('9' + 1))) >> (sizeof(c) * 8 - 1);
}

void WireguardConfig::setWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Set wireguard name!");
  std::string userspaceConfig;

  if (this->privateKey.length() == Base64WgKeyLength) userspaceConfig = userspaceConfig.append("private_key=").append(wgKeys::toHex(this->privateKey)).append("\n");
  if (this->portListen >= 0) userspaceConfig = userspaceConfig.append("listen_port=").append(std::to_string(this->portListen)).append("\n");
  if (this->fwmark >= 0) userspaceConfig = userspaceConfig.append("fwmark=").append(std::to_string(this->fwmark)).append("\n");
  if (this->replacePeers) userspaceConfig = userspaceConfig.append("replace_peers=true\n");

  for (auto peer : this->Peers) {
    userspaceConfig = userspaceConfig.append("public_key=").append(wgKeys::toHex(peer.first)).append("\n");
    auto config = peer.second;
    if (config.removeMe) {
      userspaceConfig = userspaceConfig.append("remove=true\n");
      continue;
    }
    if (config.presharedKey.length() == Base64WgKeyLength) userspaceConfig = userspaceConfig.append("preshared_key=").append(wgKeys::toHex(config.presharedKey)).append("\n");
    if (config.keepInterval > 0) userspaceConfig = userspaceConfig.append("persistent_keepalive_interval=").append(std::to_string(config.keepInterval)).append("\n");
    if (config.endpoint.length() > 0) userspaceConfig = userspaceConfig.append("endpoint=").append(config.endpoint).append("\n");
    if (config.allowedIPs.size() > 0) {
      userspaceConfig = userspaceConfig.append("replace_allowed_ips=true\n");
      for (auto s : config.allowedIPs.getIpParsed()) userspaceConfig = userspaceConfig.append("allowed_ip=").append(s.Address).append("/").append(std::to_string(s.Mask)).append("\n");
    }
  }

  std::string err = setWg((char*)this->name.c_str(), (char*)userspaceConfig.append("\n").c_str());
  if (!err.empty()) throw err;
}

std::vector<std::string> splitLines(const std::string& str) {
  std::vector<std::string> result;
  std::stringstream ss(str);
  std::string line;
  // Loop until the end of the string
  while (std::getline(ss, line)) {
    if (!line.empty()) {
      result.push_back(line);
    }
  }
  return result;
}

void WireguardConfig::getWireguardConfig() {
  auto status = getWg((char*)this->name.c_str());
  if (strlen(status.r1) > 0) throw std::string(status.r1, strlen(status.r1));
  std::string wgConfig(status.r0, strlen(status.r0));
  std::string pubKey;
  int ret = 0;
  for (auto line : splitLines(wgConfig)) {
    std::string key(line.substr(0, line.find("="))), value(line.substr(line.find("=")+1));
    if (key == "private_key") {
      this->privateKey = wgKeys::HextoBase64(value);
    } else if (key == "listen_port") {
      this->portListen = (unsigned short)std::strtoul(value.c_str(), NULL, 0);
    } else if (key == "public_key") {
      // Insert to peer key
      pubKey = wgKeys::HextoBase64(value);
      this->Peers[pubKey] = Peer{};
    } else if (key == "preshared_key" && pubKey.length() > 0) {
      this->Peers[pubKey].presharedKey = wgKeys::HextoBase64(value);
    } else if (key == "allowed_ip" && pubKey.length() > 0) {
      this->Peers[pubKey].allowedIPs.push_back(value);
    } else if (key == "persistent_keepalive_interval" && pubKey.length() > 0) {
      this->Peers[pubKey].keepInterval = std::stoi(value);
    } else if (key == "last_handshake_time_sec" && pubKey.length() > 0) {
    } else if (key == "last_handshake_time_nsec" && pubKey.length() > 0) {
      this->Peers[pubKey].lastHandshake = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = std::strtoull(value.c_str(), &end, 10); if (*end || num > 0x7fffffffffffffffULL) break; num; });
    } else if (key == "rx_bytes" && pubKey.length() > 0) {
      this->Peers[pubKey].rxBytes = std::stoull(value);
    } else if (key == "tx_bytes" && pubKey.length() > 0) {
      this->Peers[pubKey].txBytes = std::stoull(value);
    } else if (key == "endpoint" && pubKey.length() > 0) {
        char *cvalue = strdup(value.c_str());
        char *begin, *end;
        struct addrinfo *resolved;
        struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP };
        if (!value.length()) break;
        if (value[0] == '[') {
          begin = &value[1];
          end = strchr(cvalue, ']');
          if (!end) break;
          *end++ = '\0';
          if (*end++ != ':' || !*end) break;
        } else {
          begin = cvalue;
          end = strrchr(cvalue, ':');
          if (!end || !*(end + 1)) break;
          *end++ = '\0';
        }
        if (getaddrinfo(begin, end, &hints, &resolved) != 0) {
          ret = ENETUNREACH;
          throw std::string("Failed to resolve endpoint");
        }
        if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6))) this->Peers[pubKey].endpoint = value;
        else {
          freeaddrinfo(resolved);
          break;
        }
        freeaddrinfo(resolved);
    } else if (key == "errno") {
      ret = -({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = std::strtoull(value.c_str(), &end, 10); if (*end || num > 0x7fffffffU) break; num; });
      break;
    } else if (key == "protocol_version") {
    }
  }
  if (ret < 0) throw std::string("Failed to get wireguard config");
}
