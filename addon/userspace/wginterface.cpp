#include "wginterface.hh"
#include "userspace/wg-go.h"
#include "userspace/ipc.cpp"
#include "genKey/wgkeys.hh"
#include <string>
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

// Ignore if required to windows
std::string driveLoad(std::map<std::string, std::string> load) {}

std::string getWireguardVersion() {
  return std::string(wgVersion());
}

void WireguardDevices::getInterfaces() {
  size_t len; char *device_name, *devicesList = listUapis();
  for (device_name = devicesList, len = 0; (len = strlen(device_name)); device_name += len + 1) this->push_back(std::string(device_name));
}

void WireguardDevices::deleteInterface(std::string wgName) {
  std::string deleteStatus = deleteTun((char*)wgName.c_str());
  if (!deleteStatus.empty()) throw deleteStatus;
}

bool char_is_digit(int c) {
	return (unsigned int)(('0' - 1 - c) & (c - ('9' + 1))) >> (sizeof(c) * 8 - 1);
}

void WireguardConfig::getWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Set wireguard name!");
  else if (!(WireguardDevices().exist(this->name))) throw std::string("Wireguard interface not exist");
  size_t line_buffer_len = 0, line_len;
	char *key = NULL, *value;
	int ret = -EPROTO;
	FILE *f = interfaceFile(WireguardDevices().findSock(this->name).c_str());
  if (!f) throw std::string("Failed to open interface file");
  fprintf(f, "get=1\n\n");
  fflush(f);
  std::string peerPubKey;
  bool peer = false;

  while (getline(&key, &line_buffer_len, f) > 0) {
    line_len = strlen(key);
		if (line_len == 1 && key[0] == '\n') return;
		value = strchr(key, '=');
		if (!value || line_len == 0 || key[line_len - 1] != '\n') break;
		*value++ = key[--line_len] = '\0';

		if (this->Peers.size() == 0 && !strcmp(key, "private_key")) {
			this->privateKey = wgKeys::HextoBase64(value);
			this->publicKey = wgKeys::generatePublic(this->privateKey);
		} else if (this->Peers.size() == 0 && !strcmp(key, "listen_port")) this->portListen = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0xffffU) break; num; });
    else if (this->Peers.size() == 0 && !strcmp(key, "fwmark")) this->fwmark = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0xffffffffU) break; num; });
    else if (!strcmp(key, "public_key")) {
			Peer new_peer;
      peerPubKey = wgKeys::HextoBase64(value);
      this->Peers[peerPubKey] = new_peer;
      peer = true;
		} else if (peer && !strcmp(key, "preshared_key")) {
			if (std::string(value) == "0000000000000000000000000000000000000000000000000000000000000000") continue;
      if (strlen(value) == HexWgKeyLength) this->Peers[peerPubKey].presharedKey = wgKeys::HextoBase64(value);
		} else if (peer && !strcmp(key, "persistent_keepalive_interval")) this->Peers[peerPubKey].keepInterval = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0xffffU) break; num; });
    else if (peer && !strcmp(key, "allowed_ip")) this->Peers[peerPubKey].allowedIPs.push_back(value);
    else if (peer && !strcmp(key, "last_handshake_time_sec")) {}
		else if (peer && !strcmp(key, "last_handshake_time_nsec")) this->Peers[peerPubKey].lastHandshake = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0x7fffffffffffffffULL) break; num; });
		else if (peer && !strcmp(key, "rx_bytes")) this->Peers[peerPubKey].rxBytes = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0xffffffffffffffffULL) break; num; });
		else if (peer && !strcmp(key, "tx_bytes")) this->Peers[peerPubKey].txBytes = ({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0xffffffffffffffffULL) break; num; });
		else if (!strcmp(key, "errno")) ret = -({ unsigned long long num; char *end; if (!char_is_digit(value[0])) break; num = strtoull(value, &end, 10); if (*end || num > 0x7fffffffU) break; num; });
    else if (peer && !strcmp(key, "endpoint")) {
			char *begin, *end;
			struct addrinfo *resolved;
			struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM, .ai_protocol = IPPROTO_UDP };
			if (!strlen(value)) break;
			if (value[0] == '[') {
				begin = &value[1];
				end = strchr(value, ']');
				if (!end) break;
				*end++ = '\0';
				if (*end++ != ':' || !*end) break;
			} else {
				begin = value;
				end = strrchr(value, ':');
				if (!end || !*(end + 1)) break;
				*end++ = '\0';
			}
			if (getaddrinfo(begin, end, &hints, &resolved) != 0) {
				ret = ENETUNREACH;
				throw std::string("Failed to resolve endpoint");
			}
			if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6))) this->Peers[peerPubKey].endpoint = value;
			else {
				freeaddrinfo(resolved);
				break;
			}
			freeaddrinfo(resolved);
		}
  }

  free(key);
  fclose(f);
  if (ret < 0) throw std::string("Failed to get wireguard config");
}

void WireguardConfig::setWireguardConfig() {
  if (this->name.length() == 0) throw std::string("Set wireguard name!");
  else if (!(WireguardDevices().exist(this->name))) {
    std::string PathError = createTun((char*)this->name.c_str());
    if (PathError.size() > 0) throw PathError;
  }

  FILE* f = interfaceFile(WireguardDevices().findSock(this->name));
  fprintf(f, "set=1\n");

  if (this->privateKey.length() == Base64WgKeyLength) fprintf(f, "private_key=%s\n", wgKeys::toHex(this->privateKey).c_str());
  if (this->portListen >= 0) fprintf(f, "listen_port=%u\n", this->portListen);
  if (this->fwmark >= 0) fprintf(f, "fwmark=%u\n", this->fwmark);
  if (this->replacePeers) fprintf(f, "replace_peers=true\n");

  for (auto peer : this->Peers) {
    fprintf(f, "public_key=%s\n", wgKeys::toHex(peer.first).c_str());
    if (peer.second.removeMe) {
      fprintf(f, "remove=true\n");
		  continue;
    }
    if (peer.second.presharedKey.length() == Base64WgKeyLength) fprintf(f, "preshared_key=%s\n", wgKeys::toHex(peer.second.presharedKey).c_str());
    if (peer.second.keepInterval) fprintf(f, "persistent_keepalive_interval=%u\n", peer.second.keepInterval);
    if (peer.second.endpoint.length() > 2) fprintf(f, "endpoint=%s\n", peer.second.endpoint.c_str());
    if (peer.second.allowedIPs.size() > 0) {
      fprintf(f, "replace_allowed_ips=true\n");
      for (auto s : peer.second.allowedIPs.getIpParsed()) fprintf(f, "allowed_ip=%s/%d\n", s.Address.c_str(), s.Mask);
    }
  }

  fprintf(f, "\n");
  fflush(f);

  int ret, set_errno = -EPROTO;
	size_t line_buffer_len = 0, line_len;
	char *key = NULL, *value;
  while (getline(&key, &line_buffer_len, f) > 0) {
    line_len = strlen(key);
    ret = set_errno;
    if (line_len == 1 && key[0] == '\n') break;
    value = strchr(key, '=');
    if (!value || line_len == 0 || key[line_len - 1] != '\n') break;
    *value++ = key[--line_len] = '\0';

    if (!strcmp(key, "errno")) {
      long long num;
      char *end;
      if (value[0] != '-' && !char_is_digit(value[0])) break;
      num = strtoll(value, &end, 10);
      if (*end || num > INT_MAX || num < INT_MIN) break;
      set_errno = num;
    }
  }

  free(key);
  fclose(f);
  ret = -(errno ? -errno : -EPROTO);
  if (ret < 0) throw std::string("Cannot set configuration, code: ").append(std::to_string(ret));
}

void IpManeger::SetInInterface(std::string interfaceName) {}
void IpManeger::GetInInterface(std::string interfaceName) {}