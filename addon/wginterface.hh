#ifndef __WIREGUARD_ADDON__
#define __WIREGUARD_ADDON__
#include "genKey/wgkeys.hh"
#include <string>
#include <vector>
#include <map>

extern const int wgKeyLength;
extern const int Base64WgKeyLength;

std::string getWireguardVersion();
std::string driveLoad(std::map<std::string, std::string> load);

class WireguardDevices : public std::vector<std::string> {
  public:
  ~WireguardDevices() { this->clear(); }

  /** Get all interfaces from kernel and insert in vector */
  void getInterfaces();

  /** Delete interface from kernel network */
  void deleteInterface(std::string wgName);

  /** Check if exists wireguard interface intterface */
  bool exist(std::string name) {
    this->getInterfaces();
    for (auto wgDev = this->begin(); wgDev != this->end(); ++wgDev)  {
      if (name == *wgDev) return true;
      else {
        std::string __nDev = std::string(wgDev->substr(wgDev->find_last_of("/")+1));
        if (__nDev.find(".sock") != std::string::npos) __nDev = __nDev.substr(0, __nDev.find(".sock"));
        if (__nDev == name) return true;
      }
    }

    return false;
  }

  /** Find sock */
  std::string findSock(std::string name) {
    this->getInterfaces();
    for (auto wgDev = this->begin(); wgDev != this->end(); ++wgDev)  {
      if (name == *wgDev) return *wgDev;
      else if (wgDev->find_last_of(".sock") != std::string::npos) {
        std::string __nDev = std::string(wgDev->substr(wgDev->find_last_of("/")+1));
        if (__nDev.find(".sock") != std::string::npos) __nDev = __nDev.substr(0, __nDev.find(".sock"));
        if (__nDev == name) return *wgDev;
      }
    }

    return std::string("");
  }
};

typedef struct {
  std::string Address, Subnet;
  int Mask, Proto;
} IpReference;

/** Maneger Interface IPs */
class IpManeger : public std::vector<std::string> {
  private:
  std::string getSubNet4(int Mask) {
    switch (Mask) {
      case 1:	return "128.0.0.0";
      case 2:	return "192.0.0.0";
      case 3:	return "224.0.0.0";
      case 4:	return "240.0.0.0";
      case 5:	return "248.0.0.0";
      case 6:	return "252.0.0.0";
      case 7:	return "254.0.0.0";
      case 8:	return "255.0.0.0";
      case 9:	return "255.128.0.0";
      case 10:	return "255.192.0.0";
      case 11:	return "255.224.0.0";
      case 12:	return "255.240.0.0";
      case 13:	return "255.248.0.0";
      case 14:	return "255.252.0.0";
      case 15:	return "255.254.0.0";
      case 16:	return "255.255.0.0";
      case 17:	return "255.255.128.0";
      case 18:	return "255.255.192.0";
      case 19:	return "255.255.224.0";
      case 20:	return "255.255.240.0";
      case 21:	return "255.255.248.0";
      case 22:	return "255.255.252.0";
      case 23:	return "255.255.254.0";
      case 24:	return "255.255.255.0";
      case 25:	return "255.255.255.128";
      case 26:	return "255.255.255.192";
      case 27:	return "255.255.255.224";
      case 28:	return "255.255.255.240";
      case 29:	return "255.255.255.248";
      case 30:	return "255.255.255.252";
      case 31:	return "255.255.255.254";

      default:
      case 32:	return "255.255.255.255";
    }
  }
  public:
  void SetInInterface(std::string interfaceName);
  void GetInInterface(std::string interfaceName);

  void addIPMask(std::string ip) {
    IpReference xTop;
    auto maskStart = ip.find("/");
    auto isIPv6 = ip.find(":") != std::string::npos;
    if (isIPv6) xTop.Mask = 128;
    else xTop.Mask = 32;
    if (maskStart == std::string::npos) xTop.Address = ip;
    else {
      xTop.Address = ip.substr(0, maskStart);
      xTop.Mask = std::stoi(ip.substr(maskStart+1).c_str());
      if (!isIPv6 && xTop.Mask > 32) throw std::string("Set valid mask to ipv4 address!");
    }
    xTop.Proto = isIPv6 ? 6 : 4;
    if (!isIPv6) xTop.Subnet = this->getSubNet4(xTop.Mask);
    this->push_back(xTop.Address.append("/").append(std::to_string(xTop.Mask)));
  }

  std::vector<IpReference> getIpParsed() {
    std::vector<IpReference> xTops;
    for (auto ipAddrr = this->begin(); ipAddrr != this->end(); ++ipAddrr) {
      IpReference nTop;
      auto maskStart = ipAddrr->find("/");
      nTop.Address = ipAddrr->substr(0, maskStart);
      nTop.Mask = std::stoi(ipAddrr->substr(maskStart+1).c_str());
      nTop.Proto = (nTop.Address.find(":") != std::string::npos) ? 6 : 4;
      if (nTop.Proto == 6) nTop.Subnet = this->getSubNet4(nTop.Mask);
      xTops.push_back(nTop);
    }
    return xTops;
  }
};

/**
 * peer class
 */
class Peer {
  public:
  Peer() {
    this->removeMe = false;
    this->keepInterval = 0;
    this->rxBytes = 0;
    this->txBytes = 0;
    this->lastHandshake = 0;
  }

  /** Remove specifies if the peer with this public key should be removed from a device's peer list. */
  bool removeMe;

  /** PresharedKey is an optional preshared key which may be used as an additional layer of security for peer communications. */
  std::string presharedKey;

  /** Endpoint is the most recent source address used for communication by this Peer. */
  std::string endpoint;

  /** PersistentKeepaliveInterval specifies how often an "empty" packet is sent to a peer to keep a connection alive.
   *
   * A value of 0 indicates that persistent keepalives are disabled.
	 */
  unsigned int keepInterval;

  /** Last peer handshake in milisseconds */
  unsigned long long lastHandshake;

  /** Peer data received (RX) and transferred (TX)  */
  unsigned long long rxBytes, txBytes;

  /** Peer ips allowed to recive data */
  IpManeger allowedIPs;
};

/**
* Set and Get Wireguard configs
*/
class WireguardConfig {
  public:

  WireguardConfig() {
    this->portListen = 0;
    this->fwmark = 0;
    this->replacePeers = false;
  }

  /** Wireguard interface name */
  std::string name;

  /** Wireguard interface private key */
  std::string privateKey;

  /** Wireguard interface public key */
  std::string publicKey;

  /** Wireguard port listening or listened */
  unsigned short portListen;

  /** FirewallMark specifies a device's firewall mark else set to 0, the firewall mark will be cleared */
  unsigned int fwmark;

  /** Replace Wireguard peers if wireguard interface exists */
  bool replacePeers;

  /** Wireguard interface IPs */
  IpManeger interfaceAddress;

  /** Wireguard peers */
  std::map<std::string, Peer> Peers;

  /** Set wireguard config in interface */
  void setWireguardConfig();

  /** Get configuration from wireguard */
  void getWireguardConfig();
};

#endif
