#pragma once
#include <napi.h>
#include <map>
#include <vector>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

typedef uint8_t wg_key[32];

enum wgPeerFlags {
	WGPEER_REMOVE_ME = 1U << 0,
	WGPEER_REPLACE_ALLOWEDIPS = 1U << 1,
	WGPEER_HAS_PUBLIC_KEY = 1U << 2,
	WGPEER_HAS_PRESHARED_KEY = 1U << 3,
	WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4
};

union wg_endpoint {
	struct sockaddr addr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
};

class wgAllowedIP {
  public:
  uint8_t cidr;
  in6_addr ip6;
  in_addr ip4;
};

class wgPeer {
  public:
  wgPeerFlags flags;
  wg_key public_key;
	wg_key preshared_key;

  wg_endpoint endpoint;
  int64_t last_handshake_time_sec, last_handshake_time_nsec, rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

  std::vector<class wg_allowedip> allowedips;
};

class wgDevice {
  private:
    std::map<std::string, class wgPeer> wgPeers;
  public:
    char name[IFNAMSIZ];
};

/*
Esta função consegela o loop event

Pegar todas as interfaces do Wireguard e retorna em forma de String sendo tratado pelo Node.js quando retornado.
*/
Napi::Value listDevicesSync(const Napi::CallbackInfo& command);

/*
Esta função não congela o loop event criando um Napi::AsyncWorker

Pegar todas as interfaces do Wireguard e retorna em forma de String sendo tratado pelo Node.js quando retornado.
*/
Napi::Value listDevicesAsync(const Napi::CallbackInfo& command);

/*
Esta função consegela o loop event

Configure a interface do Wireguard
*/
Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info);

/*
Esta função não congela o loop event criando um Napi::AsyncWorker

Configure a interface do Wireguard
*/
Napi::Value setupInterfaceAsync(const Napi::CallbackInfo& info);

/* Esta função consegela o loop event */
Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info);

/* Esta função não congela o loop event criando um Napi::AsyncWorker */
Napi::Value parseWgDeviceAsync(const Napi::CallbackInfo& info);