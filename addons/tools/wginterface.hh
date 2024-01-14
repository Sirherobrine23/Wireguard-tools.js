#pragma once
#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <wgkeys.hh>

// Get wireguard max name length
unsigned long maxName();

// Get wireguard version
std::string versionDrive();

// On start module call this function
std::string startAddon(const Napi::Env env);

class deleteInterface : public Napi::AsyncWorker {
  private:
    std::string wgName;
  public:
  deleteInterface(const Napi::Env env, std::string name): AsyncWorker(env), deletePromise{env}, wgName{name} {}
  ~deleteInterface() {}
  const Napi::Promise::Deferred deletePromise;

  void OnError(const Napi::Error &e) override {
    Napi::HandleScope scope(Env());
    deletePromise.Reject(e.Value());
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    deletePromise.Resolve(Env().Undefined());
  };

  // Set platform Execute script
  void Execute() override;
};

class listInfo {
  public:
  std::string tunType, pathSock;
};

class listDevices : public Napi::AsyncWorker {
  private:
    std::map<std::string, listInfo> deviceNames;
  public:
  ~listDevices() {}
  listDevices(const Napi::Env env) : AsyncWorker(env), listDevicesPromise{env} {}
  const Napi::Promise::Deferred listDevicesPromise;

  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    listDevicesPromise.Reject(e.Value());
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const auto deviceArray = Napi::Array::New(env);
    for (auto it : deviceNames) {
      auto name = it.first; auto infoSrc = it.second;
      auto info = Napi::Object::New(env);
      info.Set("name", name);
      info.Set("from", infoSrc.tunType);
      if (infoSrc.pathSock.size() > 0) info.Set("path", infoSrc.pathSock);
      deviceArray.Set(deviceArray.Length(), info);
    }
    listDevicesPromise.Resolve(deviceArray);
  };
  void Execute() override;
};

class Peer {
  public:
  // Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
  bool removeMe;

  // PresharedKey is an optional preshared key which may be used as an
	// additional layer of security for peer communications.
  std::string presharedKey;

  // Endpoint is the most recent source address used for communication by
	// this Peer.
  std::string endpoint;

  // AllowedIPs specifies which IPv4 and IPv6 addresses this peer is allowed
	// to communicate on.
	//
	// 0.0.0.0/0 indicates that all IPv4 addresses are allowed, and ::/0
	// indicates that all IPv6 addresses are allowed.
  std::vector<std::string> allowedIPs;

  // PersistentKeepaliveInterval specifies how often an "empty" packet is sent
	// to a peer to keep a connection alive.
	//
	// A value of 0 indicates that persistent keepalives are disabled.
  unsigned int keepInterval = 0;

  // LastHandshakeTime indicates the most recent time a handshake was performed
	// with this peer.
	//
	// A zero-value time.Time indicates that no handshake has taken place with
	// this peer.
  long long last_handshake = 0;

  // rxBytes indicates the number of bytes received from this peer.
  unsigned long long rxBytes = 0;

  // txBytes indicates the number of bytes transmitted to this peer.
  unsigned long long txBytes = 0;

  // ProtocolVersion specifies which version of the WireGuard protocol is used
	// for this Peer.
	//
	// A value of 0 indicates that the most recent protocol version will be used.
	int ProtocolVersion = 0;
};

/*
Configure uma interface do Wireguard.
*/
class setConfig : public Napi::AsyncWorker {
  private:
    // Wireguard interface name (required)
    std::string wgName;

    // Wireguard private key (required)
    std::string privateKey;

    // Wireguard interface publicKey <optional>
    std::string publicKey;

    // Wireguard port listen
    unsigned short portListen = 0;

    // FirewallMark specifies a device's firewall mark
    // else set to 0, the firewall mark will be cleared.
    int fwmark = -1;

    // Interface address'es
    std::vector<std::string> Address;

    // Replace peers
    bool replacePeers = false;

    // Wireguard peers, Map: <publicKey(std::string), Peer>
    std::map<std::string, Peer> peersVector;
  public:
  const Napi::Promise::Deferred setPromise;

  void OnOK() override {
    Napi::HandleScope scope(Env());
    // Callback().Call({ Env().Undefined() });
    setPromise.Resolve(Env().Undefined());
  };

  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    // Callback().Call({ e.Value() });
    setPromise.Reject(e.Value());
  }

  ~setConfig() {}
  setConfig(const Napi::Env env, std::string name, const Napi::Object &config) : AsyncWorker(env), setPromise{env}, wgName{name} {
    // Wireguard public key
    const auto sppk = config.Get("publicKey");
    if (sppk.IsString()) {
      publicKey = sppk.ToString().Utf8Value();
      if (publicKey.length() != B64_WG_KEY_LENGTH) throw Napi::Error::New(env, "Set valid publicKey");
    }

    // Private key
    const auto sprk = config.Get("privateKey");
    if (!(sprk.IsString())) throw Napi::Error::New(env, "privateKey is empty");
    privateKey = sprk.ToString().Utf8Value();
    if (privateKey.length() != B64_WG_KEY_LENGTH) throw Napi::Error::New(env, (std::string("Set valid privateKey ")).append(std::to_string(privateKey.length())));

    // Port to listen Wireguard interface
    const auto spor = config.Get("portListen");
    if (spor.IsNumber() && (spor.ToNumber().Int32Value() >= 0 && spor.ToNumber().Int32Value() <= 65535)) portListen = spor.ToNumber().Int32Value();

    // Firewall mark
    const auto sfw = config.Get("fwmark");
    if (sfw.IsNumber() && (sfw.ToNumber().Uint32Value() >= 0)) fwmark = sfw.ToNumber().Uint32Value();
    else fwmark = -1;

    const auto saddr = config.Get("Address");
    if (saddr.IsArray()) {
      const Napi::Array addrs = saddr.As<Napi::Array>();
      for (unsigned int i = 0; i < addrs.Length(); i++) {
        if (addrs.Get(i).IsString()) Address.push_back(addrs.Get(i).ToString().Utf8Value());
      }
    }

    // Replace peers
    const auto srpee = config.Get("replacePeers");
    if (srpee.IsBoolean()) replacePeers = srpee.ToBoolean().Value();

    // Peers
    const auto speers = config.Get("peers");
    if (speers.IsObject()) {
      const Napi::Object Peers = speers.ToObject();
      const Napi::Array Keys = Peers.GetPropertyNames();
      for (unsigned int peerIndex = 0; peerIndex < Keys.Length(); peerIndex++) {
        const auto peerPubKey = Keys[peerIndex];
        if (peerPubKey.IsString() && Peers.Get(Keys[peerIndex]).IsObject()) {
          std::string ppkey = peerPubKey.ToString().Utf8Value();
          if (ppkey.length() != B64_WG_KEY_LENGTH) throw Napi::Error::New(env, std::string("Set valid peer publicKey, value: ").append(ppkey));
          const Napi::Object peerConfigObject = Peers.Get(Keys[peerIndex]).ToObject();

          Peer peerConfig = Peer();
          const auto removeMe = peerConfigObject.Get("removeMe");
          if (removeMe.IsBoolean() && removeMe.ToBoolean().Value()) peerConfig.removeMe = true;
          else {
            // Preshared key
            const auto pprekey = peerConfigObject.Get("presharedKey");
            if (pprekey.IsString()) {
              peerConfig.presharedKey = pprekey.ToString().Utf8Value();
              if (peerConfig.presharedKey.length() != B64_WG_KEY_LENGTH) throw Napi::Error::New(env, "Set valid peer presharedKey");
            }

            // Keep interval
            const auto pKeepInterval = peerConfigObject.Get("keepInterval");
            if (pKeepInterval.IsNumber() && (pKeepInterval.ToNumber().Int32Value() > 0 && pKeepInterval.ToNumber().Int32Value() <= 65535)) peerConfig.keepInterval = pKeepInterval.ToNumber().Int32Value();

            // Peer endpoint
            const auto pEndpoint = peerConfigObject.Get("endpoint");
            if (pEndpoint.IsString()) peerConfig.endpoint = pEndpoint.ToString().Utf8Value();

            // Allowed ip's array
            const auto pAllowedIPs = peerConfigObject.Get("allowedIPs");
            if (pAllowedIPs.IsArray()) {
              const auto AllowedIps = pAllowedIPs.As<Napi::Array>();
              for (uint32_t allIndex = 0; allIndex < AllowedIps.Length(); allIndex++) {
                if (AllowedIps.Get(allIndex).IsString()) peerConfig.allowedIPs.push_back(AllowedIps.Get(allIndex).ToString().Utf8Value());
              }
            }
          }

          // Insert peer
          peersVector[ppkey] = peerConfig;
        }
      }
    }
  }

  // Set platform Execute script
  void Execute() override;
};

class getConfig : public Napi::AsyncWorker {
  private:
    // Wireguard interface name (required)
    std::string wgName;

    // Wireguard private key (required)
    std::string privateKey;

    // Wireguard interface publicKey <optional>
    std::string publicKey;

    // Wireguard port listen
    unsigned int portListen;

    // FirewallMark specifies a device's firewall mark
    // else set to 0, the firewall mark will be cleared.
    int fwmark = -1;

    // Interface address'es
    std::vector<std::string> Address;

    /*
    Wireguard peers
    Map: <publicKey, Peer>
    */
    std::map<std::string, Peer> peersVector;
  public:
  ~getConfig() {}
  getConfig(const Napi::Env env, std::string name): AsyncWorker(env), getPromise{env}, wgName{name} {}
  const Napi::Promise::Deferred getPromise;

  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    getPromise.Reject(e.Value());
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const auto config = Napi::Object::New(env);

    if (privateKey.length() == B64_WG_KEY_LENGTH) config.Set("privateKey", privateKey);
    if (publicKey.length() == B64_WG_KEY_LENGTH) config.Set("publicKey", publicKey);
    if (portListen >= 0 && portListen <= 65535) config.Set("portListen", portListen);
    if (fwmark >= 0) config.Set("fwmark", fwmark);
    if (Address.size() > 0) {
      const auto Addrs = Napi::Array::New(env);
      for (auto &addr : Address) Addrs.Set(Addrs.Length(), addr);
      config.Set("Address", Addrs);
    }

    // Peer object
    const auto PeersObject = Napi::Object::New(env);
    for (auto &peer : peersVector) {
      const auto PeerObject = Napi::Object::New(env);
      auto peerConfig = peer.second;

      if (peerConfig.presharedKey.length() == B64_WG_KEY_LENGTH) PeerObject.Set("presharedKey", peerConfig.presharedKey);
      if (peerConfig.keepInterval > 0 && peerConfig.keepInterval <= 65535) PeerObject.Set("keepInterval", peerConfig.keepInterval);
      if (peerConfig.endpoint.length() > 0) PeerObject.Set("endpoint", peerConfig.endpoint);
      if (peerConfig.rxBytes >= 0) PeerObject.Set("rxBytes", Napi::BigInt::New(env, (uint64_t)peerConfig.rxBytes));
      if (peerConfig.txBytes >= 0) PeerObject.Set("txBytes", Napi::BigInt::New(env, (uint64_t)peerConfig.txBytes));
      if (peerConfig.last_handshake >= 0) {
        PeerObject.Set("lastHandshake", Napi::Date::New(env, peerConfig.last_handshake));
        PeerObject.Set("lastHandshakeBigint", peerConfig.last_handshake); // Debug to windows
      }
      if (peerConfig.allowedIPs.size() > 0) {
        const auto allowedIPs = Napi::Array::New(env);
        for (auto &ip : peerConfig.allowedIPs) allowedIPs.Set(allowedIPs.Length(), ip);
        PeerObject.Set("allowedIPs", allowedIPs);
      }

      // const std::string peerPubKey = peer.first;
      PeersObject.Set(peer.first, PeerObject);
    }

    // Set peers to object
    config.Set("peers", PeersObject);

    // Resolve config json
    getPromise.Resolve(config);
  };

  // Set platform Execute script
  void Execute() override;
};
