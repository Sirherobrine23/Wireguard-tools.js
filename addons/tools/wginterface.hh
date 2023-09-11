#pragma once
#include <napi.h>
#include <string>
#include <vector>
#include <map>

#define WG_KEY_LENGTH 44

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
  deleteInterface(const Napi::Function &callback, std::string name): AsyncWorker(callback), wgName(name) {}
  ~deleteInterface() {}
  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({ Env().Undefined() });
  };
  void OnError(const Napi::Error &e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value() });
  }

  // Set platform Execute script
  void Execute() override;
};

class listDevices : public Napi::AsyncWorker {
  private:
    std::map<std::string, std::string> deviceNames;
  public:
  ~listDevices() {}
  listDevices(const Napi::Function &callback) : AsyncWorker(callback) {}
  void OnOK() override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const auto deviceArray = Napi::Array::New(env);
    if (deviceNames.size() > 0) {
      for (auto &it : deviceNames) {
        auto info = Napi::Object::New(env);
        info.Set("name", it.first);
        info.Set("from", it.second);
        deviceArray.Set(deviceArray.Length(), info);
      }
    }
    Callback().Call({ Env().Undefined(), deviceArray });
  };
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value() });
  }
  void Execute() override;
};

class Peer {
  public:
  bool removeMe;
  std::string presharedKey;
  std::string endpoint;
  std::vector<std::string> allowedIPs;
  uint32_t keepInterval;
  uint64_t rxBytes = 0, txBytes = 0;
  long long last_handshake = 0;
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
    uint32_t portListen = 0;

    // Wiki
    uint32_t fwmark = 0;

    // Interface address'es
    std::vector<std::string> Address;

    // Replace peers
    bool replacePeers = false;

    // Wireguard peers, Map: <publicKey(std::string), Peer>
    std::map<std::string, Peer> peersVector;
  public:
  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({ Env().Undefined() });
  };
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value() });
  }

  ~setConfig() {}
  setConfig(const Napi::Env env, const Napi::Function &callback, std::string name, const Napi::Object &config) : AsyncWorker(callback), wgName(name) {
    // Wireguard public key
    const auto sppk = config.Get("publicKey");
    if (sppk.IsString()) {
      publicKey = sppk.ToString().Utf8Value();
      if (publicKey.length() != WG_KEY_LENGTH) throw Napi::Error::New(env, "Set valid publicKey");
    }

    // Private key
    const auto sprk = config.Get("privateKey");
    if (!(sprk.IsString())) throw Napi::Error::New(env, "privateKey is empty");
    privateKey = sprk.ToString().Utf8Value();
    if (privateKey.length() != WG_KEY_LENGTH) throw Napi::Error::New(env, ((std::string)"Set valid privateKey ").append(std::to_string(privateKey.length())));

    // Port to listen Wireguard interface
    const auto spor = config.Get("portListen");
    if (spor.IsNumber() && (spor.ToNumber().Int32Value() >= 0 && spor.ToNumber().Int32Value() <= 65535)) portListen = spor.ToNumber().Int32Value();

    //\?
    #ifdef __linux
    const auto sfw = config.Get("fwmark");
    if (sfw.IsNumber() && (sfw.ToNumber().Uint32Value() >= 0)) fwmark = sfw.ToNumber().Uint32Value();
    #endif

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
          if (ppkey.length() != WG_KEY_LENGTH) throw Napi::Error::New(env, "Set valid peer publicKey");
          const Napi::Object peerConfigObject = Peers.Get(Keys[peerIndex]).ToObject();

          Peer peerConfig = Peer();
          const auto removeMe = peerConfigObject.Get("removeMe");
          if (removeMe.IsBoolean() && removeMe.ToBoolean().Value()) peerConfig.removeMe = true;
          else {
            // Preshared key
            const auto pprekey = peerConfigObject.Get("presharedKey");
            if (pprekey.IsString()) {
              peerConfig.presharedKey = pprekey.ToString().Utf8Value();
              if (peerConfig.presharedKey.length() != WG_KEY_LENGTH) throw Napi::Error::New(env, "Set valid peer presharedKey");
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

    // Wiki
    unsigned int fwmark;

    // Interface address'es
    std::vector<std::string> Address;

    /*
    Wireguard peers
    Map: <publicKey, Peer>
    */
    std::map<std::string, Peer> peersVector;
  public:
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value() });
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const auto config = Napi::Object::New(env);

    if (publicKey.length() == WG_KEY_LENGTH) config.Set("publicKey", publicKey);
    if (privateKey.length() == WG_KEY_LENGTH) config.Set("privateKey", privateKey);
    if (portListen > 0 && portListen <= 65535) config.Set("portListen", portListen);
    #ifdef __linux
    if (fwmark >= 0) config.Set("fwmark", fwmark);
    #endif
    if (Address.size() > 0) {
      const auto Addrs = Napi::Array::New(env);
      for (auto &addr : Address) Addrs.Set(Addrs.Length(), addr);
      config.Set("Address", Addrs);
    }

    // Peer object
    const auto PeersObject = Napi::Object::New(env);
    for (auto &peer : peersVector) {
      const auto PeerObject = Napi::Object::New(env);
      const std::string peerPubKey = peer.first;
      auto peerConfig = peer.second;

      if (peerConfig.presharedKey.length() == WG_KEY_LENGTH) PeerObject.Set("presharedKey", peerConfig.presharedKey);
      if (peerConfig.keepInterval > 0 && peerConfig.keepInterval <= 65535) PeerObject.Set("keepInterval", peerConfig.keepInterval);
      if (peerConfig.endpoint.length() > 0) PeerObject.Set("endpoint", peerConfig.endpoint);
      if (peerConfig.last_handshake >= 0) PeerObject.Set("lastHandshake", Napi::Date::New(env, peerConfig.last_handshake));
      // if (peerConfig.last_handshake >= 0) PeerObject.Set("lastHandshake", peerConfig.last_handshake);
      if (peerConfig.rxBytes >= 0) PeerObject.Set("rxBytes", peerConfig.rxBytes);
      if (peerConfig.txBytes >= 0) PeerObject.Set("txBytes", peerConfig.txBytes);
      if (peerConfig.allowedIPs.size() > 0) {
        const auto allowedIPs = Napi::Array::New(env);
        for (auto &ip : peerConfig.allowedIPs) allowedIPs.Set(allowedIPs.Length(), ip);
        PeerObject.Set("allowedIPs", allowedIPs);
      }

      PeersObject.Set(peerPubKey, PeerObject);
    }
    config.Set("peers", PeersObject);

    // Done and callack call
    Callback().Call({ Env().Undefined(), config });
  };

  ~getConfig() {}
  getConfig(const Napi::Function &callback, std::string name): AsyncWorker(callback), wgName(name) {}

  // Set platform Execute script
  void Execute() override;
};