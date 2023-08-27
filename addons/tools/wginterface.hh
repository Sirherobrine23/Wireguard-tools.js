#pragma once
#include <napi.h>
#include <string>
#include <vector>
#include <map>

int maxName();

/*
Esta função consegela o loop event

Pegar todas as interfaces do Wireguard e retorna em forma de String sendo tratado pelo Node.js quando retornado.
*/
Napi::Value listDevicesSync(const Napi::CallbackInfo& info);

/* Esta função consegela o loop event */
Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info);

/*
Configure uma interface do Wireguard.
*/
Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info);

class Peer {
  public:
  std::string presharedKey;
  std::string endpoint;
  std::vector<std::string> allowedIPs;
  uint32_t keepInterval;
  bool removeMe;
};

// Parse config to wireguard interface
class setConfig : public Napi::AsyncWorker {
  private:
    // Wireguard interface name (required)
    std::string wgName;

    // Wireguard private key (required)
    std::string privateKey;

    // Wireguard interface publicKey <optional>
    std::string publicKey;

    // Wireguard port listen
    uint32_t portListen;

    // Wiki
    uint32_t fwmark;

    // Interface address'es
    std::vector<std::string> Address;

    // Replace peers
    bool replacePeers;

    /*
    Wireguard peers
    Map: <publicKey, Peer>
    */
    std::map<std::string, Peer> peersVector;
  public:
  ~setConfig() {}
  setConfig(const Napi::Env env, const Napi::Function &callback, std::string &name, const Napi::Object &config) : AsyncWorker(callback), wgName(name) {
    // Wireguard public key
    const auto sppk = config.Get("publicKey");
    if (sppk.IsString()) publicKey = sppk.ToString().Utf8Value();

    // Private key
    const auto sprk = config.Get("privateKey");
    if (!(sprk.IsString())) throw Napi::Error::New(env, "privateKey is empty");
    privateKey = sprk.ToString().Utf8Value();

    // Port to listen Wireguard interface
    const auto spor = config.Get("portListen");
    if (spor.IsNumber() && (spor.ToNumber().Int32Value() > 0)) portListen = spor.ToNumber().Int32Value();

    //\?
    const auto sfw = config.Get("fwmark");
    if (sfw.IsNumber() && (sfw.ToNumber().Uint32Value() >= 0)) fwmark = sfw.ToNumber().Uint32Value();

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
          const Napi::Object peerConfigObject = Peers.Get(Keys[peerIndex]).ToObject();

          Peer peerConfig = Peer();
          const auto removeMe = peerConfigObject.Get("removeMe");
          if (removeMe.IsBoolean() && removeMe.ToBoolean().Value()) peerConfig.removeMe = true;
          else {
            // Preshared key
            const auto pprekey = peerConfigObject.Get("presharedKey");
            if (pprekey.IsString()) peerConfig.presharedKey = pprekey.ToString().Utf8Value();

            // Keep interval
            const auto pKeepInterval = peerConfigObject.Get("keepInterval");
            if (pKeepInterval.IsNumber() && (pKeepInterval.ToNumber().Int32Value() > 0)) peerConfig.keepInterval = pKeepInterval.ToNumber().Int32Value();

            // Peer endpoint
            const auto pEndpoint = peerConfigObject.Get("endpoint");
            if (pEndpoint.IsString()) peerConfig.endpoint = pEndpoint.ToString().Utf8Value();

            // Allowed ip's array
            const auto pAllowedIPs = peerConfigObject.Get("allowedIPs");
            if (pAllowedIPs.IsArray()) {
              const auto AllowedIps = pAllowedIPs.As<Napi::Array>();
              for (uint32_t allIndex = 0; allIndex < AllowedIps.Length(); allIndex++) {
                if (AllowedIps.Get(allIndex).IsString()) {
                  std::string ip = AllowedIps.Get(allIndex).ToString().Utf8Value();
                  peerConfig.allowedIPs.insert(peerConfig.allowedIPs.begin() + 1, ip);
                }
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

  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({ Env().Null() });
  };
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value() });
  }
};
