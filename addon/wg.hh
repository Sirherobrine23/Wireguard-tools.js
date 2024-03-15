#ifndef __WG_NODE__
#define __WG_NODE__
#include "wginterface.hh"
#include <napi.h>
#include <functional>
#include <iostream>

class Promised : public Napi::AsyncWorker {
  public:
  Napi::Promise::Deferred NodePromise;
  Promised(const Napi::Env &env): AsyncWorker(env), NodePromise{env} {}

  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    NodePromise.Reject(e.Value());
  }

  void OnOK() override {
    Napi::HandleScope scope(Env());
    auto call = [&](Napi::Value data) -> void { NodePromise.Resolve(data); };
    runOk(call);
  }

  virtual void runOk(std::function<void(Napi::Value)> callback) {
    Napi::HandleScope scope(Env());
    callback(Env().Undefined());
  };
};

class DeleteInterface : public Promised {
  std::string wgName;
  public:
  DeleteInterface(const Napi::Env &env, const Napi::String &name): Promised(env), wgName{name.Utf8Value()} {}

  void Execute() override {
    WireguardDevices wgDevs = WireguardDevices();
    try {
      wgDevs.deleteInterface(wgName);
    } catch (std::string &err) { SetError(err); }
  }
};

class ListDevices : public Promised {
  WireguardDevices wgDevs;
  public:
  ListDevices(const Napi::Env &env): Promised(env), wgDevs{} {}

  void Execute() override {
    try {
      wgDevs.getInterfaces();
    } catch (std::string &err) { SetError(err); }
  }

  void runOk(std::function<void(Napi::Value)> callback) override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const Napi::Array interf = Napi::Array::New(env);
    for (auto &ip : wgDevs) interf.Set(interf.Length(), ip);
    callback(interf);
  }
};

class SetConfig : public WireguardConfig, public Promised {
  public:
  void Execute() {
    try {
      this->setWireguardConfig();
    } catch (std::string err) {
      SetError(err);
    }
  }

  SetConfig(const Napi::Env &env, const Napi::Object config): Promised(env) {
    if (!(config.Has("name"))) throw std::string("Set wireguard interface name!");
    if (!(config.Has("privateKey") && config.Get("privateKey").IsString())) throw std::string("Set wireguard private key!");
    this->name = config.Get("name").ToString().Utf8Value();
    this->privateKey = config.Get("privateKey").ToString().Utf8Value();
    if (config.Has("publicKey") && config.Get("publicKey").IsString() && config.Get("publicKey").ToString().Utf8Value().length() == Base64WgKeyLength) this->publicKey = config.Get("publicKey").ToString().Utf8Value();
    if (config.Has("portListen") && config.Get("portListen").IsNumber() && config.Get("portListen").ToNumber().Int32Value() >= 0) this->portListen = config.Get("portListen").ToNumber().Int32Value();
    if (config.Has("fwmark") && config.Get("fwmark").IsNumber() && config.Get("fwmark").ToNumber().Int32Value() >= 0) this->fwmark = config.Get("fwmark").ToNumber().Int32Value();
    if (config.Has("replacePeers") && config.Get("replacePeers").IsBoolean()) this->replacePeers = config.Get("replacePeers").ToBoolean().Value();

    if (config.Has("address") && config.Get("address").IsArray() && config.Get("address").As<Napi::Array>().Length() > 0) {
      const Napi::Array Addrs(config.Get("address").As<Napi::Array>());
      for (unsigned int AddrIndex = 0; AddrIndex < Addrs.Length(); AddrIndex++) {
        if (!(Addrs[AddrIndex].IsString())) continue;
        this->interfaceAddress.addIPMask(Addrs[AddrIndex].ToString().Utf8Value());
      }
    }

    if (config.Has("peers") && config.Get("peers").IsObject()) {
      const Napi::Object PeersObject(config.Get("peers").ToObject());
      const Napi::Array PeersKeys(PeersObject.GetPropertyNames());
      for (unsigned int peerIndex = 0; peerIndex < PeersKeys.Length(); peerIndex++) {
        if (!(PeersObject.Get(PeersKeys[peerIndex].ToString()).IsObject())) continue;
        const std::string publicKey(PeersKeys[peerIndex].ToString().Utf8Value());
        const Napi::Object peerConfig(PeersObject.Get(publicKey).ToObject());
        Peer peer;

        if (peerConfig.Has("removeMe") && peerConfig.Get("removeMe").IsBoolean() && peerConfig.Get("removeMe").As<Napi::Boolean>().Value()) peer.removeMe = true;
        else {
          if (peerConfig.Has("presharedKey") && peerConfig.Get("presharedKey").IsString() && peerConfig.Get("presharedKey").ToString().Utf8Value().length() == Base64WgKeyLength) peer.presharedKey = peerConfig.Get("presharedKey").ToString().Utf8Value();
          if (peerConfig.Has("keepInterval") && peerConfig.Get("keepInterval").IsNumber() && peerConfig.Get("keepInterval").ToNumber().Int32Value() > 0) peer.keepInterval = peerConfig.Get("keepInterval").ToNumber().Int32Value();
          if (peerConfig.Has("endpoint") && peerConfig.Get("endpoint").IsString() && peerConfig.Get("endpoint").ToString().Utf8Value().length() == Base64WgKeyLength) peer.endpoint = peerConfig.Get("endpoint").ToString().Utf8Value();
          if (peerConfig.Has("allowedIPs") && peerConfig.Get("allowedIPs").IsArray()) {
            const Napi::Array ips = peerConfig.Get("allowedIPs").As<Napi::Array>();
            for (unsigned int ipIndex = 0; ipIndex < ips.Length(); ipIndex++) peer.allowedIPs.addIPMask(ips[ipIndex].ToString().Utf8Value());
          }
        }

        // Set peer in map
        this->Peers[publicKey] = peer;
      }
    }
  }
};

class GetConfig : public WireguardConfig, public Promised {
  public:
  GetConfig(const Napi::Env &env, const Napi::String name): Promised(env) {
    this->name = name.Utf8Value();
  }
  void Execute() {
    try {
      this->getWireguardConfig();
    } catch (std::string err) {
      SetError(err);
    }
  }

  void runOk(std::function<void(Napi::Value)> callback) {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    const Napi::Object config = Napi::Object::New(env);
    config.Set("name", this->name);
    config.Set("privateKey", this->privateKey);
    if (this->publicKey.length() == Base64WgKeyLength) config.Set("publicKey", this->publicKey);
    if (this->portListen > 0) config.Set("portListen", this->portListen);
    if (this->fwmark > 0) config.Set("fwmark", this->fwmark);

    // Interface IPs
    const Napi::Array ips = Napi::Array::New(env);
    for (auto ip : this->interfaceAddress) ips.Set(ips.Length(), ip);
    config.Set("address", ips);

    // Peers
    const Napi::Object peersObj = Napi::Object::New(env);
    for (auto &__peer : this->Peers) {
      std::string publicKey = __peer.first;
      if (publicKey.length() != Base64WgKeyLength) continue;
      const Napi::Object peerConfig = Napi::Object::New(env);
      const Peer config = __peer.second;

      if (config.presharedKey.length() == Base64WgKeyLength) peerConfig.Set("presharedKey", config.presharedKey);
      if (config.keepInterval >= 0) peerConfig.Set("keepInterval", config.keepInterval);
      if (config.endpoint.length() > 0) peerConfig.Set("endpoint", config.endpoint);

      peerConfig.Set("rxBytes", Napi::BigInt::New(env, (uint64_t)config.rxBytes));
      peerConfig.Set("txBytes", Napi::BigInt::New(env, (uint64_t)config.txBytes));
      peerConfig.Set("lastHandshake", Napi::Date::New(env, config.lastHandshake));

      const Napi::Array ips = Napi::Array::New(env);
      for (auto &ip : config.allowedIPs) ips.Set(ips.Length(), ip);
      peerConfig.Set("allowedIPs", ips);

      peersObj.Set(publicKey, peerConfig);
    }
    config.Set("peers", peersObj);

    // Set data
    callback(config);
  }
};

#endif
