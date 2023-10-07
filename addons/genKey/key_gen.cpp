#include <napi.h>
#include "wgkeys.hh"

class privateKeyWorker : public Napi::AsyncWorker {
  private:
    std::string pskString;
    Napi::Promise::Deferred genPromise;
  public:
  ~privateKeyWorker() {}
  privateKeyWorker(const Napi::Env env) : AsyncWorker(env), genPromise{env} {}
  Napi::Promise getPromise() { return genPromise.Promise(); }
  void Execute() override {
    wg_key keyg;
    wgKeys::generatePrivate(keyg);
    pskString = wgKeys::toString(keyg);
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    genPromise.Resolve(Napi::String::New(Env(), pskString));
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    genPromise.Reject(e.Value());
  }
};

class publicKeyWorker : public Napi::AsyncWorker {
  private:
    std::string privKey, pubString;
    Napi::Promise::Deferred genPromise;
  public:
  ~publicKeyWorker() {}
  publicKeyWorker(const Napi::Env env, std::string privateKey) : AsyncWorker(env), privKey(privateKey), genPromise{env} {}
  Napi::Promise getPromise() { return genPromise.Promise(); }
  void Execute() override {
    wg_key interfacePrivateKey, interfacePublicKey;
    try {
      wgKeys::stringToKey(interfacePrivateKey, privKey);
      wgKeys::generatePublic(interfacePublicKey, interfacePrivateKey);
      pubString = wgKeys::toString(interfacePublicKey);
    } catch (std::string &err) {
      SetError(err);
    }
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    genPromise.Resolve(Napi::String::New(Env(), pubString));
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    genPromise.Reject(e.Value());
  }
};

class presharedKeyWorker : public Napi::AsyncWorker {
  private:
    std::string pskString;
    Napi::Promise::Deferred genPromise;
  public:
  ~presharedKeyWorker() {}
  presharedKeyWorker(const Napi::Env env) : AsyncWorker(env), genPromise{env} {}
  Napi::Promise getPromise() { return genPromise.Promise(); }
  void Execute() override {
    wg_key keyg;
    wgKeys::generatePreshared(keyg);
    pskString = wgKeys::toString(keyg);
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    genPromise.Resolve(Napi::String::New(Env(), pskString));
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    genPromise.Reject(e.Value());
  }
};

class genKeysWorker : public Napi::AsyncWorker {
  private:
    std::string privateKey, publicKey, presharedKey;
    bool withPreshared = false;
    Napi::Promise::Deferred genPromise;
  public:
  ~genKeysWorker() {}
  genKeysWorker(const Napi::Env env, bool withPresharedKey) : AsyncWorker(env), withPreshared(withPresharedKey), genPromise{env} {}
  Napi::Promise getPromise() { return genPromise.Promise(); }
  void Execute() override {
    wg_key keyPriv, preshe, pub;

    wgKeys::generatePrivate(keyPriv);
    privateKey = wgKeys::toString(keyPriv);

    wgKeys::generatePublic(pub, keyPriv);
    publicKey = wgKeys::toString(pub);

    if (!withPreshared) return;
    wgKeys::generatePreshared(preshe);
    presharedKey = wgKeys::toString(preshe);
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    const Napi::Env env = Env();
    auto keys = Napi::Object::New(env);
    keys.Set("privateKey", privateKey);
    keys.Set("publicKey", publicKey);
    if (withPreshared) keys.Set("presharedKey", presharedKey);

    genPromise.Resolve(keys);
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    genPromise.Reject(e.Value());
  }
};

Napi::Object Init(Napi::Env exportsEnv, Napi::Object exports) {
  auto constants = Napi::Object::New(exportsEnv);
  constants.Set("WG_KEY_LENGTH", WG_KEY_LENGTH);
  constants.Set("B64_WG_KEY_LENGTH", B64_WG_KEY_LENGTH);
  exports.Set("constants", constants);

  exports.Set("presharedKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) {
    const Napi::Env env = info.Env();

    // Callback function is latest argument
    auto *Gen = new presharedKeyWorker(env);
    Gen->Queue();
    return Gen->getPromise();
  }));

  exports.Set("privateKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) {
    const Napi::Env env = info.Env();

    // Callback function is latest argument
    auto *Gen = new privateKeyWorker(env);
    Gen->Queue();
    return Gen->getPromise();
  }));

  exports.Set("publicKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) -> Napi::Value {
    const Napi::Env env = info.Env();
    if (!(info[0].IsString())) {
      Napi::Error::New(env, "Require private key").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    // Callback function is latest argument
    auto *Gen = new publicKeyWorker(env, info[0].ToString().Utf8Value().c_str());
    Gen->Queue();
    return Gen->getPromise();
  }));

  exports.Set("genKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo &info) {
    const Napi::Env env = info.Env();
    bool withPreshared = false;
    if (info[0].IsBoolean()) withPreshared = info[0].ToBoolean().Value();
    auto Gen = new genKeysWorker(env, withPreshared);
    Gen->Queue();
    return Gen->getPromise();
  }));
  return exports;
}
NODE_API_MODULE(addon, Init);