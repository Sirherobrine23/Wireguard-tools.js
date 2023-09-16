#include <napi.h>
#include "wgkeys.hh"

class privateKeyWorker : public Napi::AsyncWorker {
  private:
    std::string pskString;
  public:
  ~privateKeyWorker() {}
  privateKeyWorker(const Napi::Function& callback) : AsyncWorker(callback) {}
  void Execute() override {
    wg_key keyg;
    wgKeys::generatePrivate(keyg);
    pskString = wgKeys::toString(keyg);
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({ Env().Null(), Napi::String::New(Env(), pskString) });
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value(), Env().Null() });
  }
};

class publicKeyWorker : public Napi::AsyncWorker {
  private:
    std::string privKey, pubString;
  public:
  ~publicKeyWorker() {}
  publicKeyWorker(const Napi::Function& callback, std::string privateKey) : AsyncWorker(callback), privKey(privateKey) {}
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
    Callback().Call({ Env().Null(), Napi::String::New(Env(), pubString) });
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value(), Env().Null() });
  }
};

class presharedKeyWorker : public Napi::AsyncWorker {
  private:
    std::string pskString;
  public:
  ~presharedKeyWorker() {}
  presharedKeyWorker(const Napi::Function& callback) : AsyncWorker(callback) {}
  void Execute() override {
    wg_key keyg;
    wgKeys::generatePreshared(keyg);
    pskString = wgKeys::toString(keyg);
  }
  void OnOK() override {
    Napi::HandleScope scope(Env());
    Callback().Call({ Env().Null(), Napi::String::New(Env(), pskString) });
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value(), Env().Null() });
  }
};

class genKeysWorker : public Napi::AsyncWorker {
  private:
  std::string privateKey, publicKey, presharedKey;
  bool withPreshared = false;

  public:
  ~genKeysWorker() {}
  genKeysWorker(const Napi::Function& callback, bool withPresharedKey) : AsyncWorker(callback), withPreshared(withPresharedKey) {}
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

    Callback().Call({ Env().Null(), keys });
  }
  void OnError(const Napi::Error& e) override {
    Napi::HandleScope scope(Env());
    Callback().Call({ e.Value(), Env().Null() });
  }
};

Napi::Object Init(Napi::Env exportsEnv, Napi::Object exports) {
  auto constants = Napi::Object::New(exportsEnv);
  constants.Set("WG_KEY_LENGTH", WG_KEY_LENGTH);
  constants.Set("B64_WG_KEY_LENGTH", B64_WG_KEY_LENGTH);
  exports.Set("constants", constants);

  exports.Set("presharedKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) {
    const Napi::Env env = info.Env();
    const Napi::Function callback = info[info.Length() - 1].As<Napi::Function>();
    if (!(callback.IsFunction())) {
      Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    // Callback function is latest argument
    auto *Gen = new presharedKeyWorker(callback);
    Gen->Queue();
    return env.Undefined();
  }));

  exports.Set("privateKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) {
    const Napi::Env env = info.Env();
    const Napi::Function callback = info[info.Length() - 1].As<Napi::Function>();
    if (!(callback.IsFunction())) {
      Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    // Callback function is latest argument
    auto *Gen = new privateKeyWorker(callback);
    Gen->Queue();
    return env.Undefined();
  }));

  exports.Set("publicKey", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo& info) {
    const Napi::Env env = info.Env();
    if (!(info[0].IsString())) {
      Napi::Error::New(env, "Require private key").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    const Napi::Function callback = info[info.Length() - 1].As<Napi::Function>();
    if (!(callback.IsFunction())) {
      Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    // Callback function is latest argument
    auto *Gen = new publicKeyWorker(callback, info[0].ToString().Utf8Value().c_str());
    Gen->Queue();
    return env.Undefined();
  }));

  exports.Set("genKeys", Napi::Function::New(exportsEnv, [&](const Napi::CallbackInfo &info) {
    const Napi::Env env = info.Env();
    bool withPreshared = false;
    const Napi::Function callback = info[info.Length() - 1].As<Napi::Function>();
    if (!(callback.IsFunction())) {
      Napi::Error::New(env, "Require callback").ThrowAsJavaScriptException();
      return env.Undefined();
    } else if (info[0].IsBoolean()) withPreshared = info[0].ToBoolean().Value();
    auto Gen = new genKeysWorker(callback, withPreshared);
    Gen->Queue();
    return env.Undefined();
  }));
  return exports;
}
NODE_API_MODULE(addon, Init);