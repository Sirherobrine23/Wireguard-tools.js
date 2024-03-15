#include "wg.hh"
#include <napi.h>

Napi::Object StartAddon(const Napi::Env env, const Napi::Object exports) {
  std::map<std::string, std::string> LoadConfig;
  const Napi::Array keysOnLoadsNames = exports.GetPropertyNames();
  for (unsigned int keyIndex = 0; keyIndex < keysOnLoadsNames.Length(); keyIndex++) {
    if (!(exports.Get(keysOnLoadsNames[keyIndex]).IsString())) continue;
    LoadConfig[keysOnLoadsNames[keyIndex].ToString().Utf8Value()] = exports.Get(keysOnLoadsNames[keyIndex]).ToString().Utf8Value();
  }

  #ifdef _WIN32
  std::string statusLoading = driveLoad(LoadConfig);
  if (!!(statusLoading.length())) {
    Napi::Error::New(env, statusLoading).ThrowAsJavaScriptException();
    return exports;
  }
  #endif

  const Napi::Object Constants = Napi::Object::New(env);
  if (getWireguardVersion().length() > 0) Constants.Set("driveVersion", getWireguardVersion());

  exports.Set("deleteInterface", Napi::Function::New(env, [](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    if (!(info[0].IsString())) {
      Napi::Error::New(env, "Set interface name").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    try {
      DeleteInterface *worker = new DeleteInterface(env, info[0].ToString());
      worker->Queue();
      return worker->NodePromise.Promise();
    } catch (std::string &err) {
      Napi::Error::New(env, err).ThrowAsJavaScriptException();
      return env.Undefined();
    }
  }));

  exports.Set("listDevices", Napi::Function::New(env, [](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    try {
      ListDevices *worker = new ListDevices(env);
      worker->Queue();
      return worker->NodePromise.Promise();
    } catch (std::string &err) {
      Napi::Error::New(env, err).ThrowAsJavaScriptException();
      return env.Undefined();
    }
  }));

  exports.Set("setConfig", Napi::Function::New(env, [](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    if (!(info[0].IsObject())) Napi::Error::New(env, "Set wireguard config!").ThrowAsJavaScriptException();
    try {
      SetConfig *worker = new SetConfig(env, info[0].ToObject());
      worker->Queue();
      return worker->NodePromise.Promise();
    } catch (std::string &err) {
      Napi::Error::New(env, err).ThrowAsJavaScriptException();
    }
    return env.Undefined();
  }));

  exports.Set("getConfig", Napi::Function::New(env, [](const Napi::CallbackInfo &info) -> Napi::Value {
    const Napi::Env env = info.Env();
    if (!(info[0].IsString())) {
      Napi::Error::New(env, "Set interface name in fist argument!").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    try {
      GetConfig *worker = new GetConfig(env, info[0].ToString());
      worker->Queue();
      return worker->NodePromise.Promise();
    } catch (std::string &err) {
      Napi::Error::New(env, err).ThrowAsJavaScriptException();
      return env.Undefined();
    }
  }));

  exports.Set("constants", Constants);
  return exports;
}
NODE_API_MODULE(addon, StartAddon);
