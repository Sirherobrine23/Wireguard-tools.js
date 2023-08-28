#include <napi.h>
#include <wginterface.hh>

#ifdef _WIN32
#define IFNAMSIZ 64
#else
#include <net/if.h>
#endif


int maxName() {
  return IFNAMSIZ;
}

Napi::Value listDevicesSync(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Use userpace implementation, kernel only on linux!").ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Use userpace implementation, kernel only on linux!").ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  Napi::Error::New(env, "Use userpace implementation, kernel only on linux!").ThrowAsJavaScriptException();
  return env.Undefined();
}

void setConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void getConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}