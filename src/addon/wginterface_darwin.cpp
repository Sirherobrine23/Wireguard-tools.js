#include <napi.h>
#include "wginterface.hh"
#include "sys/socket.h"

#define LISTDEVICESSYNC
#define SETUPDEVICESSYNC
#define PARSEDEVICESSYNC

Napi::Value listDevicesSync(const Napi::CallbackInfo& command) {}
Napi::Value listDevicesAsync(const Napi::CallbackInfo& command) {}

Napi::Value setupInterfaceSync(const Napi::CallbackInfo& info) {}
Napi::Value setupInterfaceAsync(const Napi::CallbackInfo& info) {}

Napi::Value parseWgDeviceSync(const Napi::CallbackInfo& info) {}
Napi::Value parseWgDeviceAsync(const Napi::CallbackInfo& info) {}