#pragma once
#include <napi.h>

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