#include <napi.h>
#include "wg/src/ipc.h"
#include "wg/src/config.h"
#include "wg/src/encoding.h"
#include "wg/src/containers.h"

const char *PROG_NAME;

Napi::Value listDevices(const Napi::CallbackInfo& info) {
  return Napi::String::New(info.Env(), ipc_list_devices());
}

Napi::Value setupInterface(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();
  const Napi::String interfaceName = info[0].As<Napi::String>();
  const Napi::Object interfaceConfig = info[1].As<Napi::Object>();

  if (!(interfaceName.IsString())) {
    Napi::Error::New(env, "Require interface name").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(interfaceConfig.IsObject())) {
    Napi::Error::New(env, "Require config Object").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (interfaceName.Utf8Value().length() > IFNAMSIZ) {
    Napi::Error::New(env, "Interface name is long").ThrowAsJavaScriptException();
    return env.Undefined();
  }

  wgdevice *deviceStruct = new wgdevice({});

  // Set interface name
  strncpy(deviceStruct->name, interfaceName.Utf8Value().c_str(), interfaceName.Utf8Value().length());

  // Private key
  if (!(interfaceConfig["privateKey"].IsString())) {
    delete deviceStruct;
    Napi::Error::New(env, "Private key is empty").ThrowAsJavaScriptException();
    return env.Undefined();
  } else if (!(key_from_base64(deviceStruct->private_key, interfaceConfig["privateKey"].ToString().Utf8Value().c_str()))) {
    delete deviceStruct;
    Napi::Error::New(env, "Cannot set Interface private key").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  deviceStruct->flags = WGDEVICE_HAS_PRIVATE_KEY;

  // Public key
  if (interfaceConfig["publicKey"].IsString()) {
    if (!(key_from_base64(deviceStruct->public_key, interfaceConfig["publicKey"].ToString().Utf8Value().c_str()))) {
      delete deviceStruct;
      Napi::Error::New(env, "Cannot set Interface public key").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    deviceStruct->flags |= WGDEVICE_HAS_PUBLIC_KEY;
  }

  // Port listen
  const Napi::Number portListen = interfaceConfig["portListen"].As<Napi::Number>();
  if (portListen.IsNumber() && (portListen.Int32Value() > 0 && 25565 < portListen.Int32Value())) {
    deviceStruct->listen_port = (uint16_t)portListen.Int32Value();
    deviceStruct->flags |= WGDEVICE_HAS_LISTEN_PORT;
  }

  const Napi::String fwmark = interfaceConfig["fwmark"].As<Napi::String>();
  if (fwmark.IsString()) {
    if (!(parse_fwmark(&deviceStruct->fwmark, &deviceStruct->flags, fwmark.Utf8Value().c_str()))) {
      delete deviceStruct;
      Napi::Error::New(env, "Cannot set fwmark").ThrowAsJavaScriptException();
      return env.Undefined();
    }
  }

  // Replace Peers
  const Napi::Boolean replacePeers = interfaceConfig["replacePeers"].As<Napi::Boolean>();
  if (replacePeers.IsBoolean() && replacePeers.Value()) deviceStruct->flags |= WGDEVICE_REPLACE_PEERS;

  // Peers config
  wgpeer* peer;
  const Napi::Object Peers = interfaceConfig["peers"].IsObject() ? interfaceConfig["peers"].ToObject() : Napi::Object::New(env);
  const Napi::Array publicKeysPeers = Peers.GetPropertyNames();
  for (uint32_t peerIndex = 0; peerIndex < publicKeysPeers.Length(); peerIndex++) {
    const Napi::String peerPubKey = publicKeysPeers.Get(peerIndex).ToString();
    const Napi::Object peerConfig = Peers.Get(peerPubKey).As<Napi::Object>();
    if (!(peerConfig.IsObject() && publicKeysPeers.Get(peerIndex).IsString())) {
      free_wgdevice(deviceStruct);
      Napi::Error::New(env, "Cannot set peer").ThrowAsJavaScriptException();
      return env.Undefined();
    }

    wgpeer *peerStruct = new wgpeer({});
    // Set public key
    if (!(key_from_base64(peerStruct->public_key, peerPubKey.Utf8Value().c_str()))) {
      delete peerStruct;
      free_wgdevice(deviceStruct);
      Napi::Error::New(env, "Cannot set peer public key").ThrowAsJavaScriptException();
      return env.Undefined();
    }
    peerStruct->flags = WGPEER_HAS_PUBLIC_KEY;

    // Remove Peer
    const Napi::Boolean removeMe = peerConfig["removeMe"].As<Napi::Boolean>();
    if (removeMe.IsBoolean() && removeMe.Value()) peerStruct->flags |= WGPEER_REMOVE_ME;
    else {
      // Set preshared key if present
      if (peerConfig["presharedKey"].IsString()) {
        Napi::String PresharedKey = peerConfig["presharedKey"].As<Napi::String>();
        if (!(key_from_base64(peerStruct->preshared_key, PresharedKey.Utf8Value().c_str()))) {
          delete peerStruct;
          free_wgdevice(deviceStruct);
          Napi::Error::New(env, "Cannot set peer preshared key").ThrowAsJavaScriptException();
          return env.Undefined();
        }
        peerStruct->flags |= WGPEER_HAS_PRESHARED_KEY;
      }

      // Set Keepalive
      const Napi::Number keepInterval = peerConfig["keepInterval"].As<Napi::Number>();
      if (keepInterval.IsNumber() && (keepInterval.Int32Value() > 0 && 65535 < keepInterval.Int32Value())) {
        peerStruct->persistent_keepalive_interval = (uint16_t)keepInterval.Int32Value();
        peerStruct->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
      }

      // Set endpoint
      if (peerConfig["endpoint"].IsString()) {
        if (!(parse_endpoint(&peerStruct->endpoint.addr, peerConfig["endpoint"].ToString().Utf8Value().c_str()))) {
          Napi::Error::New(env, "Cannot set endpoint to peer").ThrowAsJavaScriptException();
          return env.Undefined();
        }
      }

      // Set allowed IPs
      const Napi::Array allowedIPs = peerConfig["allowedIPs"].As<Napi::Array>();
      if (allowedIPs.IsArray() && allowedIPs.Length() > 0) {
        peerStruct->flags |= WGPEER_REPLACE_ALLOWEDIPS;
        for (uint32_t allowIndex = 0; allowIndex < allowedIPs.Length(); allowIndex++) {
          if (!(allowedIPs.Get(allowIndex).IsString())) continue;
          if (!(parse_allowedips(peerStruct, &peerStruct->last_allowedip, allowedIPs.Get(allowIndex).ToString().Utf8Value().c_str()))) {
            delete peerStruct;
            free_wgdevice(deviceStruct);
            Napi::Error::New(env, "Cannot set peer allowed IP").ThrowAsJavaScriptException();
            return env.Undefined();
          }
        }
      }
    }

    // Add to Peer struct
    if (peer) peer->next_peer = peerStruct;
    else deviceStruct->first_peer = peerStruct;
    peer = peerStruct;
  }

  std::string err = "";
  if (ipc_set_device(deviceStruct) != 0) err = "Unable to set interface";
  free_wgdevice(deviceStruct);
  if (err.length() > 0) Napi::Error::New(env, err).ThrowAsJavaScriptException();
  return env.Undefined();
}

Napi::Value parseWgDevice(const Napi::CallbackInfo& info) {
  const Napi::Env env = info.Env();

  return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  PROG_NAME = "nodeaddon";
  exports.Set("setupInterface", Napi::Function::New(env, setupInterface));
  exports.Set("listDevices", Napi::Function::New(env, listDevices));
  exports.Set("parseWgDevice", Napi::Function::New(env, parseWgDevice));
  return exports;
}

NODE_API_MODULE(addon, Init);