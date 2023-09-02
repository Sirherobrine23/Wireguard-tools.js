#include <napi.h>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include "wginterface.hh"
#include "win/set_ip.cpp"
#define IFNAMSIZ 64

unsigned long maxName() {
  return IFNAMSIZ;
}

void listDevices::Execute() {
  SetNetworkAddressIPv4({"192.168.1.1"});
  std::vector<std::string> arrayPrefix;
  arrayPrefix.push_back("ProtectedPrefix\\Administrators\\WireGuard\\");
  arrayPrefix.push_back("WireGuard\\");

  WIN32_FIND_DATA find_data;
  HANDLE find_handle;
  int ret = 0;
  for (auto & preit : arrayPrefix) {
    ret = 0;
    find_handle = FindFirstFile("\\\\.\\pipe\\*", &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) return SetError("Invalid Handler");

    char *iface;
    do {
      if (strncmp(preit.c_str(), find_data.cFileName, strlen(preit.c_str()))) continue;
      iface = find_data.cFileName + strlen(preit.c_str());
      deviceNames.push_back(iface);
    } while (FindNextFile(find_handle, &find_data));
    FindClose(find_handle);
    if (ret < 0) {
      std::string err = "Erro code: ";
      err = err.append(std::to_string(ret));
      return SetError(err);
    }
  }
}

void setConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void getConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void deleteInterface::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}