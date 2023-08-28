#include <napi.h>
#include <wginterface.hh>

#ifdef _WIN32
#define IFNAMSIZ 64
#else
#include <net/if.h>
#endif

unsigned long maxName() {
  return IFNAMSIZ;
}

void listDevices::Execute() {}

void setConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}

void getConfig::Execute() {
  SetError("Use userpace implementation, kernel only on linux!");
}