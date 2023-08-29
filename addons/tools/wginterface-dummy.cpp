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
void deleteInterface::Execute() {}
void setConfig::Execute() {}
void getConfig::Execute() {}