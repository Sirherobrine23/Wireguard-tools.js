#include <string>
#include <vector>
#include <windows.h>
#include <ws2ipdef.h>
#include <ws2def.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <thread>

// Function to check if the current user has administrator privileges
bool IsRunAsAdmin()
{
  BOOL fRet = FALSE;
  HANDLE hToken = NULL;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
      fRet = Elevation.TokenIsElevated;
    }
  }
  if (hToken) CloseHandle(hToken);
  return !!fRet;
}

int parse_dns_retries() {
  unsigned long ret;
  char *retries = getenv("WG_ENDPOINT_RESOLUTION_RETRIES"), *end;

  if (!retries) return 15;
  if (!strcmp(retries, "infinity")) return -1;

  ret = strtoul(retries, &end, 10);
  if (*end || ret > INT_MAX) {
    fprintf(stderr, "Unable to parse WG_ENDPOINT_RESOLUTION_RETRIES: `%s'\n", retries);
    exit(1);
  }
  return (int)ret;
}

void parseEndpoint(SOCKADDR_INET *endpoint, const char *value) {
  char *mmutable = strdup(value);
  char *begin, *end;
  int ret, retries = parse_dns_retries();
  addrinfo *resolved;
  addrinfo hints;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  if (!mmutable) {
    perror("strdup");
    throw std::string("Cannot convert to char*");
  }
  if (!strlen(value)) {
    free(mmutable);
    throw std::string("Unable to parse empty endpoint");
  }
  if (mmutable[0] == '[') {
    begin = &mmutable[1];
    end = strchr(mmutable, ']');
    if (!end) {
      free(mmutable);
      throw std::string("Unable to find matching brace of endpoint: '").append(value).append("'");
    }
    *end++ = '\0';
    if (*end++ != ':' || !*end) {
      free(mmutable);
      throw std::string("Unable to find port of endpoint: '").append(value).append("'");
    }
  } else {
    begin = mmutable;
    end = strrchr(mmutable, ':');
    if (!end || !*(end + 1)) {
      free(mmutable);
      throw std::string("Unable to find port of endpoint: '").append(value).append("'");
    }
    *end++ = '\0';
  }

  // #define min(a, b) ((a) < (b) ? (a) : (b))
  for (unsigned int timeout = 1000000;; timeout = ((20000000) < (timeout * 6 / 5) ? (20000000) : (timeout * 6 / 5))) {
    ret = getaddrinfo(begin, end, &hints, &resolved);
    if (!ret)
      break;
    /* The set of return codes that are "permanent failures". All other possibilities are potentially transient.
     *
     * This is according to https://sourceware.org/glibc/wiki/NameResolver which states:
     *	"From the perspective of the application that calls getaddrinfo() it perhaps
     *	 doesn't matter that much since EAI_FAIL, EAI_NONAME and EAI_NODATA are all
     *	 permanent failure codes and the causes are all permanent failures in the
     *	 sense that there is no point in retrying later."
     *
     * So this is what we do, except FreeBSD removed EAI_NODATA some time ago, so that's conditional.
     */
    if (ret == EAI_NONAME || ret == EAI_FAIL ||
      #ifdef EAI_NODATA
        ret == EAI_NODATA ||
      #endif
        (retries >= 0 && !retries--)) {
      free(mmutable);
      // fprintf(stderr, "%s: `%s'\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value);
      throw std::string(ret == -11 ? strerror(errno) : gai_strerror(ret)).append(": '").append(value).append("'");
    }
    // fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value, timeout / 1000000.0);
    std::this_thread::sleep_for(std::chrono::microseconds(timeout));
  }
  if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) || (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6))) memcpy(endpoint, resolved->ai_addr, resolved->ai_addrlen);
  else {
    freeaddrinfo(resolved);
    free(mmutable);
    fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s'\n", value);
    throw std::string("Neither IPv4 nor IPv6 address found: '").append(value).append("'");
  }
  freeaddrinfo(resolved);
  free(mmutable);
}