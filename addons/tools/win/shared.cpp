#include <string>
#include <vector>
#include <wireguard-nt/include/wireguard.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <ws2def.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#include <iphlpapi.h>
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

LPCWSTR toLpcwstr(std::string s) {
  wchar_t* wString = new wchar_t[s.length()+1];
  MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, wString, s.length()+1);
  return wString;
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

void insertEndpoint(SOCKADDR_INET *endpoint, std::string value) {
	int ret, retries = parse_dns_retries();
	char *begin, *end;
  auto mmutable = strdup(value.c_str());
	if (!mmutable) throw std::string("strdup");
	if (!value.size()) {
    free(mmutable);
    throw std::string("Unable to parse empty endpoint");
  }
	if (mmutable[0] == '[') {
		begin = &mmutable[1];
		end = strchr(mmutable, ']');
		if (!end) {
      free(mmutable);
      throw std::string("Unable to find matching brace of endpoint: ").append(value);
    }
		*end++ = '\0';
		if (*end++ != ':' || !*end) {
      free(mmutable);
      throw std::string("Unable to find port of endpoint: ").append(value);
    }
	} else {
		begin = mmutable;
		end = strrchr(mmutable, ':');
		if (!end || !*(end + 1)) {
      free(mmutable);
      throw std::string("Unable to find port of endpoint: ").append(value);
    }
		*end++ = '\0';
	}


	ADDRINFOA *resolved;
	// #define min(a, b) ((a) < (b) ? (a) : (b))
	for (unsigned int timeout = 1000000;; timeout = ((20000000) < (timeout * 6 / 5) ? (20000000) : (timeout * 6 / 5))) {
		// ret = getaddrinfo(begin, end, &hints, &resolved);
		ret = getaddrinfo(begin, end, NULL, &resolved);
		if (!ret) break;
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
			throw std::string("Error code: ").append(std::to_string(ret));
		}
    std::this_thread::sleep_for(std::chrono::microseconds(timeout));
	}

	if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(SOCKADDR_IN))) memcpy(&endpoint->Ipv4, resolved->ai_addr, resolved->ai_addrlen);
  else if (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(SOCKADDR_IN6)) memcpy(&endpoint->Ipv6, resolved->ai_addr, resolved->ai_addrlen);
	else {
		freeaddrinfo(resolved);
		throw std::string("Neither IPv4 nor IPv6 address found: ").append(value);
	}
	freeaddrinfo(resolved);
  free(mmutable);
}

std::string parseEndpoint(SOCKADDR_INET *input) {
  if (!(input->si_family == AF_INET || input->si_family == AF_INET6)) return "";
  char saddr[INET6_ADDRSTRLEN];
  input->si_family == AF_INET ? inet_ntop(AF_INET, &input->Ipv4.sin_addr, saddr, INET_ADDRSTRLEN) : inet_ntop(AF_INET6, &input->Ipv6.sin6_addr, saddr, INET6_ADDRSTRLEN);

  if (input->si_family == AF_INET6) return std::string("[").append(saddr).append("]:").append(std::to_string(htons(input->Ipv6.sin6_port)));
  return std::string(saddr).append(":").append(std::to_string(htons(input->Ipv4.sin_port)));
}

std::string insertIpAddr(NET_LUID InterfaceLuid, std::string IPv4, std::string IPv6) {
  NET_IFINDEX ind;
  if (ConvertInterfaceLuidToIndex(&InterfaceLuid, &ind) != NO_ERROR) return "Cannot get interface index";

  // IPv4
  if (IPv4.size() > 0) {
    ULONG NTEContext = 0;
    ULONG NTEInstance = 0;
    UINT iaIPAddress;
    inet_pton(AF_INET, IPv4.c_str(), &iaIPAddress);
    auto status = AddIPAddress(iaIPAddress, NULL, ind, &NTEContext, &NTEInstance);
    if (status != NO_ERROR) {
      if (status == 5010) {
      } else return std::string("Cannot set IPv4 interface, error code: ").append(std::to_string(status));
    }
  }

  // IPv6
  if (IPv6.size() > 0) {
    UINT iaIPAddress;
    inet_pton(AF_INET6, IPv6.c_str(), &iaIPAddress);
    std::cerr << "Current not support IPv6 to set in interface!" << std::endl;
  }
  return "";
}

std::vector<std::string> getIpAddr(NET_LUID InterfaceLuid) {
  NET_IFINDEX ind;
  if (ConvertInterfaceLuidToIndex(&InterfaceLuid, &ind) != NO_ERROR) throw std::string("Cannot get interface index");
  std::vector<std::string> ips;

  IP_ADAPTER_INFO  *pAdapterInfo;
  ULONG ulOutBufLen;
  DWORD dwRetVal;
  pAdapterInfo = (IP_ADAPTER_INFO *) malloc( sizeof(IP_ADAPTER_INFO) );
  ulOutBufLen = sizeof(IP_ADAPTER_INFO);
  if (GetAdaptersInfo( pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
    free (pAdapterInfo);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc ( ulOutBufLen );
  }
  if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) != ERROR_SUCCESS) throw std::string("GetAdaptersInfo call failed with ").append(std::to_string(dwRetVal));
  PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
  while (pAdapter) {
    if (pAdapter->Index == ind) ips.push_back(std::string(pAdapter->IpAddressList.IpAddress.String).append("/32"));
    pAdapter = pAdapter->Next;
  }
  if (pAdapterInfo) free(pAdapterInfo);

  return ips;
}
