#include <string>
#include <vector>
#include <ws2ipdef.h>
#include <ws2def.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <chrono>
#include <thread>

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

bool parseEndpoint(SOCKADDR_INET *endpoint, const char *value) {
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
		return false;
	}
	if (!strlen(value)) {
		free(mmutable);
		fprintf(stderr, "Unable to parse empty endpoint\n");
		return false;
	}
	if (mmutable[0] == '[') {
		begin = &mmutable[1];
		end = strchr(mmutable, ']');
		if (!end) {
			free(mmutable);
			fprintf(stderr, "Unable to find matching brace of endpoint: `%s'\n", value);
			return false;
		}
		*end++ = '\0';
		if (*end++ != ':' || !*end) {
			free(mmutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
			return false;
		}
	} else {
		begin = mmutable;
		end = strrchr(mmutable, ':');
		if (!end || !*(end + 1)) {
			free(mmutable);
			fprintf(stderr, "Unable to find port of endpoint: `%s'\n", value);
			return false;
		}
		*end++ = '\0';
	}

	#define min(a, b) ((a) < (b) ? (a) : (b))
	for (unsigned int timeout = 1000000;; timeout = min(20000000, timeout * 6 / 5)) {
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
			return false;
		}
		// fprintf(stderr, "%s: `%s'. Trying again in %.2f seconds...\n", ret == EAI_SYSTEM ? strerror(errno) : gai_strerror(ret), value, timeout / 1000000.0);
		std::this_thread::sleep_for(std::chrono::microseconds(timeout));
	}

	if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
	    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
		memcpy(endpoint, resolved->ai_addr, resolved->ai_addrlen);
	else {
		freeaddrinfo(resolved);
		free(mmutable);
		fprintf(stderr, "Neither IPv4 nor IPv6 address found: `%s'\n", value);
		return false;
	}
	freeaddrinfo(resolved);
	free(mmutable);
	return true;
}