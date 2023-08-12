#include <stdint.h>
#include <errno.h>

typedef uint8_t wg_key[32];
typedef char wg_key_b64_string[((sizeof(wg_key) + 2) / 3) * 4 + 1];

void wg_key_to_base64(wg_key_b64_string base64, const wg_key key);
int wg_key_from_base64(wg_key key, const wg_key_b64_string base64);