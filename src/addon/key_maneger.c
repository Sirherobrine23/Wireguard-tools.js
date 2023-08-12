#include <stdint.h>
#include <errno.h>
#include "key_maneger.h"

void encode_base64(char dest[4], const uint8_t src[3]) {
	const uint8_t input[] = { (src[0] >> 2) & 63, ((src[0] << 4) | (src[1] >> 4)) & 63, ((src[1] << 2) | (src[2] >> 6)) & 63, src[2] & 63 };
	unsigned int i;

	for (i = 0; i < 4; ++i) dest[i] = input[i] + 'A' + (((25 - input[i]) >> 8) & 6) - (((51 - input[i]) >> 8) & 75) - (((61 - input[i]) >> 8) & 15) + (((62 - input[i]) >> 8) & 3);
}

void wg_key_to_base64(wg_key_b64_string base64, const wg_key key) {
	unsigned int i;

	for (i = 0; i < 32 / 3; ++i) encode_base64(&base64[i * 4], &key[i * 3]);
	encode_base64(&base64[i * 4], (const uint8_t[]){ key[i * 3 + 0], key[i * 3 + 1], 0 });
	base64[sizeof(wg_key_b64_string) - 2] = '=';
	base64[sizeof(wg_key_b64_string) - 1] = '\0';
}

int decode_base64(const char src[4]) {
	int val = 0;
	unsigned int i;

	for (i = 0; i < 4; ++i) val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)) << (18 - 6 * i);
	return val;
}

int wg_key_from_base64(wg_key key, const wg_key_b64_string base64) {
	unsigned int i;
	int val;
	volatile uint8_t ret = 0;

	if (strlen(base64) != sizeof(wg_key_b64_string) - 1 || base64[sizeof(wg_key_b64_string) - 2] != '=') {
		errno = EINVAL;
		goto out;
	}

	for (i = 0; i < 32 / 3; ++i) {
		val = decode_base64(&base64[i * 4]);
		ret |= (uint32_t)val >> 31;
		key[i * 3 + 0] = (val >> 16) & 0xff;
		key[i * 3 + 1] = (val >> 8) & 0xff;
		key[i * 3 + 2] = val & 0xff;
	}
	val = decode_base64((const char[]){ base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A' });
	ret |= ((uint32_t)val >> 31) | (val & 0xff);
	key[i * 3 + 0] = (val >> 16) & 0xff;
	key[i * 3 + 1] = (val >> 8) & 0xff;
	errno = EINVAL & ~((ret - 1) >> 8);
out:
	return -errno;
}