// Base
#include <napi.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/socket.h>
#include <unistd.h>
#elif _WIN32
// Sets getentropy in windows
#include <windows.h>
#include <wincrypt.h>
int getentropy(void *buf, size_t len) {
  HCRYPTPROV prov;
  if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    CryptGenRandom(prov, len, (BYTE*)&buf);
    CryptReleaseContext(prov, 0);
    return true;
  }
  errno = EIO;
  return errno;
  //throw std::runtime_error("getentropy failed");
}
#endif


typedef uint8_t wg_key[32];
typedef char wg_key_b64_string[((sizeof(wg_key) + 2) / 3) * 4 + 1];
typedef int64_t fe[16];
static void encode_base64(char dest[4], const uint8_t src[3]) {
  const uint8_t input[] = {
    static_cast<uint8_t>((src[0] >> 2) & 63),
    static_cast<uint8_t>(((src[0] << 4) | (src[1] >> 4)) & 63),
    static_cast<uint8_t>(((src[1] << 2) | (src[2] >> 6)) & 63),
    static_cast<uint8_t>(src[2] & 63)
  };
  unsigned int i;
  for (i = 0; i < 4; ++i) dest[i] = input[i] + 'A' + (((25 - input[i]) >> 8) & 6) - (((51 - input[i]) >> 8) & 75) - (((61 - input[i]) >> 8) & 15) + (((62 - input[i]) >> 8) & 3);
}

void keyToBase64(wg_key_b64_string base64, const wg_key key) {
  unsigned int i;

  for (i = 0; i < 32 / 3; ++i) encode_base64(&base64[i * 4], &key[i * 3]);
  const uint8_t tempKey[3] = { key[i * 3 + 0], key[i * 3 + 1], 0 };
  encode_base64(&base64[i * 4], tempKey);
  base64[sizeof(wg_key_b64_string) - 2] = '=';
  base64[sizeof(wg_key_b64_string) - 1] = '\0';
}

static int decodeBase64(const char src[4]) {
  int val = 0;
  unsigned int i;

  for (i = 0; i < 4; ++i) val |= (-1 + ((((('A' - 1) - src[i]) & (src[i] - ('Z' + 1))) >> 8) & (src[i] - 64)) + ((((('a' - 1) - src[i]) & (src[i] - ('z' + 1))) >> 8) & (src[i] - 70)) + ((((('0' - 1) - src[i]) & (src[i] - ('9' + 1))) >> 8) & (src[i] + 5)) + ((((('+' - 1) - src[i]) & (src[i] - ('+' + 1))) >> 8) & 63) + ((((('/' - 1) - src[i]) & (src[i] - ('/' + 1))) >> 8) & 64)) << (18 - 6 * i);
  return val;
}

int keyFromBase64(wg_key key, const wg_key_b64_string base64) {
  unsigned int i;
  int val;
  volatile uint8_t ret = 0;

  if (strlen(base64) != sizeof(wg_key_b64_string) - 1 || base64[sizeof(wg_key_b64_string) - 2] != '=') {
    errno = EINVAL;
    return -errno;
  }

  for (i = 0; i < 32 / 3; ++i) {
    val = decodeBase64(&base64[i * 4]);
    ret |= (uint32_t)val >> 31;
    key[i * 3 + 0] = (val >> 16) & 0xff;
    key[i * 3 + 1] = (val >> 8) & 0xff;
    key[i * 3 + 2] = val & 0xff;
  }
  const char tempDecode[4] = {base64[i * 4 + 0], base64[i * 4 + 1], base64[i * 4 + 2], 'A'};
  val = decodeBase64(tempDecode);
  ret |= ((uint32_t)val >> 31) | (val & 0xff);
  key[i * 3 + 0] = (val >> 16) & 0xff;
  key[i * 3 + 1] = (val >> 8) & 0xff;
  errno = EINVAL & ~((ret - 1) >> 8);
  return -errno;
}

#ifdef _WIN32
static volatile void * (*memset_func)(void *, int, size_t) = (volatile void * (*)(void *, int, size_t))&memset;
void memzero_explicit(void *s, size_t count) {
	memset_func(s, 0, count);
}
#else
static __attribute__((noinline)) void memzero_explicit(void *s, size_t count) {
  memset(s, 0, count);
  __asm__ __volatile__("": :"r"(s) :"memory");
}
#endif

static void carry(fe o) {
  int i;

  for (i = 0; i < 16; ++i) {
    o[(i + 1) % 16] += (i == 15 ? 38 : 1) * (o[i] >> 16);
    o[i] &= 0xffff;
  }
}

static void cswap(fe p, fe q, int b) {
  int i;
  int64_t t, c = ~(b - 1);

  for (i = 0; i < 16; ++i) {
    t = c & (p[i] ^ q[i]);
    p[i] ^= t;
    q[i] ^= t;
  }

  memzero_explicit(&t, sizeof(t));
  memzero_explicit(&c, sizeof(c));
  memzero_explicit(&b, sizeof(b));
}

static void pack(uint8_t *o, const fe n) {
  int i, j, b;
  fe m, t;

  memcpy(t, n, sizeof(t));
  carry(t);
  carry(t);
  carry(t);
  for (j = 0; j < 2; ++j) {
    m[0] = t[0] - 0xffed;
    for (i = 1; i < 15; ++i) {
      m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
      m[i - 1] &= 0xffff;
    }
    m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
    b = (m[15] >> 16) & 1;
    m[14] &= 0xffff;
    cswap(t, m, 1 - b);
  }
  for (i = 0; i < 16; ++i) {
    o[2 * i] = t[i] & 0xff;
    o[2 * i + 1] = t[i] >> 8;
  }

  memzero_explicit(m, sizeof(m));
  memzero_explicit(t, sizeof(t));
  memzero_explicit(&b, sizeof(b));
}

static void add(fe o, const fe a, const fe b) {
  int i;
  for (i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void subtract(fe o, const fe a, const fe b) {
  int i;
  for (i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void multmod(fe o, const fe a, const fe b) {
  int i, j;
  int64_t t[31] = { 0 };
  for (i = 0; i < 16; ++i) {
    for (j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
  }
  for (i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
  memcpy(o, t, sizeof(fe));
  carry(o);
  carry(o);
  memzero_explicit(t, sizeof(t));
}

static void invert(fe o, const fe i) {
  fe c;
  int a;
  memcpy(c, i, sizeof(c));
  for (a = 253; a >= 0; --a) {
    multmod(c, c, c);
    if (a != 2 && a != 4) multmod(c, c, i);
  }
  memcpy(o, c, sizeof(fe));
  memzero_explicit(c, sizeof(c));
}


void generatePreshared(wg_key preshared_key) {
  size_t ret;
  size_t i;
  int fd;
  #if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
  if (!getentropy(preshared_key, sizeof(wg_key))) return;
  #elif defined(__NR_getrandom) && defined(__linux__)
  if (syscall(__NR_getrandom, preshared_key, sizeof(wg_key), 0) == sizeof(wg_key)) return;
  #elif _WIN32
  if (!getentropy(preshared_key, sizeof(wg_key))) return;
  #elif defined(open)
  fd = open("/dev/urandom", O_RDONLY);
  assert(fd >= 0);
  for (i = 0; i < sizeof(wg_key); i += ret) {
    ret = read(fd, preshared_key + i, sizeof(wg_key) - i);
    assert(ret > 0);
  }
  close(fd);
  #endif
}

static void clamp_key(uint8_t *z) {
  z[31] = (z[31] & 127) | 64;
  z[0] &= 248;
}

void generatePrivate(wg_key private_key) {
  generatePreshared(private_key);
  clamp_key(private_key);
}

void generatePublic(wg_key public_key, const wg_key private_key) {
  int i, r;
  uint8_t z[32];
  fe a = { 1 }, b = { 9 }, c = { 0 }, d = { 1 }, e, f;

  memcpy(z, private_key, sizeof(z));
  clamp_key(z);

  for (i = 254; i >= 0; --i) {
    r = (z[i >> 3] >> (i & 7)) & 1;
    cswap(a, b, r);
    cswap(c, d, r);
    add(e, a, c);
    subtract(a, a, c);
    add(c, b, d);
    subtract(b, b, d);
    multmod(d, e, e);
    multmod(f, a, a);
    multmod(a, c, a);
    multmod(c, b, e);
    add(e, a, c);
    subtract(a, a, c);
    multmod(b, a, a);
    subtract(c, d, f);
    const fe abc = { 0xdb41, 1 };
    multmod(a, c, abc);
    add(a, a, d);
    multmod(c, c, a);
    multmod(a, d, f);
    const fe abc2 = { 9 };
    multmod(d, b, abc2);
    multmod(b, e, e);
    cswap(a, b, r);
    cswap(c, d, r);
  }
  invert(c, c);
  multmod(a, a, c);
  pack(public_key, a);

  memzero_explicit(&r, sizeof(r));
  memzero_explicit(z, sizeof(z));
  memzero_explicit(a, sizeof(a));
  memzero_explicit(b, sizeof(b));
  memzero_explicit(c, sizeof(c));
  memzero_explicit(d, sizeof(d));
  memzero_explicit(e, sizeof(e));
  memzero_explicit(f, sizeof(f));
}

namespace gereneate_Keys {
  Napi::Value presharedKey(const Napi::CallbackInfo& info) {
    wg_key interfacePresharedKey;
    generatePreshared(interfacePresharedKey);
    wg_key_b64_string pskString;
    keyToBase64(pskString, interfacePresharedKey);
    return Napi::String::New(info.Env(), pskString);
  }

  Napi::Value privateKey(const Napi::CallbackInfo& info) {
    wg_key interfacePublicKey;
    generatePrivate(interfacePublicKey);
    wg_key_b64_string privString;
    keyToBase64(privString, interfacePublicKey);
    return Napi::String::New(info.Env(), privString);
  }

  Napi::Value publicKey(const Napi::CallbackInfo& info) {
    const Napi::String privKey = info[0].As<Napi::String>();
    if (privKey.IsEmpty()) return Napi::String::New(info.Env(), "Invalid private key");

    // base64 to wg_key
    wg_key interfacePrivateKey;
    keyFromBase64(interfacePrivateKey, privKey.Utf8Value().c_str());

    // Create public key
    wg_key interfacePublicKey;
    generatePublic(interfacePublicKey, interfacePrivateKey);

    // Convert to base64
    wg_key_b64_string pubString;
    keyToBase64(pubString, interfacePublicKey);

    // Return public key
    return Napi::String::New(info.Env(), pubString);
  }
}

Napi::Object initKeyGen(Napi::Env env) {
  const Napi::Object keyGen = Napi::Object::New(env);
    keyGen.Set("presharedKey", Napi::Function::New(env, gereneate_Keys::presharedKey));
    keyGen.Set("genPrivateKey", Napi::Function::New(env, gereneate_Keys::privateKey));
    keyGen.Set("getPublicKey", Napi::Function::New(env, gereneate_Keys::publicKey));
  return keyGen;
}