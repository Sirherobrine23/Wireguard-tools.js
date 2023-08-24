import path from "path";
const addonKeyGen = (require("../../libs/prebuildifyLoad.cjs"))("keygen", path.join(__dirname, "../.."));
export type keyObject = {private: string, public: string};
export type keyObjectPreshered = keyObject & {preshared: string};

/**
 * Create a pre-shared key quickly by returning a string with the base64 of the key.
 *
 */
export async function genPresharedAsync(): Promise<string> {
  return new Promise((done, reject) => addonKeyGen["presharedKeyAsync"]((err, key) => err ? reject(err) : done(key)));
}

/**
 * Create a Private key returning its base64.
 *
 */
export async function genPrivateAsync(): Promise<string> {
  return new Promise((done, reject) => addonKeyGen["genPrivateKeyAsync"]((err, key) => err ? reject(err) : done(key)));
}

/**
 * Create your public key from a private key.
 *
 */
export function genPublicAsync(privateKey: string): Promise<string> {
  return new Promise((done, reject) => addonKeyGen["getPublicKeyAsync"](privateKey, (err, key) => err ? reject(err) : done(key)));
}


/**
 * Generate Wireguard keys withou preshared key
 */
export async function keygenAsync(): Promise<keyObject>;

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export async function keygenAsync(genPreshared: false): Promise<keyObject>;

/**
 * Generate Wireguard keys with pershared key.
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export async function keygenAsync(genPreshared: true): Promise<keyObjectPreshered>;

/**
 * Generate Wireguard keys without preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export async function keygenAsync(genPresharedKey: boolean = false): Promise<keyObject|keyObjectPreshered> {
  const keys = await genPrivateAsync().then(async privateKey => genPublicAsync(privateKey).then(pub => ({ private: privateKey, public: pub })));;
  if (!genPresharedKey) return keys;
  return genPresharedAsync().then(preshared => Object.assign(keys, {preshared}));
}

/**
 * Create a pre-shared key quickly by returning a string with the base64 of the key.
 * @deprecated use genPresharedAsync, in future are remove
 */
export function genPreshared(): string {
  return addonKeyGen.presharedKey();
}

/**
 * Create a Private key returning its base64.
 * @deprecated use genPrivateAsync, in future are remove
 */
export function genPrivate(): string {
  return addonKeyGen.genPrivateKey();
}

/**
 * Create your public key from a private key.
 * @deprecated use genPublicAsync, in future are remove
 */
export function genPublic(privateKey: string): string {
  if (typeof privateKey !== "string") throw new Error("privateKey must be a string");
  else if (privateKey.length > 44||44 > privateKey.length) throw new Error(`Invalid private key length (44), you length: (${privateKey.length})`);
  return addonKeyGen.getPublicKey(privateKey);
}

/**
 * Generate Wireguard keys withou preshared key
 * @deprecated use keygenAsync, in future are remove
 */
export function keygen(): keyObject;

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 * @deprecated use keygenAsync, in future are remove
 */
export function keygen(genPreshared: false): keyObject;

/**
 * Generate Wireguard keys with pershared key.
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 * @deprecated use keygenAsync, in future are remove
 */
export function keygen(genPreshared: true): keyObjectPreshered;

/**
 * Generate Wireguard keys without preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 * @deprecated use keygenAsync, in future are remove
 */
export function keygen(genPresharedKey: boolean = false): keyObject|keyObjectPreshered {
  const privateKey = genPrivate();
  const publicKey = genPublic(privateKey);
  if (!genPresharedKey) return { private: privateKey, public: publicKey };
  return {
    private: privateKey,
    public: publicKey,
    preshared: genPreshared()
  };
}