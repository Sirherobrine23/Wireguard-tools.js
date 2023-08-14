import path from "path";
const addonKeyGen = (require("../../libs/prebuildifyLoad.cjs"))(path.join(__dirname, "../.."), "keygen");
export type keyObject = {private: string, public: string};
export type keyObjectPreshered = keyObject & {preshared: string};

/**
 * Create a pre-shared key quickly by returning a string with the base64 of the key.
 *
*/
export function genPresharedKey(): string {
  return addonKeyGen.presharedKey();
}

/**
 * Create a Private key returning its base64.
 *
*/
export function genPrivateKey(): string {
  return addonKeyGen.genPrivateKey();
}

/**
 * Create your public key from a private key.
 *
*/
export function genPublicKey(privateKey: string): string {
  if (typeof privateKey !== "string") throw new Error("privateKey must be a string");
  else if (privateKey.length > 44||44 > privateKey.length) throw new Error(`Invalid private key length (44), you length: (${privateKey.length})`);
  return addonKeyGen.getPublicKey(privateKey);
}

/**
 * Generate Wireguard keys withou preshared key
 */
export function keygen(): keyObject;

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export function keygen(genPreshared: false): keyObject;

/**
 * Generate Wireguard keys with pershared key.
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export function keygen(genPreshared: true): keyObjectPreshered;

/**
 * Generate Wireguard keys without preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export function keygen(genPreshared: boolean = false): keyObject|keyObjectPreshered {
  const privateKey = genPrivateKey();
  const publicKey = genPublicKey(privateKey);
  if (!genPreshared) return {
    private: privateKey,
    public: publicKey
  };
  return {
    private: privateKey,
    public: publicKey,
    preshared: genPresharedKey()
  };
}