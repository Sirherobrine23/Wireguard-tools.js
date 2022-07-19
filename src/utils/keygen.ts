import * as crypto from "node:crypto";
async function cryptoCreateKey() {
  return new Promise<{privateKey: string, publicKey: string}>((res, rej) => {
    return crypto.generateKeyPair("x25519", {publicKeyEncoding: {format: "der", type: "spki"}, privateKeyEncoding: {format: "der", type: "pkcs8"}}, (err: Error, publicKey: Buffer, privateKey: Buffer) => {
      if (err) rej(err);
      else res({
        privateKey: Buffer.from(privateKey.subarray(16)).toString("base64"),
        publicKey: Buffer.from(publicKey.subarray(12)).toString("base64")
      });
    });
  });
}

export type keyObject = {private: string, public: string};
export type keyObjectPreshered = keyObject & {preshared: string};

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export default function CreateKey(): Promise<keyObject>;

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export default function CreateKey(genPreshared: false): Promise<keyObject>;

/**
 * Generate Wireguard keys with pershared key.
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export default function CreateKey(genPreshared: true): Promise<keyObjectPreshered>;

/**
 * Generate Wireguard keys without preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export default async function CreateKey(genPreshared: boolean = false): Promise<keyObject|keyObjectPreshered> {
  const key = await cryptoCreateKey();
  if (genPreshared) {
    return {
      private: key.privateKey,
      public: key.publicKey,
      preshared: (await cryptoCreateKey()).privateKey
    };
  }
  return {
    private: key.privateKey,
    public: key.publicKey
  };
}