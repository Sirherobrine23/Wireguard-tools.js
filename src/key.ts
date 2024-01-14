export interface keyObject {
  privateKey: string;
  publicKey: string;
}

export interface keyObjectWithPreshared extends keyObject {
  presharedKey: string;
}

interface KeyAddon {
  constants: {
    WG_KEY_LENGTH: number;
    B64_WG_KEY_LENGTH: number;
  };

  /**
   * Generate preshared key
   */
  presharedKey(): Promise<string>;
  /**
   * Generate private key
   */
  privateKey(): Promise<string>;
  /**
   * Get public key from private key.
   * @param privateKey - Private key
   */
  publicKey(privateKey: string): Promise<string>;

  /**
   * Generate keys with Preshared key
   */
  genKey(presharedKey: true): Promise<keyObjectWithPreshared>;
  /**
   * Generate keys without Preshared key
   */
  genKey(presharedKey: false): Promise<keyObject>;
  /**
   * Generate keys without Preshared key
   */
  genKey(): Promise<keyObject>;
}

export const {
  constants,
  presharedKey,
  privateKey,
  publicKey,
  genKey
}: KeyAddon = require("../libs/prebuildifyLoad.cjs")("keygen");