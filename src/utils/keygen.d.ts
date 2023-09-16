export type keyObject = {privateKey: string, publicKey: string};
export type keyObjectPreshered = keyObject & {presharedKey: string};

export const keysConstants: { WG_KEY_LENGTH: number, B64_WG_KEY_LENGTH: number };
export function genPreshared(): Promise<string>;
export function genPrivate(): Promise<string>;
export function genPublic(privateKey: string): Promise<string>;

/**
 * Generate Wireguard keys withou preshared key
 */
export function keygen(): Promise<keyObject>;

/**
 * Generate Wireguard keys withou preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export function keygen(genPreshared: false): Promise<keyObject>;

/**
 * Generate Wireguard keys with pershared key.
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
export function keygen(genPreshared: true): Promise<keyObjectPreshered>;
export function keygen(genPresharedKey?: boolean): Promise<keyObject|keyObjectPreshered>