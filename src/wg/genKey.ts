import * as crypto from "node:crypto";

const randomKeys = () => new Promise<{privateKey: string, publicKey: string}>((res, rej) => crypto.generateKeyPair("x25519", {publicKeyEncoding: {format: "der", type: "spki"}, privateKeyEncoding: {format: "der", type: "pkcs8"}}, (err: Error, publicKey: Buffer, privateKey: Buffer) => {
  if (err) rej(err);
  else res({
    privateKey: Buffer.from(privateKey.slice(16)).toString("base64"),
    publicKey: Buffer.from(publicKey.slice(12)).toString("base64")
  });
}));

export type keyObject = {private: string, public: string};
export type keyObjectPreshered = keyObject & {preshared: string};

export default function CreateKey(genPreshared: true): Promise<keyObjectPreshered>;
export default function CreateKey(genPreshared: false): Promise<keyObject>;

export default async function CreateKey(genPreshared: boolean = false): Promise<keyObject|keyObjectPreshered> {
  const key = await randomKeys();
  if (genPreshared) {
    return {
      private: key.privateKey,
      public: key.publicKey,
      preshared: (await randomKeys()).privateKey
    };
  }
  return {
    private: key.privateKey,
    public: key.publicKey
  };
}
