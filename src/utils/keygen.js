const path = require("path");
const addonKeyGen = (require("../../libs/prebuildifyLoad.cjs"))("keygen", path.join(__dirname, "../.."));
module.exports = { genPreshared, genPrivate, genPublic, keygen }

/**
 * Create a pre-shared key quickly by returning a string with the base64 of the key.
 *
 */
async function genPreshared() {
  return new Promise((done, reject) => addonKeyGen["presharedKeyAsync"]((err, key) => err ? reject(err) : done(key)));
}

/**
 * Create a Private key returning its base64.
 *
 */
async function genPrivate() {
  return new Promise((done, reject) => addonKeyGen["genPrivateKeyAsync"]((err, key) => err ? reject(err) : done(key)));
}

/**
 * Create your public key from a private key.
 *
 */
function genPublic(privateKey) {
  return new Promise((done, reject) => addonKeyGen["getPublicKeyAsync"](privateKey, (err, key) => err ? reject(err) : done(key)));
}

/**
 * Generate Wireguard keys without preshared key
 *
 * @param genPreshared - In object includes Preshared key, defaults is `false`
 */
async function keygen(genPresharedKey = false) {
  const keys = await genPrivate().then(async privateKey => genPublic(privateKey).then(pub => ({ private: privateKey, public: pub })));;
  if (!genPresharedKey) return keys;
  return genPreshared().then(preshared => Object.assign(keys, {preshared}));
}