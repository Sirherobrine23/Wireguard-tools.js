// Parse config
export * as config from "./config";

// IPs utils
export * as nodeCidr4 from "../lib/nodeCidr4";
export * as nodeCidr6 from "../lib/nodeCidr6";

// Export types fist before export functions
export { keygen, genPresharedKey, genPrivateKey, genPublicKey, keyObject, keyObjectPreshered } from "./keygen";
