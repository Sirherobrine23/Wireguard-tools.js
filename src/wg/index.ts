export type { wgInterface as wgInterfaceStatus, peerInfo as peerInfoStatus } from "./getStatus";
export type { keyObject, keyObjectPreshered } from "./genKey";
import getStatus from "./getStatus";
import genKey from "./genKey";
import syncInterface from "./updateInterface";
export {genKey, getStatus, syncInterface};