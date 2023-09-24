import * as key from "./key";
import * as wgQuick from "./quick";
import * as wginterface from "./wginterface";

export * from "./wginterface";
export { key, wgQuick, wginterface };
export default Object.assign({}, wginterface, { key, wgQuick, wginterface });