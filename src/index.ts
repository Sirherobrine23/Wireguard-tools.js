export * from "./wginterface";
import * as wginterface from "./wginterface";
import * as key from "./key";
export { key };

export default Object.assign({}, wginterface, { key });