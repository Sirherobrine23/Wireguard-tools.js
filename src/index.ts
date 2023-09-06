export * as utils from "./utils/index";
export * from "./wginterface";

import SegfaultHandler from "segfault-handler";
SegfaultHandler.registerHandler("crash.log");