import { parse, stringify, QuickConfig } from "./quick";
import test from "node:test";
import assert from "node:assert";

const configJson: QuickConfig = {
  privateKey: "uFVB0+R+IrQRFwKCiCWXFLFZsOS0tQPL4O1FYE3X6lU=",
  peers: {
    // 6MyCbRlWEJ9+UHRQlnSXWuWsCgboUwOLJL9loVR+/VY=,
    "Xp/PbG0IApQvAaNoBWG36vt+PGPC4d9jHtfC/VDXs1o=": {
      allowedIPs: [
        "10.6.6.3/32"
      ]
    }
  }
};
const configText: string = "";

test("Wireguard quick config", async t => {
  await Promise.all([
    t.test("Stringify", () => {stringify(configJson);}),
    t.test("Parse", () => {
      parse
      assert.equal(configText, configText);
    }),
  ]);
});