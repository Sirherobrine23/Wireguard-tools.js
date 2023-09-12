import { randomInt } from "crypto";
import keyGem from "./keygen.js";
const {
  genPreshared,
  genPrivate,
  genPublic,
  keygen
} = keyGem;

const keysToGen = Array(randomInt(10, 8 ** 3)).fill(null);

// Async
describe("Wireguard generate keys Async", function() {
  it("Preshared", async () => genPreshared());
  it("Private", async () => genPrivate());
  it("Public", async () => genPublic(await genPrivate()));
  it("Generate keys without preshared", async () => keygen());
  it("Generate keys with preshared", async () => keygen(true));
  it(`Random keys ${keysToGen.length} with preshared`, () => Promise.all(keysToGen.map(async () => keygen(true))));
  it(`Random keys ${keysToGen.length} without preshared`, () => Promise.all(keysToGen.map(async () => keygen())));
});