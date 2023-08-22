import {
  genPreshared, genPresharedAsync,
  genPrivate, genPrivateAsync,
  genPublic, genPublicAsync,
  keygen, keygenAsync
} from "./keygen";

const keysToGen = Array(8 ** 3).fill(null);

// Async
describe("Wireguard generate keys Async", function() {
  it("Preshared", async () => genPresharedAsync());
  it("Private", async () => genPrivateAsync());
  it("Public", async () => genPublicAsync(await genPrivateAsync()));
  it("Generate keys without preshared", async () => keygenAsync());
  it("Generate keys with preshared", async () => keygenAsync(true));
  it(`Random keys ${keysToGen.length} with preshared`, () => Promise.all(keysToGen.map(async () => keygenAsync(true))));
  it(`Random keys ${keysToGen.length} without preshared`, () => Promise.all(keysToGen.map(async () => keygenAsync())));
});

describe("Wireguard generate keys Sync", function() {
  it("Preshared", () => genPreshared());
  it("Private", () => genPrivate());
  it("Public", () => genPublic(genPrivate()));
  it("Generate keys without preshared", () => keygen());
  it("Generate keys with preshared", () => keygen(true));
  it(`Random keys ${keysToGen.length} with preshared`, () => keysToGen.map(() => keygen(true)));
  it(`Random keys ${keysToGen.length} without preshared`, () => keysToGen.map(() => keygen()));
});