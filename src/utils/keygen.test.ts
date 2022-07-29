import { keygen as keyGen } from "./keygen";

export default async function main() {
  const keyWithoutPre = await keyGen();
  const keyWithPre = await keyGen(true);
  console.log({
    keyWithPre,
    keyWithoutPre
  });
  if (keyWithoutPre["preshared"] !== undefined && typeof keyWithPre.preshared !== "string") throw new Error("Invalid");
}