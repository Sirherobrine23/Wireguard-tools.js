import * as os from "node:os";
import * as fs from "node:fs";
import execAsync from "../lib/childPromise";
import commandExists from "../lib/commandExists";

async function createInterface(wgInterface: string) {
  await execAsync("ip", ["link", "add", wgInterface], {}).catch(async () => {
    if (!fs.existsSync("/sys/module/wireguard")) {
      const wgGo = process.env.WG_QUICK_USERSPACE_IMPLEMENTATION||"wireguard-go";
      if (await commandExists(wgGo)) {
        console.log("Missing WireGuard kernel module. Falling back to slow userspace implementation")
        return execAsync(wgGo, [wgInterface], {});
      }
    }
    throw new Error("It wasn't create a wireguard interface, make sure it's installed!");
  });
}

export default async function up(wgInterface: string) {
  if (!!os.networkInterfaces()[wgInterface]) throw new Error("Interface alwere exist");
  await createInterface(wgInterface);
  throw new Error("Required wg works"); // TODO: complete wg command on add.
}