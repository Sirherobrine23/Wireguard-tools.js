import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as fsOld from "node:fs";
import * as parseConfig from "../lib/parseConfig";

export default async function getConfig(device: string): Promise<string> {
  const device_config = path.join("/etc/wireguard", `${device}.conf`);
  if (!fsOld.existsSync(device_config)) throw new Error("Config not found");
  return parseConfig.createConfig(parseConfig.parseConfig(await fs.readFile(device_config, "utf8")));
}