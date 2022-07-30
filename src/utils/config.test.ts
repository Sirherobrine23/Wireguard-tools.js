import * as configManeger from "./config";
import * as fs from "node:fs";
const configUser = fs.readFileSync(process.cwd()+"/configsExamples/wg1.ini", "utf8");
const configServer = fs.readFileSync(process.cwd()+"/configsExamples/wg0.ini", "utf8");

export function main() {
  const userConfigObject = configManeger.parseConfig(configUser);
  console.log("Sucess to parse user config");
  const serverConfigObject = configManeger.parseConfig(configServer);
  console.log("Sucess to parse server config");

  const backConfigStringUser = configManeger.writeConfig(userConfigObject.data);
  console.log("Sucess to write user config");
  const backconfigStringServer = configManeger.writeConfig(serverConfigObject.data);
  console.log("Sucess to write server config");
  return {userConfigObject, backConfigStringUser, serverConfigObject, backconfigStringServer};
}