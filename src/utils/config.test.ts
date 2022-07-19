import * as configManeger from "./config";
import * as fs from "node:fs";
const configUser = fs.readFileSync(process.cwd()+"/configsExamples/wg1.ini", "utf8");
const configServer = fs.readFileSync(process.cwd()+"/configsExamples/wg0.ini", "utf8");

export default function main() {
  const userConfigObject = configManeger.parseConfig(configUser);
  const serverConfigObject = configManeger.parseConfig(configServer);
  const backConfigStringUser = configManeger.writeConfig(userConfigObject.data);
  const backconfigStringServer = configManeger.writeConfig(serverConfigObject.data);
  console.log({userConfigObject, backConfigStringUser, serverConfigObject, backconfigStringServer})
}