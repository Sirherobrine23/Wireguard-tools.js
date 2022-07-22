import * as wireguardNetlink from "./index";

export default async function main() {
  // Create interface and attempt to get devices again
  await wireguardNetlink.addInterface({
    interfaceName: "wgtest",
    ip: ["10.0.0.1/24"]
  });
  const wireguardDevices = await wireguardNetlink.getDevices();
  if (!wireguardDevices.some(x => x.name === "wgtest")) throw new Error("Interface not found");
  console.log("Interface created");

  return console.log(wireguardDevices);
}