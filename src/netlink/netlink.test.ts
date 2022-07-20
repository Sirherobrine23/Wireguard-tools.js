import * as wireguardNetlink from "./index";

export default async function main() {
  try {
    await wireguardNetlink.getDevices();
  } catch(err) {
    console.log("Get devices works:", err);
  }

  // Create interface and attempt to get devices again
  await wireguardNetlink.addInterface({
    interfaceName: "wg-test",
    ip: ["10.0.0.1/24"]
  });
  const wireguardDevices = await wireguardNetlink.getDevices();
  if (!wireguardDevices.some(x => x.name === "wg-test")) throw new Error("Interface not found");
  console.log("Interface created");

  return console.log(wireguardDevices);
}