// @ts-ignore
import Bridge from "../build/Release/wireguard_bridge";
console.log(Bridge)

export async function getDevices(): Promise<string[]> {
  return Bridge.getDevices();
}