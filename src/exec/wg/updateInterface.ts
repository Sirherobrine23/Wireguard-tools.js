import { singleRun } from "../../lib/childPromise";

export default async function syncInterface(wgInterface: string): Promise<void> {
  console.info("this api is under development, and for now it remains dependent on wg commands and wg-quick");
  await singleRun(`wg syncconf "${wgInterface}" <(wg-quick strip "${wgInterface}")`);
}
