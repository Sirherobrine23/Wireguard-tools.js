import * as child_process from "node:child_process";

export default function exists(command: string) {
  return new Promise<boolean>(res => {
    child_process.execFile("command", ["-v", command], err => {
      if (!!err) return res(false);
      return res(true);
    })
  });
}