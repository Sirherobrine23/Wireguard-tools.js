import * as child_process from "node:child_process";

export default async function run(command, args: string[], env: {[ke: string]: string}, cwd?: string) {
  return new Promise((res, rej) => {
    child_process.execFile(command, args, {
      cwd: cwd,
      env: {
        ...process.env,
        ...env
      }
    }, (err, stdout, stderr) => {
      if (!!err) return rej(err);
      return res({stderr, stdout});
    });
  });
}