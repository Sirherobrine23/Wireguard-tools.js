import * as child_process from "node:child_process";

export default run;
export async function run(command, args: string[], env: {[ke: string]: string}, cwd?: string): Promise<{stderr: string, stdout: string}> {
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

export async function singleRun(command: string, env?: {[ke: string]: string}, cwd?: string): Promise<{stderr: string, stdout: string}> {
  return new Promise((res, rej) => {
    child_process.exec(command, {
      cwd: cwd,
      env: {
        ...process.env,
        ...(env||{})
      }
    }, (err, stdout, stderr) => {
      if (!!err) return rej(err);
      return res({stderr, stdout});
    });
  });
}