import * as child_process from "node:child_process";

export function up(wgInterface: string): Promise<void> {
  return new Promise<void>((res, rej) => {
    child_process.execFile("wg-quick", ["up", wgInterface], (err: Error, Stdout, Stderr) => {
      if (!!err) return rej(err);
      console.log({Stderr, Stdout});
      return res();
    });
  });
}

export function down(wgInterface: string): Promise<void> {
  return new Promise<void>((res, rej) => {
    child_process.execFile("wg-quick", ["down", wgInterface], (err: Error, Stdout, Stderr) => {
      if (!!err) return rej(err);
      console.log({Stderr, Stdout});
      return res();
    });
  });
}

export function save(wgInterface: string): Promise<void> {
  return new Promise<void>((res, rej) => {
    child_process.execFile("wg-quick", ["save", wgInterface], (err: Error, Stdout, Stderr) => {
      if (!!err) return rej(err);
      console.log({Stderr, Stdout});
      return res();
    });
  });
}

export function strip(wgInterface: string): Promise<void> {
  return new Promise<void>((res, rej) => {
    child_process.execFile("wg-quick", ["strip", wgInterface], (err: Error, Stdout, Stderr) => {
      if (!!err) return rej(err);
      console.log({Stderr, Stdout});
      return res();
    });
  });
}
