import * as fs from "node:fs/promises";
import * as fsOld from "node:fs";
import * as path from "node:path";
import * as crypto from "node:crypto";

async function readDirAndFilter(dir: string, test: Array<RegExp> = [/.*/]) {
  if (!(fsOld.existsSync(dir))) throw new Error(`${dir} does not exist`);
  const files = await fs.readdir(dir);
  const parseFiles: Array<string> = []
  await Promise.all(files.map(async (fd) => {
    const stat = await fs.stat(path.join(dir, fd));
    if (stat.isDirectory()) return readDirAndFilter(path.join(dir, fd), test).then(res => parseFiles.push(...res)).catch(err => console.error(err));
    else if (stat.isFile()) {
      const match = test.some(reg => reg.test(fd));
      if (match) parseFiles.push(path.join(dir, fd));
    }
  }));
  return parseFiles;
}

// Add default envs
process.env.PASSWORD_SECERET = "password";
process.env.NODE_ENV = "development";
const RandomUUIDs = Array(50).fill(0).map(() => crypto.randomUUID());

async function runTest() {
  const testDir = path.join(__dirname, ".testDir");
  if (fsOld.existsSync(testDir)) await fs.rm(testDir, { recursive: true });
  await fs.mkdir(testDir);
  const mainFind = path.join(process.cwd(), "src");
  const testsFiles = await readDirAndFilter(mainFind, [/.*\.test\.ts$/]);
  for (const file of testsFiles) {
    console.log("************** Start Script: %s **************", file);
    const testScript = await import(file) as {[key: string]: (...any) => Promise<void>};
    for (const key in testScript) {
      const logFileJson = path.join(testDir, `${path.basename(file)}_${key}.json`);
      console.log("************** Start Test: %s **************", key);
      await fs.writeFile(logFileJson, JSON.stringify(await testScript[key](RandomUUIDs), null, 2));
    }
    console.log("************** End Script: %s **************", file);
  }
}

runTest().then(() => {
  console.log("Test passed");
  process.exitCode = 0;
}).catch((err: Error) => {
  console.error("Test failed");
  console.error(err);
  process.exitCode = 1;
}).then(() => {
  console.log("Exit with code: %d", process.exitCode);
  return process.exit();
});