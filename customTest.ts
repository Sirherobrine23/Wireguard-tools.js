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
const RandomUUIDs = Array(50).fill(0).map(() => crypto.randomUUID());
async function runTest() {
  const testDir = path.join(__dirname, ".testDir");
  if (fsOld.existsSync(testDir)) await fs.rm(testDir, { recursive: true });
  await fs.mkdir(testDir);
  const mainFind = path.join(process.cwd(), "src");
  const testsFiles = (await readDirAndFilter(mainFind, [/.*\.test\.ts$/])).reverse();
  const testResults = {};
  for (const file of testsFiles) {
    console.log("************** Test script: %s **************", file);
    const StartTime = Date.now();
    const testScript = await import(file) as {[key: string]: (...any) => Promise<any>};
    testResults[file] = {};
    const FunctionsKeys = Object.keys(testScript).sort((a, b) => {
      if (a.toString().includes("pre")) return -1;
      if (b.toString().includes("pre")) return 1;
      return 0;
    });
    for (const key of FunctionsKeys) {
      console.log("************** %s **************", key);
      const result = await testScript[key](RandomUUIDs);
      if (result) testResults[file][key] = result;
    }
    const timeEnd = (Date.now() - StartTime);
    console.log("************** End Script: %s, time Run: %fms **************", file, timeEnd);
    testResults[file].consumedTime = timeEnd;
  }
  await fs.writeFile(path.join(testDir, "testResults.json"), JSON.stringify(testResults, null, 2));
  let READMEResult = "# Test Results\n\nThese are the test results!\n\n";
  for (const file of Object.keys(testResults)) {
    READMEResult += `## Time: ${testResults[file].consumedTime}ms, File: ${file}\n\n`;
    for (const key of Object.keys(testResults[file])) {
      if (key === "consumedTime") continue;
      READMEResult += `### Function: ${key}\n\n`;
      READMEResult += "```json\n";
      READMEResult += JSON.stringify(testResults[file][key], null, 2);
      READMEResult += "\n```\n\n";
    }
  }
  await fs.writeFile(path.join(testDir, "README.md"), READMEResult.trim());
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