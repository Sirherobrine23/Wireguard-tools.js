const fs = require("fs");
const path = require("path");

module.exports = main;
/**
 * Load node addon
 * @param {string|undefined} path
 * @param {string|undefined} name
 * @returns {any}
 */
function main(pathLocation, name) {
  if (!pathLocation) pathLocation = process.cwd();
  else pathLocation = path.resolve(pathLocation);
  const folders = [
    path.join(pathLocation, "build", "Release"),
    path.join(pathLocation, "build", "Debug"),
    path.join(pathLocation, "prebuilds", `${process.platform}-${process.arch}`),
    path.join(pathLocation, "prebuilds", `${process.platform}_${process.arch}`)
  ]
  for (const folder of folders) {
    if (fs.existsSync(folder)) {
      if (!name) name = (fs.readdirSync(folder)).filter(file => file.endsWith(".node")).at(0);
      if (typeof name === "string") {
        if (!(name.endsWith(".node"))) name += ".node";
        if (fs.existsSync(path.join(folder, name))) return require(path.join(folder, name));
      }
    }


  }
  throw new Error("Cannot get node addon");
}