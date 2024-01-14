const fs = require("fs");
const path = require("path");

module.exports = main;
/**
 * Load node addon
 * @param {string|number|undefined} name
 * @param {string|undefined} path
 * @returns {any}
 */
function main(name, pathLocation) {
  if (!pathLocation) pathLocation = path.resolve(__dirname, "..");
  else pathLocation = path.resolve(process.cwd(), pathLocation);
  const folders = [
    path.join(pathLocation, "build", "Release"),
    path.join(pathLocation, "build", "Debug"),
    path.join(pathLocation, "prebuilds", `${process.platform}_${process.arch}`),
    path.join(pathLocation, "prebuilds", `${process.platform}-${process.arch}`),
  ];
  for (const folder of folders) {
    if (fs.existsSync(folder)) {
      const files = (fs.readdirSync(folder)).filter(file => file.endsWith(".node"));
      if (typeof name === "number") return require(path.join(folder, files.at(name)));
      else if (!name) name = files.at(0);
      if (typeof name === "string") {
        const bname = name.concat("");
        if ((name = files.find(s => s.startsWith(name)))) return require(path.join(folder, name));
        name = bname;
      }
    }
  }
  throw new Error("Cannot get node addon");
}