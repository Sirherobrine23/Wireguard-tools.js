import path from "node:path";
import fs from "node:fs/promises";
import nodeURL from "node:url"

// Solve current __dirname in ESM module
const __dirname = import.meta.dirname || path.dirname(nodeURL.fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(__dirname, "..");

if (__dirname.includes(".asar")) {
  console.warn("Check if addon nothing includes in .asar file")
}

declare global {
  namespace NodeJS {
    export interface Moduledlopen {
      exports: any;
    }

    interface Process {
      /**
       * The `process.dlopen()` method allows dynamically loading shared objects. It is primarily used by `require()` to load C++ Addons, and should not be used directly, except in special cases. In other words, `require()` should be preferred over `process.dlopen()` unless there are specific reasons such as custom dlopen flags or loading from ES modules.
       *
       * An important requirement when calling `process.dlopen()` is that the `module` instance must be passed. Functions exported by the C++ Addon are then accessible via `module.exports`.
       * @param module - module to export
       * @param filename - Addon path
       * @param flags - The flags argument is an integer that allows to specify dlopen behavior. See the [os.constants.dlopen](https://nodejs.org/docs/latest/api/os.html#dlopen-constants) documentation for details.
       * @default flags `os.constants.dlopen.RTLD_LAZY`
       * @since v9.0.0
       */
      dlopen(module: Moduledlopen, filename: string, flags: number): void;
      /**
       * The `process.dlopen()` method allows dynamically loading shared objects. It is primarily used by `require()` to load C++ Addons, and should not be used directly, except in special cases. In other words, `require()` should be preferred over `process.dlopen()` unless there are specific reasons such as custom dlopen flags or loading from ES modules.
       *
       * An important requirement when calling `process.dlopen()` is that the `module` instance must be passed. Functions exported by the C++ Addon are then accessible via `module.exports`.
       * @param module - module to export
       * @param filename - Addon path
       * @since v0.1.16
       */
      dlopen(module: Moduledlopen, filename: string): void;
    }
  }
}

async function exists(filePath: string) {
  return fs.access(path.resolve(filePath)).then(() => true, () => false);
}

export async function LoadAddon<T = any>(addonFile: string,  exports?: Record<string, any>): Promise<T> {
  let filesTests = [
    addonFile,
    path.resolve(projectRoot, addonFile),
    path.resolve(projectRoot, addonFile+".node"),
    path.resolve(projectRoot, "build/Release", addonFile),
    path.resolve(projectRoot, "build/Release", addonFile+".node"),
    path.resolve(projectRoot, "build/Debug", addonFile),
    path.resolve(projectRoot, "build/Debug", addonFile+".node"),
  ]

  for (const file of filesTests) {
    if (await exists(file)) {
      let ext: NodeJS.Moduledlopen = { exports: Object.assign({}, exports) }
      process.dlopen(ext, file)
      return ext.exports
    }
  }

  throw new Error("Cannot load required addon")
}
