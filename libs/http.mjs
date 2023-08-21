import http from "node:http";
import https from "node:https";
import stream from "node:stream";

export default fetchContent;
export { fetchContent };
/**
 * @param {string|URL} req
 * @param {undefined|{ method?: string, headers?: Record<string, string>, body?: string }} options
 *
 * @return {Promise<stream.Readable>}
 *
 */
async function fetchContent(req, options) {
  const fixedURL = req instanceof URL ? req : new URL(req);
  const { method, headers, body } = (options || {});
  if (typeof fetch === "function") {
    const req = await fetch(fixedURL, { method, headers, body });
    if (!req.body) return new stream.Readable({ read() { this.push(null); } })
    return stream.Readable.fromWeb(req.body);
  } else {
    return new Promise((done, reject) => {
      const req = fixedURL.protocol === "http:" ? http.request(fixedURL, {  }) : https.request(fixedURL, { method, headers });
      return req.on("error", reject).once("connect", () => body ? (req.end(body)) : null).on("response", (res) => {
        done(res);
      });
    });
  }
}