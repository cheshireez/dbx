import { createServer as createHttpServer, type Server } from "node:http";
import path from "node:path";
import { afterEach, expect, test } from "vitest";
import { createServer as createViteServer, type ViteDevServer } from "vite";

let backendServer: Server | undefined;
let viteServer: ViteDevServer | undefined;
const originalEnvironment = {
  DBX_BACKEND_URL: process.env.DBX_BACKEND_URL,
  DBX_PUBLIC_BASE_PATH: process.env.DBX_PUBLIC_BASE_PATH,
  TAURI_DEV_HOST: process.env.TAURI_DEV_HOST,
  TAURI_ENV_ARCH: process.env.TAURI_ENV_ARCH,
  VITE_DBX_BASE_PATH: process.env.VITE_DBX_BASE_PATH,
};

function restoreEnvironment(name: keyof typeof originalEnvironment): void {
  const value = originalEnvironment[name];
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

afterEach(async () => {
  await viteServer?.close();
  viteServer = undefined;
  if (backendServer) {
    await new Promise<void>((resolve, reject) => {
      backendServer?.close((error) => (error ? reject(error) : resolve()));
    });
    backendServer = undefined;
  }
  for (const name of Object.keys(originalEnvironment) as Array<keyof typeof originalEnvironment>) {
    restoreEnvironment(name);
  }
});

test("Vite redirects only the bare public base path and preserves query, assets, and API proxying", async () => {
  backendServer = createHttpServer((request, response) => {
    response.statusCode = 200;
    response.end(request.url);
  });
  await new Promise<void>((resolve) => backendServer?.listen(0, "127.0.0.1", resolve));
  const backendAddress = backendServer.address();
  if (!backendAddress || typeof backendAddress === "string") throw new Error("backend server did not bind to TCP");

  process.env.DBX_PUBLIC_BASE_PATH = "/dbx";
  process.env.DBX_BACKEND_URL = `http://127.0.0.1:${backendAddress.port}`;
  delete process.env.VITE_DBX_BASE_PATH;
  delete process.env.TAURI_DEV_HOST;
  delete process.env.TAURI_ENV_ARCH;

  viteServer = await createViteServer({
    configFile: path.resolve("apps/desktop/vite.config.ts"),
    logLevel: "silent",
    mode: "web",
    server: { host: "127.0.0.1", port: 0, strictPort: false },
  });
  await viteServer.listen();
  const viteAddress = viteServer.httpServer?.address();
  if (!viteAddress || typeof viteAddress === "string") throw new Error("Vite server did not bind to TCP");
  const origin = `http://127.0.0.1:${viteAddress.port}`;

  const rootResponse = await fetch(`${origin}/`, { redirect: "manual" });
  expect(rootResponse.status).toBe(302);
  expect(rootResponse.headers.get("location")).toBe("/dbx/");

  const bareResponse = await fetch(`${origin}/dbx`, { redirect: "manual" });
  expect(bareResponse.status).toBe(308);
  expect(bareResponse.headers.get("location")).toBe("/dbx/");

  const queryResponse = await fetch(`${origin}/dbx?next=%2Fworkspace&theme=dark`, { redirect: "manual" });
  expect(queryResponse.status).toBe(308);
  expect(queryResponse.headers.get("location")).toBe("/dbx/?next=%2Fworkspace&theme=dark");

  const indexResponse = await fetch(`${origin}/dbx/?next=%2Fworkspace`, { redirect: "manual" });
  expect(indexResponse.status).toBe(200);
  expect(await indexResponse.text()).toContain('<div id="root">');

  const assetResponse = await fetch(`${origin}/dbx/favicon.png`, { redirect: "manual" });
  expect(assetResponse.status).toBe(200);
  expect(assetResponse.headers.get("content-type")).toBe("image/png");

  const apiResponse = await fetch(`${origin}/dbx/api/probe?value=1`, { redirect: "manual" });
  expect(apiResponse.status).toBe(200);
  expect(await apiResponse.text()).toBe("/api/probe?value=1");
});
