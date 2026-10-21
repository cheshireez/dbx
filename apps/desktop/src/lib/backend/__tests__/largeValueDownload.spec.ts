// @vitest-environment happy-dom
import { afterEach, expect, it, vi } from "vitest";
import { downloadLargeValue, exportSnapshotResult } from "../http";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it("does not deliver a late snapshot export after local cancellation", async () => {
  let release!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    ),
  );
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  const controller = new AbortController();
  const pending = exportSnapshotResult({ context: { connectionId: "ob", database: "APP", valueRef: "locator" }, format: "json", columns: ["C"], rows: [["preview"]], cells: [{ rowIndex: 0, columnIndex: 0, valueRef: "locator" }] }, "snapshot.json", controller.signal);
  controller.abort(new Error("cancelled locally"));
  const outcome = pending.then(
    () => "delivered",
    () => "cancelled",
  );
  // 请求体经 encodeSqlDeep 异步准备后 fetch 才会发起,需等待 fetch 桩就绪再放行响应
  await vi.waitFor(() => {
    expect(typeof release).toBe("function");
  });
  release(new Response(JSON.stringify({ downloadId: "prepared" }), { status: 200, headers: { "Content-Type": "application/json" } }));
  expect(await outcome).toBe("cancelled");
  expect(click).not.toHaveBeenCalled();
});

it("delivers an uncancelled browser download with the original filename", async () => {
  const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ downloadId: "prepared" }), { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetch);
  const filenames: string[] = [];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    filenames.push(this.download);
  });
  await downloadLargeValue({ connectionId: "ob", database: "APP", valueRef: "locator" }, "lob.bin", new AbortController().signal);
  expect(filenames).toEqual(["lob.bin"]);
  expect(JSON.parse(fetch.mock.calls[0]![1].body)).toEqual({ request: { connectionId: "ob", database: "APP", valueRef: "locator" }, fileName: "lob.bin" });
});

it("does not deliver a browser download when cancelled while the server prepares it", async () => {
  let release!: (response: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    ),
  );
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
  const controller = new AbortController();
  const pending = downloadLargeValue({ connectionId: "ob", database: "APP", valueRef: "locator" }, "lob.bin", controller.signal);
  controller.abort(new Error("cancelled locally"));
  const outcome = pending.then(
    () => "delivered",
    () => "cancelled",
  );
  // 同上:等待 fetch 桩就绪(请求体异步加密准备)再放行响应
  await vi.waitFor(() => {
    expect(typeof release).toBe("function");
  });
  release(new Response(JSON.stringify({ downloadId: "prepared" }), { status: 200, headers: { "Content-Type": "application/json" } }));
  expect(await outcome).toBe("cancelled");
  expect(click).not.toHaveBeenCalled();
});
