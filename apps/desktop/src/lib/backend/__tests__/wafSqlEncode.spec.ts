import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encodeSqlDeep, isWafSqlField } from "@/lib/backend/http";

// WAF 载荷加密字段匹配与深度加密行为(与后端 waf_codec 解码侧对称)。
describe("WAF SQL 字段名匹配", () => {
  it("覆盖复合命名(驼峰/下划线)与单复数", () => {
    expect(isWafSqlField("whereInput")).toBe(true);
    expect(isWafSqlField("orderBy")).toBe(true);
    expect(isWafSqlField("orderByInput")).toBe(true);
    expect(isWafSqlField("tableFilters")).toBe(true);
    expect(isWafSqlField("searchText")).toBe(true);
    expect(isWafSqlField("originalSql")).toBe(true);
    expect(isWafSqlField("filterJson")).toBe(true);
    expect(isWafSqlField("messages")).toBe(true);
    // 任意文本载荷(单元格值 / 导出行数据 / Redis-KV 写入值)
    expect(isWafSqlField("value")).toBe(true);
    expect(isWafSqlField("values")).toBe(true);
    expect(isWafSqlField("rows")).toBe(true);
    expect(isWafSqlField("newRows")).toBe(true);
    expect(isWafSqlField("rawValue")).toBe(true);
    // schema diff 携带的 DDL 文本
    expect(isWafSqlField("ddl")).toBe(true);
    expect(isWafSqlField("targetDdl")).toBe(true);
  });

  it("标识符/时间戳类字段不命中", () => {
    expect(isWafSqlField("updateTime")).toBe(false);
    expect(isWafSqlField("columns")).toBe(false);
    expect(isWafSqlField("tableName")).toBe(false);
    expect(isWafSqlField("connectionId")).toBe(false);
    expect(isWafSqlField("limit")).toBe(false);
  });
});

describe("WAF 深度加密", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_DBX_WAF_SQL_ENCODE", "1");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("whereInput/orderBy 加密,标识符与数字保留", async () => {
    const encoded = (await encodeSqlDeep({
      options: { whereInput: "push_status = 2 AND warning_source = 'x'", orderBy: '"id" DESC', tableName: "warning_info", limit: 500 },
    })) as { options: Record<string, unknown> };
    expect(String(encoded.options.whereInput)).not.toContain("AND");
    expect(String(encoded.options.orderBy)).not.toContain("DESC");
    expect(encoded.options.tableName).toBe("warning_info");
    expect(encoded.options.limit).toBe(500);
  });

  it("动态键映射(tableFilters)子树值加密且键保留", async () => {
    const encoded = (await encodeSqlDeep({ tableFilters: { t_order: "id <= 90000" } })) as { tableFilters: Record<string, unknown> };
    expect(Object.keys(encoded.tableFilters)).toEqual(["t_order"]);
    expect(String(encoded.tableFilters.t_order)).not.toContain("<=");
  });

  it("幂等:二次深度加密不再变化", async () => {
    const once = await encodeSqlDeep({ options: { whereInput: "a = 1" } });
    const twice = await encodeSqlDeep(once);
    expect(twice).toEqual(once);
  });

  it("单元格值/导出行数据/Redis 写入值一并加密", async () => {
    const encoded = (await encodeSqlDeep({
      rows: [["SELECT * FROM t WHERE a = 1 AND b = 2", 7]],
      value: "UPDATE t SET c = 3 AND d = 4",
      columns: ["body", "id"],
    })) as { rows: unknown[][]; value: string; columns: string[] };
    expect(String(encoded.rows[0]![0])).not.toContain("SELECT");
    expect(String(encoded.value)).not.toContain("UPDATE");
    // 非字符串值与列名保留
    expect(encoded.rows[0]![1]).toBe(7);
    expect(encoded.columns).toEqual(["body", "id"]);
  });

  it("开关关闭时原样透传", async () => {
    vi.stubEnv("VITE_DBX_WAF_SQL_ENCODE", "0");
    const body = { options: { whereInput: "a = 1" } };
    expect(await encodeSqlDeep(body)).toBe(body);
  });
});
