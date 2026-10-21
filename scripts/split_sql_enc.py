# -*- coding: utf-8 -*-
"""从工作流定义中精确拆分「构建加密SQL」为「构建SQL」+「加密SQL」两段 jsCode。
输入：MCP get_workflow_details 持久化输出文件；输出：两个 jsCode 文本与中间产物。
"""

import json
import re
import sys

SRC = r"C:\Users\ZJPLAN~1\AppData\Local\Temp\trae\toolcall-output\ff598999-a37b-4b30-b757-6d1a9a737b93.txt"
OUT_DIR = r"E:\Projects\personal\dbx\scripts"

def main() -> None:
    with open(SRC, "r", encoding="utf-8") as f:
        raw = f.read()

    # MCP 返回带 "The MCP server responded with: " 前缀 + 包裹数组，剥离后解析
    marker = "The MCP server responded with: "
    idx = raw.find(marker)
    if idx >= 0:
        raw = raw[idx + len(marker):]
    payload = json.loads(raw)
    text = payload[0]["text"]
    data = json.loads(text)
    workflow = data["workflow"]

    # 定位 构建加密SQL 节点
    node = None
    for n in workflow["nodes"]:
        if n["name"] == "构建加密SQL":
            node = n
            break
    if node is None:
        print("ERROR: 未找到节点 构建加密SQL")
        sys.exit(1)

    js = node["parameters"]["jsCode"]

    # 拆分点：加密 IIFE 起点 "const enc = (function(s,secret){"
    m = re.search(r"const enc = \(function\(s,secret\)\{", js)
    if not m:
        print("ERROR: 未找到加密函数起点")
        sys.exit(1)
    split_idx = m.start()

    head = js[:split_idx].rstrip()          # SQL 构建部分（含 const rawSql = sql;）
    enc_part = js[split_idx:].rstrip()      # 加密 IIFE + return

    # 新「构建SQL」节点代码：只构建明文 SQL
    js_build = head + "\nreturn [{ json: { sql: sql, cscode: cscode } }];\n"

    # 新「加密SQL」节点代码：接收 $json.sql，走原有加密逻辑
    js_encrypt = (
        "const sql = $json.sql;\n"
        "const cscode = $json.cscode;\n"
        "const secret = 'dbx-waf-default-key-2026';\n"
        "const rawSql = sql;\n"
        + enc_part
    )

    with open(OUT_DIR + r"\js_build_sql.txt", "w", encoding="utf-8") as f:
        f.write(js_build)
    with open(OUT_DIR + r"\js_encrypt_sql.txt", "w", encoding="utf-8") as f:
        f.write(js_encrypt)
    with open(OUT_DIR + r"\js_original.txt", "w", encoding="utf-8") as f:
        f.write(js)

    print("OK 拆分完成")
    print("构建SQL jsCode 行数:", js_build.count("\n") + 1, "长度:", len(js_build))
    print("加密SQL jsCode 行数:", js_encrypt.count("\n") + 1, "长度:", len(js_encrypt))

if __name__ == "__main__":
    main()