# dsh-egress-guard

[![npm](https://img.shields.io/npm/v/dsh-egress-guard?color=4D6BFE)](https://www.npmjs.com/package/dsh-egress-guard)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[English](README.md) | 中文

给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 工具调用加的**运行时**安全网关。

生态里已有的安全插件都是在 agent 跑起来**之前**静态扫描配置文件。这个插件挂在工具执行管线上，作用于调用本身：

| 规则 | 扩展点 | 作用 |
|---|---|---|
| **出站白名单** | `tools/pre-execute` | 调用里出现白名单之外的网络目的地时拒绝（或转审批）——`curl` 到某个 paste 站、`git push` 到陌生远端、fetch 到外传端点。 |
| **密钥脱敏** | `tools/post-execute` | 在模型、持久化会话日志、Code Mode 程序读到之前，把工具结果里的凭据改写掉。 |
| **审计日志** | 两条瀑布 | 每个决策都追加成一行 JSONL，包括 `monitor` 模式下"本来会拦"的那些。 |

不 fork、不改 loop：三个监听器挂在文档化的扩展点上，卸载时干净释放。

## 安装

```sh
dsh plugin --profile <名字> add dsh-egress-guard
```

bundle 默认是 `mode: monitor`，所以**装上它不会弄坏你现有的配置**：所有规则照常评估、照常写审计日志，但不拦截、不改写。先看一天日志，再去 profile 的 `cordis.patch.yml` 里打开强制：

```yaml
- id: egress-guard
  config:
    mode: enforce
    egress:
      enabled: true
      allowHosts: ['*.github.com', '*.npmjs.org', 'api.deepseek.com']
      denyHosts: []
      allowLoopback: true
      onViolation: deny
    redact:
      enabled: true
      builtins: true
      extraPatterns: []
      placeholder: '[redacted:{name}]'
    audit:
      enabled: true
      path: ''
      logAllowed: false
```

注意 patch 替换的是整个 `config`，不是深合并——你想保留的键都要重写一遍。

## 配置项

| 键 | 默认值 | 含义 |
|---|---|---|
| `mode` | `monitor` | `off` 什么都不注册；`monitor` 只评估只记录；`enforce` 真拦真改。 |
| `egress.allowHosts` | schema 里为 `[]`，bundle 里给了一份起步清单 | 放行的主机。`*.example.com` 同时覆盖主域名**和**所有子域名。留空表示只用黑名单。 |
| `egress.denyHosts` | `[]` | 始终拒绝，优先级高于 `allowHosts` 和 `allowLoopback`。 |
| `egress.allowLoopback` | `true` | 放行 `localhost`、`127.0.0.0/8`、`::1`、`*.localhost`。 |
| `egress.onViolation` | `deny` | 设成 `ask` 则交给 `ctx.approval` 审批——**没挂审批服务时会降级为拒绝**。 |
| `redact.builtins` | `true` | 内置：私钥、各家 API key、JWT、bearer 头、`KEY=value` 赋值。 |
| `redact.extraPatterns` | `[]` | 额外的正则（按 global 标志编译）。 |
| `redact.placeholder` | `[redacted:{name}]` | `{name}` 会替换成命中的规则名。 |
| `audit.path` | `$DSH_HOME/egress-guard.jsonl` | JSONL，一行一个决策。 |
| `audit.logAllowed` | `false` | 连"命中了主机但放行"的调用也记——这是用真实流量反推白名单的办法。 |

### 用真实流量反推白名单

```sh
# 1. 先用 monitor 模式装上，把 logAllowed 开成 true，正常干活一段时间
# 2. 看你的 agent 到底访问了哪些主机：
jq -r '.hosts[]?' ~/.dsh/egress-guard.jsonl | sort | uniq -c | sort -rn
# 3. 把合理的填进 allowHosts，再把 mode 切成 enforce
```

## 设计取舍

**脱敏改的是 canonical value，不是渲染出来的 content。** 注册表的契约里写得很明确：content 替换**不是**保密边界——Code Mode 的程序直接拿到的是 `value`。所以成功结果走 value 替换，content 由脱敏后的 value 重新渲染；失败结果没有 value（注册表禁止对失败结果替换 value），只能按 content 脱敏。

**这个插件在 post-execute 瀑布里最后动手。** 它先 `next()` 把下游跑完，再对最终决策实际携带的那份投影做脱敏，这样瀑布更深处的监听器没法把原文再塞回来。如果别的插件替换了 content 而底层 value 里还有密钥，本插件会替换 **value**——代价是丢掉那个插件的展示效果，但不会泄漏给程序化消费者。这个优先级是有意为之的。

**拒绝时会明确告诉模型别绕路。** 只回一句"denied"会诱导模型换个工具重试；这里的 reason 会点名主机，并要求它去问用户。

## 局限 —— 信任它之前请先读这段

这是**护栏，不是隔离边界**。它提高的是"手滑"和"轻度 prompt 注入"的成本，挡不住一个已经能在你机器上执行代码的对手。

- **检测是文本层面的**：从参数字符串里扫 URL 和 `user@host` 远端。运行期才拼出目的地的命令（`curl "$ENDPOINT"`、base64、字符串拼接、十进制形式的 IP）对这个网关**完全隐形**。真正的隔离是沙箱接缝该干的事（`dsh-bash-sandbox`、网络命名空间、代理），不是字符串匹配。
- **工具自己开 socket 就完全绕过**，除非目的地出现在它的参数里。
- **脱敏基于模式匹配**：不认识的凭据形状会漏，看起来像密钥的正常文本会被误改。自己的格式请加 `extraPatterns`；开强制之前先看审计日志里的误报。
- **不扫二进制内容**：图片等非文本块原样透传。
- **审计日志在本地且未签名**：任何能写你文件系统的东西都能改它。

## 兼容性

针对 `@deepseek-ai/dsh-tools` `0.1.0-rc` 的管线契约开发。测试套件跑在 npm 上的 `0.1.0-rc.6`；bundle 在真实的 `dsh 0.1.0-rc.5` profile 里用 npm、本地路径、打包 tarball、git 四种方式各装过一遍，`fiberPhase` 均为 `active`。

另外提醒：npm 上 `@deepseek-ai/*` 的 `latest` 标签还停在很旧的 `0.0.1-rc.1`，当前版本在 `next` 标签上。手动安装 harness 相关包时请显式指定版本。

Harness 处于开发者预览期，官方明确说会有破坏性变更。契约一旦变动，本插件的测试会直接炸——因为它们是通过真实注册表执行真实调用，而不是 mock 瀑布。

## 开发

```sh
npm install
npm test          # 61 个测试：纯单元测试 + 通过真实 ToolRuntime 的端到端测试
npm run typecheck
npm run build
```

不发包也能在真实 harness 上试：

```sh
dsh plugin --profile <名字> add /path/to/dsh-egress-guard
dsh --profile <名字> --dump-config   # 能看到 "# == dsh-egress-guard" 这一层
```

## 许可证

[MIT](LICENSE)
