import { For, Show, createSignal } from "solid-js";
import { Button, Card, Container, Field, Input, JsonEditor, SaveBar, Select, Switch, Tag } from "../components/ui";
import { api } from "../api";
import { config, patchConfig, refreshStatus, replaceConfig, setSpeedResults, speedResults, speedTesting, status, toast, useDraft } from "../store";

export default function ServerPage() {
  const [busy, setBusy] = createSignal("");
  const server = () => config().server ?? {};

  /// 编辑走草稿：修改后出现「保存并应用」，保存前不落盘；enabled 开关即时生效，不进草稿
  const { draft, patch, set, dirty, reset, saveValue } = useDraft(server, ["enabled"]);
  const dsetting = () => draft().setting ?? {};

  /// 数字输入：空串/非数字不写入草稿
  const num = (v: string): number | undefined => {
    if (v === "") return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };

  const toggleEnabled = async (v: boolean) => {
    setBusy("enabled");
    try {
      // 先让后端完成真实启停（关闭时还会回滚插件与系统代理），成功后再落配置。
      // 反过来先写 enabled=false 会制造“配置已关闭、服务仍在跑”的假象。
      if (v) {
        await api.startServer();
      } else {
        await api.stopServer();
      }
      await patchConfig({ server: { enabled: v } });
      await refreshStatus();
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const restart = async () => {
    setBusy("restart");
    try {
      await api.restartServer();
      toast("加速服务已重启", "success");
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const doSpeedTest = async () => {
    setBusy("speed");
    try {
      const res = await api.speedTest();
      setSpeedResults(res.resultList ?? []);
      toast(`测速完成，共 ${(res.resultList ?? []).length} 条结果`, "success");
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 保存草稿并应用：服务运行中则重启加速服务，使新配置立即生效
  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["server"], saveValue());
      if (status().server === "success") {
        await api.restartServer();
        toast("配置已保存，加速服务已重启生效", "success");
      } else {
        toast("配置已保存", "success");
      }
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <Container title="加速服务" desc="本地 MITM 加速服务的端口、证书、拦截器与 DNS 配置">
      <Card title="基础设置" extra={<Tag type={status().server === "success" ? "success" : "default"}>{status().server === "success" ? "运行中" : "已停止"}</Tag>}>
        <Field label="启用加速服务" desc="关闭后本地代理不再监听端口">
          <Switch
            checked={!!server().enabled}
            disabled={busy() === "enabled"}
            onChange={toggleEnabled}
          />
        </Field>
        <Field label="监听地址">
          <Input value={draft().host ?? "127.0.0.1"} onInput={(v) => patch({ host: v })} />
        </Field>
        <Field label="HTTPS 端口" desc="HTTP 端口自动为 HTTPS 端口 - 1">
          <Input
            type="number"
            value={draft().port ?? 31181}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ port: n });
            }}
          />
        </Field>
        <Field label="拦截功能" desc="关闭后仅做转发，不启用拦截规则">
          <Switch
            checked={!!draft().intercept?.enabled}
            onChange={(v) => patch({ intercept: { enabled: v } })}
          />
        </Field>
        <Field label="证书最大缓存数">
          <Input
            type="number"
            value={draft().fakeServerMaxLength ?? 100}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ fakeServerMaxLength: n });
            }}
          />
        </Field>
        <div class="mt-3 flex gap-2">
          <Button type="primary" loading={busy() === "restart"} onClick={restart}>
            重启加速服务
          </Button>
        </div>
      </Card>

      <Card title="连接设置">
        <Field label="校验 SSL 证书" desc="关闭后不校验上游证书（等价于 unVerifySsl）">
          <Switch checked={!!dsetting().verifySsl} onChange={(v) => patch({ setting: { verifySsl: v } })} />
        </Field>
        <Field label="允许 TLS 1.2" desc="默认仅使用 TLS 1.3">
          <Switch checked={!!dsetting().allowTls12} onChange={(v) => patch({ setting: { allowTls12: v } })} />
        </Field>
        <Field label="启用 HTTP/2 上游" desc="与上游按 ALPN 协商 h2/http1.1（对客户端仍以 HTTP/1.1 回写）">
          <Switch
            checked={dsetting().allowHttp2 ?? true}
            onChange={(v) => patch({ setting: { allowHttp2: v } })}
          />
        </Field>
        <Field
          label="拦截模式"
          desc="all-but-whitelist：非白名单域名均解密（默认）；intercepts-only：仅解密拦截规则命中的域名"
        >
          <Select
            value={dsetting().interceptMode ?? "all-but-whitelist"}
            options={[
              { label: "all-but-whitelist（默认）", value: "all-but-whitelist" },
              { label: "intercepts-only（更保守）", value: "intercepts-only" },
            ]}
            onChange={(v) => patch({ setting: { interceptMode: v } })}
          />
        </Field>
        <Field label="流式转发阈值（字节）" desc="Content-Length 超过该值的请求体边读边转发，不在内存缓冲（不参与重试）">
          <Input
            type="number"
            value={dsetting().streamBodyThreshold ?? 1048576}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ setting: { streamBodyThreshold: n } });
            }}
          />
        </Field>
        <Field label="脚本注入" desc="网页端注入油猴脚本等增强脚本">
          <Switch
            checked={!!dsetting().script?.enabled}
            onChange={(v) => patch({ setting: { script: { enabled: v } } })}
          />
        </Field>
        <Field label="默认超时（毫秒）">
          <Input
            type="number"
            value={dsetting().defaultTimeout ?? 20000}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ setting: { defaultTimeout: n } });
            }}
          />
        </Field>
        <Field label="慢速阈值（毫秒）" desc="超过该时间未响应则切换备选 IP">
          <Input
            type="number"
            value={dsetting().lowSpeedDelay ?? 200}
            onInput={(v) => {
              const n = num(v);
              if (n !== undefined) patch({ setting: { lowSpeedDelay: n } });
            }}
          />
        </Field>
      </Card>

      <Card
        title="DNS 服务"
        extra={
          <Button
            size="sm"
            type="primary"
            loading={busy() === "speed" || speedTesting()}
            onClick={doSpeedTest}
          >
            立即测速
          </Button>
        }
      >
        <div class="mb-4">
          <div class="mb-2 text-sm" style={{ color: "var(--ds-text)" }}>
            DNS 服务列表
          </div>
          <JsonEditor
            height="200px"
            value={draft().dns?.providers ?? {}}
            onChange={(v) => set("dns", { ...(draft().dns ?? {}), providers: v })}
          />
        </div>
        <div class="mb-4">
          <div class="mb-2 text-sm" style={{ color: "var(--ds-text)" }}>
            域名 → DNS 映射
          </div>
          <JsonEditor
            height="200px"
            value={draft().dns?.mapping ?? {}}
            onChange={(v) => set("dns", { ...(draft().dns ?? {}), mapping: v })}
          />
        </div>
        <div class="mb-4">
          <div class="mb-2 text-sm" style={{ color: "var(--ds-text)" }}>
            测速配置
          </div>
          <JsonEditor
            height="160px"
            value={draft().dns?.speedTest ?? {}}
            onChange={(v) => set("dns", { ...(draft().dns ?? {}), speedTest: v })}
          />
        </div>
        <Show when={speedResults().length > 0}>
          <div class="rounded border p-2" style={{ "border-color": "var(--ds-border)" }}>
            <For each={speedResults()}>
              {(r) => (
                <div class="flex justify-between py-0.5 text-xs" style={{ color: "var(--ds-text)" }}>
                  <span>
                    {r.hostname} · {r.name} · {r.ip}
                  </span>
                  <span style={{ color: r.ok ? "var(--ds-success)" : "var(--ds-danger)" }}>
                    {r.ok ? `${r.delay} ms` : "不可用"}
                  </span>
                </div>
              )}
            </For>
          </div>
        </Show>
      </Card>

      <Card title="预设 IP 列表" desc="为指定域名直接使用预设 IP，命中后不再发起 DNS 查询">
        <JsonEditor
          value={draft().preSetIpList ?? {}}
          onChange={(v) => set("preSetIpList", v)}
        />
      </Card>

      <Card title="白名单" desc="白名单内的域名不做拦截，直接隧道转发">
        <JsonEditor value={draft().whiteList ?? {}} onChange={(v) => set("whiteList", v)} />
      </Card>

      <Card title="拦截规则" desc="intercepts：按域名与路径匹配的拦截/代理/缓存/脚本规则">
        <JsonEditor height="420px" value={draft().intercepts ?? {}} onChange={(v) => set("intercepts", v)} />
      </Card>

      <SaveBar dirty={dirty()} saving={busy() === "save"} onSave={save} onReset={reset} text="服务配置已修改，尚未保存" />
    </Container>
  );
}
