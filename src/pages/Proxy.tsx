import { createSignal } from "solid-js";
import { Button, Card, Container, Field, SaveBar, Switch, Tag, TextArea } from "../components/ui";
import { api } from "../api";
import { config, patchConfig, refreshStatus, replaceConfig, status, toast, useDraft } from "../store";

export default function ProxyPage() {
  const [busy, setBusy] = createSignal("");
  const proxy = () => config().proxy ?? {};

  /// 编辑走草稿：修改后出现「保存并应用」，保存前不落盘；enabled 开关即时生效，不进草稿
  const { draft, patch, set, dirty, reset, saveValue } = useDraft(proxy, ["enabled"]);

  // 排除列表使用本地文本状态，避免受控值被归一化后剥离换行导致多行无法输入
  const [excludeText, setExcludeText] = createSignal<string | null>(null);

  const toggleProxy = async () => {
    setBusy("proxy");
    try {
      if (status().proxy === "success") {
        await api.stopProxy();
        await patchConfig({ proxy: { enabled: false } });
      } else {
        await api.startProxy();
        await patchConfig({ proxy: { enabled: true } });
      }
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 保存草稿并应用：系统代理开启中则重新应用，使新配置立即生效
  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["proxy"], saveValue());
      if (status().proxy === "success") {
        await api.startProxy();
        toast("配置已保存，系统代理已重新应用", "success");
      } else {
        toast("配置已保存", "success");
      }
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  const savedExcludeText = () =>
    Object.entries(draft().excludeIpList ?? {})
      .filter(([, v]) => v === true || v === "true")
      .map(([k]) => k)
      .join("\n");

  /// 失焦后整段写入草稿（删除的域名可生效），随「保存并应用」落盘
  const setExclude = (text: string) => {
    const list: Record<string, boolean> = {};
    for (const line of text.split(/\r?\n/)) {
      const key = line.trim();
      if (key) list[key] = true;
    }
    set("excludeIpList", list);
    setExcludeText(null);
  };

  return (
    <Container title="系统代理" desc="将系统网络请求接管到本地加速服务">
      <Card title="代理开关" extra={<Tag type={status().proxy === "success" ? "success" : "default"}>{status().proxy === "success" ? "已开启" : "未开启"}</Tag>}>
        <Field label="启用系统代理">
          <Switch checked={!!proxy().enabled} onChange={toggleProxy} disabled={busy() === "proxy"} />
        </Field>
        <Field label="同时代理 HTTP" desc="开启后会同时设置 HTTP 代理（端口 -1）">
          <Switch checked={!!draft().proxyHttp} onChange={(v) => patch({ proxyHttp: v })} />
        </Field>
        <Field label="设置环境变量" desc="写入 HTTP_PROXY / HTTPS_PROXY / NO_PROXY">
          <Switch checked={!!draft().setEnv} onChange={(v) => patch({ setEnv: v })} />
        </Field>
        <Field label="设置 CA 证书路径" desc="写入指向「系统公共根证书 + DevSidecar CA」合并文件的 REQUEST_CA_BUNDLE / NODE_EXTRA_CA_CERTS / SSL_CERT_FILE，不会替换掉公共根证书">
          <Switch checked={!!draft().setCaBundle} onChange={(v) => patch({ setCaBundle: v })} />
        </Field>
        <Field label="排除国内域名" desc="国内域名直连，不经过代理">
          <Switch
            checked={!!draft().excludeDomesticDomainAllowList}
            onChange={(v) => patch({ excludeDomesticDomainAllowList: v })}
          />
        </Field>
        <div class="mt-3 flex gap-2">
          <Button type="primary" loading={busy() === "proxy"} onClick={toggleProxy}>
            {status().proxy === "success" ? "关闭系统代理" : "开启系统代理"}
          </Button>
          <Button
            onClick={async () => {
              try {
                await api.startProxy();
                toast("系统代理已重新应用", "success");
              } catch (e: any) {
                toast(String(e), "error");
              }
            }}
          >
            重新应用
          </Button>
        </div>
      </Card>

      <Card title="排除列表" desc="每行一个域名，这些域名不经过代理（失焦后记入草稿，随「保存并应用」落盘）">
        <TextArea
          class="font-mono"
          height="260px"
          style={{
            background: "var(--ds-bg-soft)",
            color: "var(--ds-text)",
            "border-color": "var(--ds-border)",
          }}
          value={excludeText() ?? savedExcludeText()}
          onInput={(v) => setExcludeText(v)}
          onBlur={(v) => setExclude(v)}
        />
      </Card>

      <SaveBar dirty={dirty()} saving={busy() === "save"} onSave={save} onReset={reset} text="代理配置已修改，尚未保存" />
    </Container>
  );
}
