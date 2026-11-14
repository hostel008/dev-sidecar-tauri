import { For, createSignal } from "solid-js";
import { Button, Card, Container, Field, Input, JsonEditor, SaveBar, Switch, Tag } from "../components/ui";
import { api } from "../api";
import { config, refreshStatus, reloadConfig, replaceConfig, status, toast, useDraft } from "../store";

export default function PluginNodePage() {
  const [busy, setBusy] = createSignal("");
  const node = () => config().plugin?.node ?? {};
  /// 唯一事实来源：后端运行时状态（外部配置是否真的写入）。配置里的 enabled
  /// 由后端回写，只用于持久化，不再单独驱动开关，避免两者不一致。
  const running = () => status().node === "success";
  const serverOn = () => status().server === "success";

  /// 编辑走草稿：修改后出现「保存并应用」，保存前不落盘；enabled 开关即时生效，不进草稿
  const { draft, patch, set, dirty, reset, saveValue } = useDraft(node, ["enabled"]);
  const dsetting = () => draft().setting ?? {};

  const registryList = () => {
    const list = (dsetting().registryList ?? {}) as Record<string, { name?: string; value?: string }>;
    return Object.entries(list).map(([k, v]) => ({ key: k, name: v.name ?? k, value: v.value }));
  };

  const toggle = async () => {
    if (busy()) return;
    setBusy("toggle");
    try {
      // 动作与显示都基于后端运行时状态，避免“开关看着是开、点击却在开启”的错位
      if (running()) {
        await api.disablePlugin("node");
      } else {
        await api.enablePlugin("node");
      }
      // 后端已把真实结果写回 plugin.node.enabled，这里只做对账
      await reloadConfig();
      await refreshStatus();
    } catch (e: any) {
      await refreshStatus().catch(() => {});
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  /// 保存草稿并应用：插件启用中则重新应用，使 registry/cafile 等设置立即写入 npm
  const save = async () => {
    setBusy("save");
    try {
      await replaceConfig(["plugin", "node"], saveValue());
      if (running()) {
        await api.enablePlugin("node");
        toast("配置已保存，NPM 加速已重新应用", "success");
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
    <Container title="NPM 加速" desc={node().tip ?? "npm / yarn 镜像与环境变量加速"}>
      <Card title="插件开关" extra={<Tag type={running() ? "success" : "default"}>{running() ? "已启用" : "未启用"}</Tag>}>
        <Field
          label="启用 NPM 加速"
          desc={serverOn() ? undefined : "加速服务未运行，请先在首页启动加速服务"}
        >
          <Switch checked={running()} onChange={toggle} disabled={busy() === "toggle"} />
        </Field>
        <Field label="随应用启动" desc="跟随加速服务：服务启动时自动拉起（服务未运行则不启动），并随首页「一键加速」同步开关">
          <Switch checked={!!draft().startWithApp} onChange={(v) => patch({ startWithApp: v })} />
        </Field>
        <div class="mt-3">
          <Button type={running() ? "danger" : "primary"} loading={busy() === "toggle"} onClick={toggle}>
            {running() ? "关闭加速" : "开启加速"}
          </Button>
        </div>
      </Card>

      <Card title="Registry 设置">
        <Field label="命令">
          <Input value={dsetting().command ?? "npm"} onInput={(v) => patch({ setting: { command: v } })} />
        </Field>
        <Field label="Registry 地址">
          <Input
            class="w-96"
            value={dsetting().registry ?? ""}
            onInput={(v) => patch({ setting: { registry: v } })}
          />
        </Field>
        <div class="mt-2 flex flex-wrap gap-2">
          <For each={registryList()}>
            {(r) => (
              <Button size="sm" onClick={() => patch({ setting: { registry: r.value } })}>
                {r.name}
              </Button>
            )}
          </For>
        </div>
        <Field label="严格校验 SSL">
          <Switch checked={!!dsetting()["strict-ssl"]} onChange={(v) => patch({ setting: { "strict-ssl": v } })} />
        </Field>
        <Field label="使用 CA 文件（npm cafile）" desc="写入「系统公共根证书 + DevSidecar CA」合并文件，立即对后续 npm 命令生效；不会替换掉公共根证书">
          <Switch checked={!!dsetting().cafile} onChange={(v) => patch({ setting: { cafile: v } })} />
        </Field>
      </Card>

      <Card title="环境变量" desc="开启加速时写入 HKCU 用户环境变量；已打开的终端和新进程不会自动继承，需重开终端。NODE_EXTRA_CA_CERTS 仅追加信任 DevSidecar CA">
        <JsonEditor
          height="220px"
          value={draft().envVariables ?? {}}
          onChange={(v) => set("envVariables", v)}
        />
      </Card>

      <SaveBar dirty={dirty()} saving={busy() === "save"} onSave={save} onReset={reset} text="插件配置已修改，尚未保存" />
    </Container>
  );
}
