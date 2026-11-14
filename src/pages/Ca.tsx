import { createSignal, onMount } from "solid-js";
import { Button, Card, Container, Field, Tag } from "../components/ui";
import { api, openPath } from "../api";
import { toast } from "../store";

export default function CaPage() {
  const [exists, setExists] = createSignal(false);
  const [trusted, setTrusted] = createSignal(false);
  const [path, setPath] = createSignal("");
  const [busy, setBusy] = createSignal("");

  const refresh = async () => {
    setBusy("refresh");
    try {
      const [e, t, p] = await Promise.all([api.isCaExists(), api.canTrustCa(), api.getCaCertPath()]);
      setExists(!!e);
      setTrusted(!!t);
      setPath(p ?? "");
      toast(
        e ? (t ? "已刷新：根证书已安装" : "已刷新：根证书已生成，尚未安装") : "已刷新：根证书尚未生成",
        e ? (t ? "success" : "warn") : "error",
      );
    } catch (e: any) {
      toast(`刷新状态失败: ${e}`, "error");
    } finally {
      setBusy("");
    }
  };

  const openFile = async () => {
    try {
      await openPath(path());
      toast("已打开证书文件", "success");
    } catch (e: any) {
      toast(`打开文件失败: ${e}`, "error");
    }
  };

  onMount(refresh);

  const install = async () => {
    setBusy("install");
    try {
      const msg = await api.setupCa();
      toast(msg, "success");
      await refresh();
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy("");
    }
  };

  return (
    <Container title="安装证书" desc="将 DevSidecar 根证书加入系统信任区，避免浏览器提示不安全">
      <Card
        title="根证书状态"
        extra={<Tag type={exists() ? (trusted() ? "success" : "warn") : "danger"}>{exists() ? (trusted() ? "已安装" : "已生成·未安装") : "未生成"}</Tag>}
      >
        <Field label="证书路径" desc={path() || "—"}>
          <Button onClick={openFile} disabled={!path()}>
            打开文件
          </Button>
        </Field>
        <div class="mt-3 flex gap-2">
          <Button type="primary" loading={busy() === "install"} onClick={install} disabled={!exists() || busy() === "install"}>
            安装根证书
          </Button>
          <Button loading={busy() === "refresh"} onClick={refresh}>
            刷新状态
          </Button>
        </div>
        <div class="mt-4 text-xs" style={{ color: "var(--ds-text-soft)" }}>
          <div>Windows：写入「受信任的根证书颁发机构」（当前用户）。</div>
          <div>macOS：写入登录钥匙串并设置为始终信任。</div>
          <div>Linux：复制到 /usr/local/share/ca-certificates 并执行 update-ca-certificates（需要权限）。</div>
        </div>
      </Card>
    </Container>
  );
}
