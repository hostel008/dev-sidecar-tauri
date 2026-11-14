import { createSignal } from "solid-js";
import { Button, Card, Container, Input, Tag } from "../components/ui";
import { api } from "../api";
import { toast } from "../store";

export default function CheckPage() {
  const [host, setHost] = createSignal("github.com");
  const [result, setResult] = createSignal<any>(null);
  const [busy, setBusy] = createSignal(false);

  const check = async () => {
    setBusy(true);
    try {
      const res = await api.networkCheck(host().trim() || "github.com");
      setResult(res);
    } catch (e: any) {
      toast(String(e), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Container title="网络检测" desc="检测域名的 DNS 解析、TCP 连通性与 TLS 握手耗时">
      <Card title="检测">
        <div class="flex items-center gap-2">
          <Input class="w-72" value={host()} onInput={setHost} placeholder="请输入域名" />
          <Button type="primary" loading={busy()} onClick={check}>
            开始检测
          </Button>
        </div>

        {result() && (
          <div class="mt-4 flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
            <div class="flex justify-between">
              <span>域名</span>
              <span>{result().hostname}</span>
            </div>
            <div class="flex justify-between">
              <span>DNS 解析结果</span>
              <span>{(result().dns ?? []).join(", ") || "无"}</span>
            </div>
            <div class="flex justify-between">
              <span>TCP 连通（域名）</span>
              <Tag type={result().tcp != null ? "success" : "danger"}>
                {result().tcp != null ? `${result().tcp} ms` : "失败"}
              </Tag>
            </div>
            <div class="flex justify-between">
              <span>TCP 连通（解析 IP）</span>
              <Tag type={result().tls != null ? "success" : "danger"}>
                {result().tls != null ? `${result().tls} ms` : "失败"}
              </Tag>
            </div>
            <div class="flex justify-between">
              <span>总耗时</span>
              <span>{result().cost} ms</span>
            </div>
          </div>
        )}
      </Card>
    </Container>
  );
}
