import { For, Show, createSignal, onMount } from "solid-js";
import { Button, Card, Container, Tag } from "../components/ui";
import { openExternal } from "../api";
import { toast } from "../store";

interface StatusResponse {
  status?: { indicator?: string; description?: string };
  components?: { name: string; status: string }[];
}

export default function GithubStatusPage() {
  const [data, setData] = createSignal<StatusResponse | null>(null);
  const [busy, setBusy] = createSignal(false);

  const load = async () => {
    setBusy(true);
    try {
      const res = await fetch("https://www.githubstatus.com/api/v2/summary.json");
      setData((await res.json()) as StatusResponse);
    } catch (e: any) {
      toast(`获取 GitHub 状态失败: ${e}`, "error");
    } finally {
      setBusy(false);
    }
  };

  onMount(load);

  const level = () => {
    const indicator = data()?.status?.indicator ?? "none";
    return indicator === "none" ? "success" : indicator === "minor" ? "warn" : "danger";
  };

  return (
    <Container title="GitHub 状态" desc="查看 GitHub 各服务的实时可用状态">
      <Card
        title="总体状态"
        extra={
          <Button size="sm" loading={busy()} onClick={load}>
            刷新
          </Button>
        }
      >
        <Show when={data()} fallback={<div class="text-xs" style={{ color: "var(--ds-text-soft)" }}>加载中…</div>}>
          <div class="flex items-center gap-2">
            <Tag type={level()}>{data()!.status?.indicator ?? "none"}</Tag>
            <span class="text-sm" style={{ color: "var(--ds-text)" }}>
              {data()!.status?.description ?? ""}
            </span>
          </div>
        </Show>
      </Card>

      <Card title="组件状态">
        <Show when={(data()?.components ?? []).length > 0}>
          <div class="flex flex-col gap-1">
            <For each={(data()?.components ?? []).slice(0, 12)}>
              {(c) => (
                <div class="flex justify-between py-0.5 text-xs" style={{ color: "var(--ds-text)" }}>
                  <span class="truncate">{c.name}</span>
                  <Tag type={c.status === "operational" ? "success" : "warn"}>{c.status}</Tag>
                </div>
              )}
            </For>
          </div>
        </Show>
        <div class="mt-3">
          <Button size="sm" onClick={() => openExternal("https://www.githubstatus.com/")}>
            打开 GitHub Status
          </Button>
        </div>
      </Card>
    </Container>
  );
}
