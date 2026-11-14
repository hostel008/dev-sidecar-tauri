import { Button, Card, Container, Tag } from "../components/ui";
import { api } from "../api";
import { humanBytes, setTraffic, toast, traffic } from "../store";

export default function TrafficPage() {
  return (
    <Container title="流量统计" desc="本地代理进出的流量与实时速率">
      <div class="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card title="累计流量">
          <div class="flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
            <div class="flex justify-between">
              <span>上传总量</span>
              <span>{humanBytes(traffic().upload)}</span>
            </div>
            <div class="flex justify-between">
              <span>下载总量</span>
              <span>{humanBytes(traffic().download)}</span>
            </div>
          </div>
        </Card>
        <Card title="实时速率">
          <div class="flex flex-col gap-2 text-sm" style={{ color: "var(--ds-text)" }}>
            <div class="flex justify-between">
              <span>上传速率</span>
              <Tag type="warn">{humanBytes(traffic().uploadSpeed)}/s</Tag>
            </div>
            <div class="flex justify-between">
              <span>下载速率</span>
              <Tag type="success">{humanBytes(traffic().downloadSpeed)}/s</Tag>
            </div>
          </div>
        </Card>
      </div>
      <Card title="操作">
        <Button
          type="danger"
          onClick={async () => {
            try {
              await api.resetTraffic();
              // 后端只重置计数器，前端信号需同步归零，避免空闲时长时间显示旧值
              setTraffic({ upload: 0, download: 0, uploadSpeed: 0, downloadSpeed: 0 });
              toast("已重置流量统计", "success");
            } catch (e: any) {
              toast(String(e), "error");
            }
          }}
        >
          重置统计
        </Button>
      </Card>
    </Container>
  );
}
