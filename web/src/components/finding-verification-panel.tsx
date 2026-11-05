"use client";

import * as React from "react";

import { CheckCircle2Icon, Clock3Icon, RefreshCwIcon, ShieldCheckIcon, XCircleIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import type { FindingStatus, FindingVerificationRun } from "@/lib/types";

function verdictLabel(run: FindingVerificationRun) {
  if (run.status === "pending") return "等待复核";
  if (run.status === "running") return "复核中";
  if (run.verdict === "confirmed") return "证据支持";
  if (run.verdict === "rejected") return "证据反证";
  return "证据不足";
}

function verdictIcon(run: FindingVerificationRun) {
  if (run.status !== "completed") return <Clock3Icon className="size-4" />;
  if (run.verdict === "confirmed") return <CheckCircle2Icon className="size-4" />;
  if (run.verdict === "rejected") return <XCircleIcon className="size-4" />;
  return <ShieldCheckIcon className="size-4" />;
}

function fmtTime(value?: string) {
  return value ? new Date(value).toLocaleString("zh-CN") : "—";
}

export function FindingVerificationPanel({
  findingId,
  findingStatus,
  readOnly,
}: {
  findingId: string;
  findingStatus: FindingStatus;
  readOnly?: boolean;
}) {
  const [runs, setRuns] = React.useState<FindingVerificationRun[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [retrying, setRetrying] = React.useState(false);

  const load = React.useCallback(async () => {
    try {
      const response = await api.findingVerificationRuns(findingId);
      setRuns(response);
    } catch (error) {
      toast.error("加载独立复核记录失败：" + (error as Error).message);
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  React.useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  const retry = async () => {
    setRetrying(true);
    try {
      await api.retryFindingVerification(findingId);
      toast.success("已重新加入独立复核队列");
      await load();
    } catch (error) {
      toast.error("重新排队失败：" + (error as Error).message);
    } finally {
      setRetrying(false);
    }
  };

  const latest = runs[0];
  const canRetry = !readOnly && findingStatus === "pending" && latest?.status === "completed";

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between gap-3">
        <CardTitle className="text-sm">独立证据复核</CardTitle>
        {canRetry && (
          <Button size="sm" variant="outline" onClick={retry} disabled={retrying}>
            <RefreshCwIcon className={retrying ? "size-3.5 animate-spin" : "size-3.5"} />
            重新复核
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-3">
        {loading && runs.length === 0 ? (
          <p className="text-sm text-muted-foreground">正在读取复核记录…</p>
        ) : runs.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {findingStatus === "pending" ? "暂无复核记录；候选漏洞提交后会自动进入只读复核队列。" : "该漏洞没有独立复核记录。"}
          </p>
        ) : (
          runs.map((run, index) => (
            <div key={run.id} className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 text-sm font-medium">
                  {verdictIcon(run)}
                  <span>复核 #{run.id}</span>
                  <Badge variant={run.verdict === "confirmed" ? "default" : "outline"}>{verdictLabel(run)}</Badge>
                </div>
                <span className="text-xs text-muted-foreground tabular-nums">{fmtTime(run.created_at)}</span>
              </div>
              {run.summary && <p className="text-sm leading-relaxed">{run.summary}</p>}
              {run.evidence?.length > 0 && (
                <div className="space-y-2 rounded-md bg-muted/50 p-3">
                  {run.evidence.map((item, i) => (
                    <div key={i} className="space-y-1 text-xs">
                      {item.quote && <code className="block whitespace-pre-wrap break-all">{item.quote}</code>}
                      {item.reason && <p className="text-muted-foreground">{item.reason}</p>}
                      {item.text && <p className="text-muted-foreground">{item.text}</p>}
                    </div>
                  ))}
                </div>
              )}
              {run.last_error && <p className="text-xs text-destructive">上次执行错误：{run.last_error}</p>}
              <p className="text-xs text-muted-foreground">
                尝试 {run.attempts} 次 · 开始 {fmtTime(run.started_at)} · 完成 {fmtTime(run.finished_at)}
              </p>
              {index < runs.length - 1 && <Separator />}
            </div>
          ))
        )}
        {findingStatus === "pending" && latest?.verdict === "inconclusive" && (
          <p className="text-xs text-muted-foreground">证据不足不会自动标记为误报；补充证据后可重新复核，或由人工调整处置状态。</p>
        )}
      </CardContent>
    </Card>
  );
}
