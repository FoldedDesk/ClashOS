export interface ProbeSample { index: number; delay: number; error: string; }
export interface ProbeSeries {
  name: string; url: string; total: number; samples: ProbeSample[];
  state: string; stopping: boolean;
}
export interface ProbeStatistics { completed: number; passed: number; failed: number; median: number; minimum: number; maximum: number; }

export function emptyProbeSeries(): ProbeSeries { return { name: '', url: '', total: 5, samples: [], state: 'idle', stopping: false }; }
export function probeStatistics(series: ProbeSeries): ProbeStatistics {
  const values: number[] = series.samples.filter((s: ProbeSample) => Number.isFinite(s.delay) && s.delay > 0).map((s: ProbeSample) => s.delay).sort((a: number, b: number) => a - b);
  const middle: number = Math.floor(values.length / 2);
  return { completed: series.samples.length, passed: values.length, failed: series.samples.length - values.length,
    median: values.length ? Math.round(values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2) : 0,
    minimum: values[0] || 0, maximum: values[values.length - 1] || 0 };
}
export function probeFailureText(error: string): string {
  const status = /Probe returned HTTP (\d{3}) outside expected status ([0-9/*-]+)$/.exec(error);
  if (status) return `目标返回 HTTP ${status[1]}（期望 ${status[2]}）`;
  if (error === 'HTTP probe response interrupted or timed out') return 'HTTP 响应中断或超时';
  if (error === 'HTTPS probe response interrupted or timed out') return 'HTTPS 响应中断或超时';
  if (error.includes('TLS peer closed the connection before handshake completed')) return '对端在 TLS 握手完成前关闭了连接';
  if (error.includes('TLS connection reset during handshake')) return 'TLS 握手期间连接被重置';
  if (error.includes('TLS handshake timed out')) return 'TLS 握手超时';
  if (error.includes('TLS certificate hostname mismatch')) return 'TLS 证书与服务器名称不匹配';
  if (error.includes('TLS certificate has expired')) return 'TLS 证书已过期';
  if (error.includes('TLS certificate is not valid yet')) return 'TLS 证书尚未生效';
  if (error.includes('TLS certificate is not trusted')) return 'TLS 证书不受信任';
  if (error.includes('TLS certificate verification failed')) return 'TLS 证书校验失败';
  if (error.includes('Proxy response authentication failed during TLS handshake')) return '代理响应认证失败';
  if (error.includes('TLS peer rejected the handshake')) return '对端拒绝了 TLS 握手';
  if (error.includes('TLS handshake transport read failed')) return 'TLS 握手期间网络读取失败';
  if (error.includes('TLS handshake transport write failed')) return 'TLS 握手期间网络发送失败';
  return error;
}
export function probeReport(series: ProbeSeries): string {
  const stats = probeStatistics(series);
  return [`ClashOS 节点连续检测`, `节点：${series.name}`, `目标：${series.url}`,
    `状态：${series.state === 'complete' ? '已完成' : series.state === 'cancelled' ? '已停止' : series.state === 'stale' ? '配置或连接状态已变化' : series.state === 'running' ? '检测中' : '未开始'}`,
    `已完成 ${stats.completed}/${series.total} · 成功 ${stats.passed} · 失败 ${stats.failed}`,
    `中位延迟 ${stats.median || '—'} ms · 最低 ${stats.minimum || '—'} ms · 最高 ${stats.maximum || '—'} ms`,
    ...series.samples.map((s: ProbeSample): string => `${s.index}. ${s.delay > 0 ? `${s.delay} ms` : `${probeFailureText(s.error)}\n   ${s.error}`}`)].join('\n');
}

export class ProbeSeriesController {
  private sequence: number = 0;
  private busy: boolean = false;
  private disposed: boolean = false;
  private current: ProbeSeries = emptyProbeSeries();
  private onChange: (state: ProbeSeries) => void = (_state: ProbeSeries): void => {};
  private probe: (name: string, url: string) => Promise<number>;
  private isCurrent: () => boolean;
  constructor(probe: (name: string, url: string) => Promise<number>, isCurrent: () => boolean = (): boolean => true) { this.probe = probe; this.isCurrent = isCurrent; }
  private publish(): void {
    this.onChange({ name: this.current.name, url: this.current.url, total: this.current.total, state: this.current.state, stopping: this.current.stopping,
      samples: this.current.samples.map((s: ProbeSample): ProbeSample => ({ index: s.index, delay: s.delay, error: s.error })) });
  }
  async run(name: string, url: string, count: number, onChange: (state: ProbeSeries) => void): Promise<void> {
    if (this.disposed || this.busy) throw new Error('检测正在进行或已关闭');
    if (!name || name === 'REJECT' || !/^https?:\/\/[^\s]+$/.test(url) || url.length > 4096 || !Number.isInteger(count) || count < 1 || count > 20)
      throw new Error('请输入 HTTP(S) 目标和 1 至 20 次检测');
    const sequence: number = ++this.sequence; this.busy = true; this.onChange = onChange;
    this.current = { name, url, total: count, samples: [], state: 'running', stopping: false };
    try {
      this.publish();
      for (let index: number = 1; index <= count; index++) {
        if (this.disposed || sequence !== this.sequence) return;
        if (!this.isCurrent()) { this.current.state = 'stale'; break; }
        if (this.current.stopping) break;
        let delay: number = 0; let error: string = '';
        try {
          delay = await this.probe(name, url);
          if (!Number.isFinite(delay) || delay <= 0) throw new Error('节点没有返回有效的延迟');
        } catch (failure) { delay = 0; error = ((failure as Error).message || '检测失败').slice(0, 1024); }
        if (this.disposed || sequence !== this.sequence) return;
        if (!this.isCurrent()) { this.current.state = 'stale'; break; }
        if (this.current.stopping) break;
        this.current.samples.push({ index, delay, error }); this.publish();
      }
      if (this.current.state !== 'stale') this.current.state = this.current.stopping ? 'cancelled' : 'complete';
    } finally {
      if (!this.disposed && sequence === this.sequence) { this.busy = false; this.publish(); }
    }
  }
  cancel(): void { if (this.busy && !this.disposed && !this.current.stopping) { this.current.stopping = true; this.publish(); } }
  dispose(): void { this.disposed = true; ++this.sequence; this.busy = false; }
}
