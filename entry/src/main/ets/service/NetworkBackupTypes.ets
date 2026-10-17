export interface NetworkBackupPorts { http: number; socks: number; mixed: number; }
export interface NetworkBackupInbound {
  'allow-lan': boolean;
  'bind-address': string;
  authentication: string[];
  'skip-auth-prefixes': string[];
  'lan-allowed-ips': string[];
  'lan-disallowed-ips': string[];
}
export interface NetworkBackup { version: number; ports: NetworkBackupPorts | null; inbound: NetworkBackupInbound | null; }
export interface NetworkBackupSnapshot { settings: NetworkBackup; revision: string; error?: string; }
export interface NetworkBackupResult { revision: string; applied: boolean; error?: string; }

export function networkBackupSummary(value: NetworkBackup): string {
  const ports = value.ports;
  // Native validation fixes the types; Record access is required for YAML keys
  // containing hyphens by ArkTS. This view is never included in UI/report data.
  const flags = value.inbound ? JSON.parse(JSON.stringify(value.inbound)) as Record<string, boolean> : undefined;
  return (ports ? `HTTP ${ports.http} · SOCKS5 ${ports.socks} · 混合 ${ports.mixed}` : '端口跟随当前配置') +
    (value.inbound ? `；${flags!['allow-lan'] ? '允许' : '关闭'}局域网共享 · ${value.inbound.authentication.length} 个代理账号` : '；共享设置跟随当前配置');
}
