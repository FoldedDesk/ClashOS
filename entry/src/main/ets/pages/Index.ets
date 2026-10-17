import { VergePalette } from '../theme/VergeTheme';
import { DEFAULT_ACCENT } from '../theme/VergeTheme';
import { AppearanceController } from '../service/AppearanceController';
import { sameAppearance } from '../theme/AppearanceTypes';
import { NativeStyles } from '../theme/NativeStyles';
import { NativeStyleDialog } from '../components/NativeStyleDialog';
import { GroupIconStore } from '../service/GroupIconStore';
import { GroupIconEntry, iconImageUrl } from '../service/GroupIconTypes';
import { pickGroupIcon } from '../service/GroupIconPicker';
import { GroupIconDialog } from '../components/GroupIconDialog';
import { ProxyGroupIcon } from '../components/ProxyGroupIcon';
import { RuntimeConfigDialog } from '../components/RuntimeConfigDialog';
import { InboundSettingsDialog } from '../components/InboundSettingsDialog';
import { SnifferSettingsDialog } from '../components/SnifferSettingsDialog';
import { ProbeSeriesDialog } from '../components/ProbeSeriesDialog';
import { SystemNetworkDialog } from '../components/SystemNetworkDialog';
import { probeFailureText } from '../service/ProbeSeriesController';
import { ClashInboundSettings, ClashInboundChanges } from '../service/ClashApi';
import { ClashRuntimeConfig } from '../service/ClashApi';
import { ProxyPortsDialog } from '../components/ProxyPortsDialog';
import { ControllerAccessDialog } from '../components/ControllerAccessDialog';
import { ControllerAccessStore, ControllerAccessSnapshot } from '../service/ControllerAccessStore';
import { ControllerAccessController, localControllerCredential } from '../service/ControllerAccessController';
import { BackupManagerDialog } from '../components/BackupManagerDialog';
import { BackupStore } from '../service/BackupStore';
import { BackupRestoreCoordinator, BackupRuntime } from '../service/BackupRestoreCoordinator';
import { BackupGlobals, BackupRestoreSelection, BackupRestoreResult } from '../service/BackupTypes';
import { RuleEditorDialog } from '../components/RuleEditorDialog';
import { RuleEdits, parseRuleEditsText } from '../service/RuleEditsTypes';
import { ObjectEditorDialog } from '../components/ObjectEditorDialog';
import { ObjectEdits, parseObjectEditsText } from '../service/ObjectEditsTypes';
import { NodeImportDialog } from '../components/NodeImportDialog';
import { NodeLinkImport } from '../service/NodeLinkTypes';
import { MergeEditorDialog } from '../components/MergeEditorDialog';
import { ScriptEditorDialog } from '../components/ScriptEditorDialog';
import { ScriptPreview } from '../service/ConfigMergeTypes';
import { ClashProxyPorts } from '../service/ClashApi';
import { abilityAccessCtrl, common } from '@kit.AbilityKit';
import { pasteboard } from '@kit.BasicServicesKit';
import { connection } from '@kit.NetworkKit';
import { util } from '@kit.ArkTS';
import { AppSettings, SettingsStore } from '../service/SettingsStore';
import { ProfileEditorDialog, ProfileInfoDialog } from '../components/ProfileDialogs';
import { ClashApi, ClashCoreLog, ClashConnection, ClashProxyGroup, ClashProxyNode, ClashProxyProvider, ClashRule, ClashRuleProvider, ClashRulePayload, ClashSnapshot, CoreDiagnostics } from '../service/ClashApi';
import { ClashNativeCore } from '../service/ClashNativeCore';
import { ClashProfile, ProfileStore, MergeEditSnapshot, DEFAULT_PROFILE } from '../service/ProfileStore';
import { SubscriptionOptions, subscriptionTraffic, subscriptionExpiry, subscriptionUrl } from '../service/SubscriptionTypes';
import { SubscriptionImport, subscriptionImports } from '../service/SubscriptionImport';
import { dialogActivity } from '../service/DialogActivity';
import { MessageDialog, MessageDialogOptions } from '../components/MessageDialog';
import { VpnTunnelService } from '../service/VpnTunnelService';
import { CoreRuntime, VpnState, emptyRuntime } from '../service/CoreSessionTypes';
import { CoreSessionCoordinator } from '../service/CoreSessionCoordinator';
import { TextViewerDialog } from '../components/TextViewerDialog';
import { ClashDnsAnswer, ClashDnsRecord, ClashDnsStatus } from '../service/ClashApi';
import { ClashGeoResource, ClashGeoStatus } from '../service/ClashApi';

interface UiLogEntry {
  id: number;
  time: string;
  level: string;
  message: string;
}

interface SummaryCardOptions {
  title: string;
  value: string;
  detail: string;
  source: Resource;
  color: string;
}

interface SettingRowOptions {
  title: string;
  detail: string;
  value: string;
}

@Entry
@Component
struct Index {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  @State appearanceMode: string = 'system';
  @State accentInput: string = DEFAULT_ACCENT;
  @State appearanceError: string = '';
  private appearanceController: AppearanceController | undefined = undefined;
  private groupIconStore?: GroupIconStore;
  @State groupIcons: GroupIconEntry[] = [];
  @State groupIconRevision: number = 0;
  private accentOptions: string[] = ['#3478F6', '#8B5CF6', '#199A70', '#D94C86', '#D87724', '#64748B'];
  private accentNames: string[] = ['蓝色', '紫色', '绿色', '粉色', '橙色', '灰色'];
  @State selectedTab: number = 0;
  @State isRunning: boolean = false;
  @State selectedProxy: string = '';
  @State @Watch('onNoticeChanged') notice: string = '';
  @State coreConnected: boolean = false;
  @State coreVersion: string = '未连接';
  @State coreMode: string = 'Rule';
  @State coreError: string = '';
  @State internalCore: boolean = false;
  @State activeConnections: number = 0;
  @State downloadTotal: number = 0;
  @State uploadTotal: number = 0;
  @State coreMemory: number = 0;
  @State ruleCount: number = 0;
  @State rules: ClashRule[] = [];
  @State ruleQuery: string = '';
  @State ruleProviders: ClashRuleProvider[] = [];
  @State showRuleProviders: boolean = false;
  @State ruleProviderQuery: string = '';
  @State requestingRuleProviders: string[] = [];
  @State proxyGroups: ClashProxyGroup[] = [];
  @State proxyProviders: ClashProxyProvider[] = [];
  @State showProviderCollections: boolean = false;
  @State providerQuery: string = '';
  @State expandedProviders: string[] = [];
  @State requestingProviders: string[] = [];
  @State proxyNodes: ClashProxyNode[] = [];
  @State testingNodes: string[] = [];
  @State delayResults: Record<string, number> = {};
  @State delayErrors: Record<string, string> = {};
  @State batchTesting: boolean = false;
  @State proxySort: string = 'default';
  @State connections: ClashConnection[] = [];
  @State profiles: ClashProfile[] = [];
  @State profileRevision: number = 0;
  @State activeProfileId: string = '';
  @State temporaryConfig: boolean = false;
  @State endpoint: string = 'http://127.0.0.1:9090';
  @State secret: string = '';
  @State syncing: boolean = false;
  @State dnsName: string = 'google.com';
  @State dnsServer: string = '';
  @State dnsType: string = 'A';
  @State dnsBusy: boolean = false;
  @State dnsError: string = '';
  @State dnsAnswer: ClashDnsAnswer | undefined = undefined;
  @State dnsStatus: ClashDnsStatus | undefined = undefined;
  @State geoStatus: ClashGeoStatus | undefined = undefined;
  @State geoBusy: string[] = [];

  private navItems: string[] = ['首页', '代理', '规则', '连接', '订阅', '日志', '设置', '测试'];
  private navOrder: number[] = [0, 1, 4, 3, 2, 5, 7, 6];
  private navIcons: Resource[] = [
    $r('app.media.verge_home'), $r('app.media.verge_proxies'), $r('app.media.verge_rules'),
    $r('app.media.verge_connections'), $r('app.media.verge_profiles'),
    $r('app.media.verge_logs'), $r('app.media.verge_settings'), $r('app.media.verge_test')
  ];
  private iconFilters: Map<string, ColorFilter> = new Map();
  @State windowWidth: number = 1280;
  @State hoverTab: number = -1;
  @State hoveredAction: string = '';
  @State hoveredProxyNode: string = '';
  @State hoveredProfile: string = '';
  @State focusedProxyGroup: string = '';
  @State hoveredProxyGroup: string = '';
  @State proxyQuery: string = '';
  @State connectionQuery: string = '';
  @State profileQuery: string = '';
  @State collapsedGroups: string[] = [];
  @State showProxySearch: boolean = false;
  private knownGroupNames: string[] = [];
  @State logFilter: string = 'ALL';
  @State logEntries: UiLogEntry[] = [];
  @State downloadRate: number = 0;
  @State uploadRate: number = 0;
  @State downloadSamples: number[] = [];
  @State uploadSamples: number[] = [];
  @State chartWidth: number = 600;
  @State lastSyncTime: string = '尚未同步';
  private lastSampleAt: number = 0;
  private previousDownload: number = 0;
  private previousUpload: number = 0;
  private nextLogId: number = 0;
  private contentScroller: Scroller = new Scroller();
  private navigationScroller: Scroller = new Scroller();
  private navigationPositions: Record<number, number> = {};
  private groupPositions: Record<string, number> = {};
  private contentTop: number = 0;
  @State selectedGroupName: string = '';
  private coreApi: ClashApi = new ClashApi();
  private nativeCore: ClashNativeCore = new ClashNativeCore();
  private controllerAccessStore?: ControllerAccessStore;
  @State controllerAccessStatus: string = '未启用';
  private profileStore: ProfileStore | undefined = undefined;
  private refreshTimer: number = -1;
  private subscriptionTimer: number = -1;
  private settingsStore: SettingsStore | undefined = undefined;
  private dialogController: CustomDialogController | undefined = undefined;
  private messageDialogController: CustomDialogController | undefined = undefined;
  private savedMode: string = '';
  private mutationVersion: number = 0;
  @State subscriptionUrl: string = '';
  @State updatingProfiles: string[] = [];
  @State pendingProxy: string = '';
  @State httpPort: number = 0;
  @State proxyHost: string = '127.0.0.1';
  @State allowLan: boolean = false;
  @State sniffing: boolean = false;
  @State snifferBusy: boolean = false;
  @State socksPort: number = 0;
  @State diagnosing: boolean = false;
  @State testUrl: string = 'https://www.gstatic.com/generate_204';
  @State tunEnabled: boolean = false;
  @State tunBusy: boolean = false;
  @State tunError: string = '';
  private vpnService: VpnTunnelService | undefined = undefined;
  private coreSession: CoreSessionCoordinator | undefined = undefined;
  private connectedRuntime: CoreRuntime = emptyRuntime();
  private pageActive: boolean = true;
  private initializingCore: boolean = true;
  @State backgroundCore: boolean = false;
  @State systemProxyHost: string = '';
  @State systemProxyPort: number = 0;
  @State systemProxyError: string = '';
  @State systemProxyOpening: boolean = false;
  @StorageLink('clashosForeground') @Watch('onAbilityForeground') foregroundRevision: number = 0;
  private systemProxyReadVersion: number = 0;
  @StorageLink('clashosImportRevision') @Watch('reviewNextImport') importRevision: number = 0;

  aboutToAppear(): void {
    this.pageActive = true;
    this.initializingCore = true;
    dialogActivity.onIdle = (): void => { setTimeout(() => this.reviewNextImport(), 0); };
    let defaultConfigPath: string = '';
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      this.nativeCore.configureControllerStore(context.filesDir);
      this.controllerAccessStore = new ControllerAccessStore(context.filesDir, (fd: number) => this.nativeCore.protectFile(fd));
      this.refreshControllerAccessStatus();
      try {
        this.appearanceController = new AppearanceController(context, (fd: number) => this.nativeCore.protectFile(fd));
        this.appearanceMode = this.appearanceController.settings.mode;
        this.accentInput = this.appearanceController.settings.accent;
        this.appearanceError = this.appearanceController.loadError;
      } catch (_) { this.appearanceError = '外观初始化失败，请重新打开应用'; }
      this.groupIconStore = new GroupIconStore(context.filesDir, (fd: number) => this.nativeCore.protectFile(fd));
      try { this.groupIcons = this.groupIconStore.load(); }
      catch (_) { this.notice = '代理组图标设置无法读取，已恢复默认显示'; }
      this.vpnService = new VpnTunnelService(context.filesDir, context.abilityInfo.bundleName);
      this.coreApi.setLocalCredentialProvider((endpoint: string): string | undefined => {
        const store: ControllerAccessStore | undefined = this.controllerAccessStore;
        return store ? localControllerCredential(endpoint, store, this.nativeCore.info(), this.vpnService?.status()) : undefined;
      });
      this.coreSession = new CoreSessionCoordinator(this.nativeCore, this.vpnService);
      this.settingsStore = new SettingsStore(context);
      try {
        const settings: AppSettings = this.settingsStore.load();
        this.endpoint = settings.endpoint;
        this.secret = settings.secret;
        this.activeProfileId = settings.activeProfileId;
        this.savedMode = settings.mode;
        this.testUrl = settings.testUrl;
      } catch (_) {
        this.notice = '设置文件无法读取，已使用默认设置';
      }
      this.profileStore = new ProfileStore(context);
      this.profiles = this.profileStore.list();
      const selected: ClashProfile | undefined = this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId) ?? this.profiles[0];
      if (selected !== undefined) {
        this.activeProfileId = selected.id;
        defaultConfigPath = selected.path;
      }
    } catch (error) {
      this.notice = `配置目录不可用：${(error as Error).message}`;
    }
    this.coreApi.setConfig(this.endpoint, this.secret);
    this.refreshSystemProxy();
    this.initializeCore(defaultConfigPath);
    this.refreshTimer = setInterval(() => this.refreshCore(), 5000);
    this.subscriptionTimer = setInterval(() => this.autoUpdateSubscriptions(), 60000);
  }

  private async initializeCore(path: string): Promise<void> {
    try { await this.coreSession?.initialize(path, this.savedMode); }
    catch (error) { this.notice = `内核启动失败：${(error as Error).message}`; }
    this.initializingCore = false;
    if (!this.pageActive) return;
    await this.refreshCore();
    if (this.coreConnected && !this.internalCore && this.savedMode.length > 0) await this.changeMode(this.savedMode);
    this.autoUpdateSubscriptions();
    this.reviewNextImport();
  }

  private reviewNextImport(): void {
    if (!this.pageActive || this.initializingCore || !this.profileStore || dialogActivity.busy()) return;
    const error: string = subscriptionImports.takeError();
    if (error) this.notice = error;
    const request: SubscriptionImport | undefined = subscriptionImports.take();
    if (!request) return;
    try {
      this.selectedTab = 4;
      this.openProfileInfo(undefined, request);
    } catch (_) {
      subscriptionImports.finish(request.id);
      this.notice = '无法打开订阅导入窗口，请重新打开链接';
    }
  }

  private showMessageDialog(options: MessageDialogOptions): void {
    this.messageDialogController = new CustomDialogController({ builder: MessageDialog({ options }), autoCancel: true, customStyle: true });
    this.messageDialogController.open();
  }

  private persistSettings(): void {
    try {
      this.settingsStore?.save({ activeProfileId: this.activeProfileId, endpoint: this.endpoint, secret: this.secret,
        mode: this.savedMode, testUrl: this.testUrl });
    } catch (error) {
      this.notice = `设置保存失败：${(error as Error).message}`;
    }
  }

  aboutToDisappear(): void {
    this.pageActive = false;
    dialogActivity.onIdle = undefined;
    this.appearanceController?.dispose();
    if (this.subscriptionTimer >= 0) clearInterval(this.subscriptionTimer);
    this.dialogController?.close();
    this.messageDialogController?.close();
    this.persistSettings();
    if (this.refreshTimer >= 0) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = -1;
    }
    this.coreSession?.dispose().catch(() => {});
  }

  private async refreshCore(): Promise<void> {
    if (this.syncing || this.tunBusy || this.initializingCore || !this.pageActive) {
      return;
    }
    this.refreshControllerAccessStatus();
    this.syncing = true;
    const version: number = this.mutationVersion;
    const snapshot: ClashSnapshot = await this.coreApi.readSnapshot();
    if (!this.pageActive) { this.syncing = false; return; }
    if (version !== this.mutationVersion) {
      this.syncing = false;
      await this.refreshCore();
      return;
    }
    if (!snapshot.connected) {
      const path: string = this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)?.path ?? '';
      try {
        if (await this.coreSession?.recoverLocalIfStopped(path, this.savedMode)) {
          this.addLog('WARN', '后台服务已结束，已恢复前台内核');
          this.syncing = false;
          await this.refreshCore();
          return;
        }
      } catch (error) { this.notice = `恢复内核失败：${(error as Error).message}`; }
    }
    if (this.coreConnected !== snapshot.connected) {
      this.addLog(snapshot.connected ? 'INFO' : 'WARN', snapshot.connected ? `已连接 ${snapshot.version}` : '内核连接已断开');
      if (snapshot.connected && this.notice.endsWith('将在内核启动后加载')) this.notice = `已加载「${this.activeProfileName()}」`;
    }
    this.sampleTraffic(snapshot);
    this.refreshSystemProxy();
    this.coreConnected = snapshot.connected;
    this.isRunning = snapshot.connected;
    this.coreVersion = snapshot.version;
    this.coreMode = snapshot.mode;
    this.temporaryConfig = snapshot.temporaryConfig === true;
    this.httpPort = snapshot.httpPort;
    this.socksPort = snapshot.socksPort;
    this.proxyHost = snapshot.proxyHost ?? '127.0.0.1';
    this.allowLan = snapshot.allowLan === true;
    this.sniffing = snapshot.sniffing === true;
    this.coreError = snapshot.error;
    const local: CoreRuntime = this.nativeCore.info();
    if (!snapshot.connected && (local.error ?? '').length > 0) this.coreError = local.error ?? '';
    const background: VpnState | undefined = this.vpnService?.status();
    this.backgroundCore = snapshot.connected && snapshot.instance.length > 0 && background?.core.running === true &&
      background.core.instance === snapshot.instance;
    this.internalCore = this.backgroundCore || (snapshot.connected && local.running && local.instance === snapshot.instance);
    this.connectedRuntime = { running: snapshot.connected, instance: snapshot.instance, configPath: snapshot.configPath,
      mode: snapshot.mode, controllerPort: this.backgroundCore ? background!.core.controllerPort : local.controllerPort,
      httpPort: snapshot.httpPort, socksPort: snapshot.socksPort, temporaryConfig: this.temporaryConfig };
    if (this.internalCore && !this.temporaryConfig) {
      const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.path === snapshot.configPath);
      const profileId: string = profile?.id ?? this.activeProfileId;
      if (profileId !== this.activeProfileId || this.savedMode !== snapshot.mode) {
        this.activeProfileId = profileId;
        this.savedMode = snapshot.mode;
        this.persistSettings();
      }
    }
    this.activeConnections = snapshot.connectionCount;
    this.downloadTotal = snapshot.downloadTotal;
    this.coreMemory = snapshot.memoryBytes ?? 0;
    this.uploadTotal = snapshot.uploadTotal;
    this.ruleCount = snapshot.ruleCount;
    this.rules = snapshot.rules;
    const groupNames: string[] = snapshot.groups.map((group: ClashProxyGroup) => group.name);
    const newGroups: string[] = groupNames.filter((name: string) => this.knownGroupNames.indexOf(name) < 0);
    this.collapsedGroups = [...this.collapsedGroups.filter((name: string) => groupNames.indexOf(name) >= 0), ...newGroups];
    this.knownGroupNames = groupNames;
    if (groupNames.indexOf(this.focusedProxyGroup) < 0) this.focusedProxyGroup = groupNames[0] ?? '';
    this.proxyGroups = snapshot.groups;
    this.proxyProviders = snapshot.providers;
    this.ruleProviders = snapshot.ruleProviders;
    this.proxyNodes = snapshot.nodes;
    snapshot.logs.forEach((entry: ClashCoreLog) => {
      const timestamp: Date = new Date(entry.time);
      const item: UiLogEntry = { id: this.nextLogId++, time: Number.isNaN(timestamp.getTime()) ? this.clockText(new Date()) : this.clockText(timestamp),
        level: entry.type === 'error' ? 'ERROR' : entry.type === 'warning' || entry.type === 'warn' ? 'WARN' : entry.type === 'debug' ? 'DEBUG' : 'INFO', message: entry.payload };
      this.logEntries = [...this.logEntries.slice(-299), item];
    });
    this.connections = snapshot.connections;
    this.refreshTunnelState();
    if (snapshot.groups.length > 0) {
      const selectedGroup: ClashProxyGroup | undefined = snapshot.groups.find((group: ClashProxyGroup) => group.name === this.selectedGroupName);
      const firstGroup: ClashProxyGroup = selectedGroup ?? snapshot.groups[0];
      this.selectedGroupName = firstGroup.name;
      this.selectedProxy = firstGroup.now || firstGroup.lastSelected || (this.isBalancedGroup(firstGroup) ? '按请求分配节点' : '');
    } else {
      this.selectedGroupName = '';
      this.selectedProxy = '';
    }
    if (!snapshot.connected) {
      this.proxyGroups = [];
      this.connections = [];
      this.selectedGroupName = '';
      this.selectedProxy = '';
    }
    if (!snapshot.connected && this.selectedTab === 0) {
      this.notice = this.coreError.length > 0 ? `内核未连接：${this.coreError}` : '未连接 Clash 内核：请在设置中检查 External Controller 地址';
    }
    this.syncing = false;
    this.refreshGeoStatus();
  }

  private async showLicenses(): Promise<void> {
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const bytes: Uint8Array = await context.resourceManager.getRawFileContent('OPEN_SOURCE_NOTICES.txt');
      const content: string = util.TextDecoder.create('utf-8').decodeToString(bytes);
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({
        builder: TextViewerDialog({ title: '开源许可', content }), autoCancel: true, customStyle: true
      });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开许可文件：${(error as Error).message}`; }
  }

  private refreshTunnelState(): void {
    if (this.tunBusy || this.vpnService === undefined) return;
    const state: VpnState = this.vpnService.status();
    const wasEnabled: boolean = this.tunEnabled;
    this.tunEnabled = ['running', 'updating'].indexOf(state.state) >= 0 && state.core.running;
    this.tunError = state.state === 'error' ? state.error : '';
    if (wasEnabled && !this.tunEnabled && this.tunError.length > 0) this.notice = this.tunError;
  }

  private async setTunEnabled(enabled: boolean, reason: string = ''): Promise<void> {
    if (this.tunBusy || this.vpnService === undefined || this.coreSession === undefined) return;
    if (enabled && (!this.internalCore || !this.coreConnected || this.socksPort <= 0)) {
      this.notice = '请先连接内置内核并开启 SOCKS5 端口';
      return;
    }
    this.tunBusy = true;
    this.mutationVersion++;
    this.tunError = '';
    try {
      if (enabled) await this.coreSession.enableTunnel();
      else await this.coreSession.disableTunnel(this.internalCore ? this.connectedRuntime : undefined);
      if (this.pageActive) {
        this.tunEnabled = enabled;
        this.notice = reason || (enabled ? 'TUN 已开启，后台内核会在窗口关闭后继续运行' : 'TUN 已关闭，已恢复前台内核');
      }
    } catch (error) {
      this.tunEnabled = ['running', 'updating'].indexOf(this.vpnService.status().state) >= 0;
      this.tunError = (error as Error).message || 'VPN 操作失败';
      this.notice = this.tunError;
    } finally {
      this.tunBusy = false;
      this.mutationVersion++;
      if (this.pageActive) await this.refreshCore();
    }
  }

  private async connectCore(): Promise<void> {
    this.persistSettings();
    this.coreApi.setConfig(this.endpoint.trim().replace(/\/$/, ''), this.secret.trim());
    await this.refreshCore();
    if (this.coreConnected) {
      this.notice = `已连接 Clash ${this.coreVersion}`;
    } else {
      this.notice = `连接失败：${this.endpoint}`;
    }
  }

  private async chooseProxy(groupName: string, name: string, closeConnections: boolean = false): Promise<void> {
    const group: ClashProxyGroup | undefined = this.proxyGroups.find((item: ClashProxyGroup) => item.name === groupName);
    if (group !== undefined && this.isBalancedGroup(group)) { await this.testNode(name); return; }
    if (this.tunBusy) { this.notice = '内核正在切换，请稍后重试'; return; }
    if (!this.coreConnected) { this.notice = '当前未连接内核'; return; }
    if (this.pendingProxy.length > 0) return;
    this.pendingProxy = name;
    this.mutationVersion++;
    try {
      await this.coreApi.selectProxy(groupName, name);
      this.mutationVersion++;
      this.selectedGroupName = groupName;
      this.selectedProxy = name;
      this.markProxySelection(groupName, name);
      this.notice = `${groupName} 已切换到 ${name}`;
      if (closeConnections) {
        const count: number = await this.coreApi.closeProxyConnections(groupName);
        this.notice = `已切换到 ${name}，关闭 ${count} 个组内连接`;
      }
      await this.refreshCore();
    } catch (error) {
      this.notice = `切换失败：${(error as Error).message}`;
    } finally {
      this.pendingProxy = '';
    }
  }

  private markProxySelection(groupName: string, name: string): void {
    const updatedGroups: ClashProxyGroup[] = [];
    this.proxyGroups.forEach((group: ClashProxyGroup) => {
      if (group.name === groupName) {
        updatedGroups.push({
          name: group.name,
          type: group.type,
          now: name,
          proxies: group.proxies,
          checking: group.checking,
          manual: group.manual,
          strategy: group.strategy,
          lastSelected: group.lastSelected
        });
      } else {
        updatedGroups.push(group);
      }
    });
    this.proxyGroups = updatedGroups;
  }

  private async changeMode(mode: string): Promise<void> {
    if (this.tunBusy) { this.notice = '内核正在切换，请稍后重试'; return; }
    if (!this.coreConnected) {
      this.notice = '请先连接 Clash 内核';
      return;
    }
    try {
      await this.coreApi.setMode(mode);
      this.coreMode = mode;
      this.savedMode = mode;
      this.mutationVersion++;
      this.persistSettings();
      this.notice = `运行模式已切换为 ${mode}`;
      await this.refreshCore();
    } catch (error) {
      this.notice = `模式切换失败：${(error as Error).message}`;
    }
  }

  private async importProfile(): Promise<void> {
    if (this.profileStore === undefined) return;
    try {
      const profile: ClashProfile | undefined = await this.profileStore.pickAndImport();
      if (profile === undefined) return;
      this.reloadProfiles();
      await this.activateProfile(profile);
    } catch (error) {
      this.notice = `导入失败：${(error as Error).message}`;
    }
  }

  private async activateProfile(profile: ClashProfile, requireApplied: boolean = false): Promise<void> {
    if (this.tunBusy) { this.notice = '内核正在切换，请稍后重试'; if (requireApplied) throw new Error(this.notice); return; }
    if (!this.coreConnected) {
      if (requireApplied) throw new Error('内核连接已变化');
      this.activeProfileId = profile.id;
      this.persistSettings();
      this.notice = `已选择「${profile.name}」，将在内核启动后加载`;
      return;
    }
    this.mutationVersion++;
    try {
      await this.coreApi.loadConfig(profile.path);
      if (this.savedMode.length > 0) await this.coreApi.setMode(this.savedMode);
      this.mutationVersion++;
      this.activeProfileId = profile.id;
      this.delayResults = {};
      this.delayErrors = {};
      this.knownGroupNames = [];
      this.collapsedGroups = [];
      this.dnsAnswer = undefined;
      this.dnsServer = '';
      this.dnsStatus = undefined;
      this.geoStatus = undefined;
      this.dnsError = '';
      this.persistSettings();
      await this.refreshCore();
      this.notice = `已加载配置「${profile.name}」`;
      if(this.selectedTab === 7) await this.refreshDnsStatus();
    } catch (error) {
      this.notice = `加载失败：${(error as Error).message}`;
      if (requireApplied) throw new Error((error as Error).message || '配置未能应用');
    }
  }

  private async openRuntimeConfig(): Promise<void> {
    if (!this.coreConnected || !this.internalCore) { this.notice = '请先连接内置内核'; return; }
    if (this.tunBusy) { this.notice = '内核正在切换，请稍后重试'; return; }
    try {
      const initial: ClashRuntimeConfig = await this.coreApi.runtimeConfig();
      const instance: string = this.connectedRuntime.instance;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({
        builder: RuntimeConfigDialog({ initial,
          onSave: async (changed: ClashRuntimeConfig): Promise<void> => {
            if (this.tunBusy || !this.internalCore || this.connectedRuntime.instance !== instance) throw new Error('当前内核已变化，请重新打开运行设置');
            ++this.mutationVersion;
            try { await this.coreApi.saveRuntimeConfig(initial, changed); }
            finally { ++this.mutationVersion; }
            await this.refreshCore();
            this.notice = '内核运行设置已应用，重新加载配置后恢复配置中的设置';
          },
          onReload: async (): Promise<void> => {
            if (this.tunBusy || this.tunEnabled || !this.internalCore || this.connectedRuntime.instance !== instance) throw new Error('请先关闭虚拟网卡并确认当前内核');
            const current: ClashRuntimeConfig = await this.coreApi.runtimeConfig();
            if (current.path !== initial.path || current.revision !== initial.revision) throw new Error('当前配置已变化，请重新打开运行设置');
            ++this.mutationVersion;
            try { await this.coreApi.loadConfig('', initial); }
            finally { ++this.mutationVersion; }
            await this.refreshCore();
            this.notice = '已重新加载保存的配置';
          }
        }), autoCancel: false, customStyle: true
      });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开运行设置：${(error as Error).message}`; }
  }

  private profileIsActive(id: string): boolean { return !this.temporaryConfig && id === this.activeProfileId; }

  private async setSniffing(enabled: boolean): Promise<void> {
    if (this.snifferBusy || enabled === this.sniffing) return;
    if (!this.coreConnected || !this.internalCore || this.tunBusy) { this.notice = '请先连接内置内核，并等待切换完成'; return; }
    this.snifferBusy = true;
    try {
      const current: ClashRuntimeConfig = await this.coreApi.runtimeConfig();
      ++this.mutationVersion;
      try { await this.coreApi.saveRuntimeConfig(current, { mode: current.mode, logLevel: current.logLevel, ipv6: current.ipv6,
        sniffing: enabled, path: current.path, temporary: current.temporary, revision: current.revision }); }
      finally { ++this.mutationVersion; }
      await this.refreshCore(); this.notice = `域名嗅探已${enabled ? '开启' : '关闭'}，重载或重启后恢复配置中的设置`;
    } catch (error) { this.notice = `嗅探未能切换：${(error as Error).message}`; await this.refreshCore(); }
    finally { this.snifferBusy = false; }
  }

  private async openSnifferSettings(): Promise<void> {
    if (!this.coreConnected || !this.internalCore || this.tunBusy) { this.notice = '请先连接内置内核，并等待切换完成'; return; }
    try {
      const initial: ClashRuntimeConfig = await this.coreApi.runtimeConfig();
      const content: string = await this.coreApi.snifferDraft();
      const instance: string = this.connectedRuntime.instance;
      const validate = (text: string): void => {
        this.nativeCore.validateSniffer(text);
      };
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: SnifferSettingsDialog({ initialContent: content, onValidate: validate,
        onCopy: (text: string): void => { this.copyText(text, '嗅探扩展配置'); },
        onSave: async (text: string): Promise<void> => {
          if (this.tunBusy || !this.internalCore || this.connectedRuntime.instance !== instance) throw new Error('当前内核已变化，请重新打开嗅探设置');
          validate(text); ++this.mutationVersion;
          try { await this.coreApi.saveSnifferDraft(initial, text); }
          finally { ++this.mutationVersion; }
          await this.refreshCore(); this.notice = '嗅探设置已应用；长期保留请写入配置或扩展';
        }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开嗅探设置：${(error as Error).message}`; }
  }

  private async openProxyPorts(): Promise<void> {
    if (!this.coreConnected || !this.internalCore) { this.notice = '请先连接内置内核后修改端口'; return; }
    if (this.temporaryConfig) { this.notice = '请先选择保存的配置，再修改全局端口'; return; }
    if (this.tunEnabled || this.tunBusy) { this.notice = '请先关闭虚拟网卡模式，再修改代理端口'; return; }
    try {
      const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
      if (profile === undefined) throw new Error('请先导入或新建一份配置');
      const initial: ClashProxyPorts = await this.coreApi.proxyPorts();
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({
        builder: ProxyPortsDialog({ initial,
          onSave: async (ports?: ClashProxyPorts): Promise<void> => {
            if (this.activeProfileId !== profile.id || this.tunEnabled || this.tunBusy) throw new Error('配置或虚拟网卡状态已变化，请重新打开端口设置');
            this.mutationVersion++;
            try {
              await this.coreApi.saveProxyPorts(profile.path, ports);
            } catch (error) {
              const message: string = (error as Error).message;
              const occupied: RegExpMatchArray | null = message.match(/Cannot bind proxy port (\d+)/);
              throw new Error(occupied !== null ? `端口 ${occupied[1]} 无法监听，可能已被占用，原设置已保留` : `端口未能应用：${message}`);
            } finally { this.mutationVersion++; }
            await this.refreshCore();
            this.refreshSystemProxy();
            this.notice = `${ports === undefined ? '已恢复当前配置的端口' : '代理端口已保存并应用'}${this.systemProxyPort > 0 && !this.systemProxyMatchesCore() ? '；请同步更新系统网络代理中的端口' : ''}`;
          }
        }), autoCancel: false, customStyle: true
      });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开端口设置：${(error as Error).message}`; }
  }

  private async openInboundSettings(): Promise<void> {
    if (!this.coreConnected || !this.internalCore) { this.notice = '请先连接内置内核'; return; }
    if (this.temporaryConfig) { this.notice = '请先选择保存的配置，再修改共享设置'; return; }
    if (this.tunBusy || this.tunEnabled) { this.notice = '请先关闭虚拟网卡，再修改共享设置'; return; }
    try {
      const initial: ClashInboundSettings = await this.coreApi.inboundSettings();
      const instance: string = this.connectedRuntime.instance;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: InboundSettingsDialog({ initial,
        onSave: async (changes?: ClashInboundChanges): Promise<void> => {
          if (this.tunBusy || this.tunEnabled || !this.internalCore || this.connectedRuntime.instance !== instance) throw new Error('当前内核或虚拟网卡状态已变化，请重新打开共享设置');
          ++this.mutationVersion;
          try { await this.coreApi.saveInboundSettings(initial, changes); }
          catch (error) { throw new Error(this.inboundError((error as Error).message)); }
          finally { ++this.mutationVersion; }
          await this.refreshCore();
          this.notice = changes === undefined ? '共享设置已恢复为当前配置的设置' : '共享设置已保存并应用';
        }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开共享设置：${(error as Error).message}`; }
  }

  private inboundError(message: string): string {
    if (message.indexOf('Active configuration changed') >= 0) return '当前配置或运行设置已变化，请取消并重新打开共享设置';
    if (message.indexOf('bind-address') >= 0) return '监听地址应为 *、IPv4 或 IPv6 地址';
    if (message.indexOf('Cannot bind proxy port') >= 0) return '无法监听所选地址或端口，可能已被占用；原设置已保留';
    if (message.indexOf('skip-auth-prefixes') >= 0) return '免认证网段应填写有效的 IPv4 / IPv6 CIDR';
    if (message.indexOf('lan-allowed-ips') >= 0) return '允许访问的网段应填写有效的 IPv4 / IPv6 CIDR';
    if (message.indexOf('lan-disallowed-ips') >= 0) return '禁止访问的网段应填写有效的 IPv4 / IPv6 CIDR';
    if (message.indexOf('Proxy accounts') >= 0 || message.indexOf('Accounts require') >= 0) return '请检查账号和密码：名称不能重复，新账号必须有密码，单项最多 255 字节且不能包含控制字符';
    if (message.indexOf('Cannot save') >= 0 || message.indexOf('Cannot commit') >= 0) return '无法保存共享设置，原设置已保留';
    return message;
  }

  private refreshControllerAccessStatus(): void {
    try {
      const snapshot: ControllerAccessSnapshot | undefined = this.controllerAccessStore?.snapshot();
      this.controllerAccessStatus = snapshot?.error ? '设置损坏' : snapshot?.secret ? '已启用' : '未启用';
    } catch (_) { this.controllerAccessStatus = '无法读取'; }
  }

  private openControllerAccess(): void {
    try {
      if (!this.controllerAccessStore) throw new Error('认证设置目录不可用');
      if (this.tunBusy || this.tunEnabled || this.vpnService?.status().core.running) throw new Error('请先关闭虚拟网卡模式，再修改内置控制器密钥');
      const store: ControllerAccessStore = this.controllerAccessStore;
      const initial: ControllerAccessSnapshot = store.snapshot();
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: ControllerAccessDialog({ initial,
        onCopy: (secret: string): void => { this.copyText(secret, '内置控制器密钥'); },
        onSave: async (secret: string): Promise<void> => {
          if (this.tunBusy || this.tunEnabled || this.vpnService?.status().core.running) throw new Error('请先关闭虚拟网卡模式，再修改内置控制器密钥');
          this.mutationVersion++;
          try { new ControllerAccessController(store, this.nativeCore).save(initial, secret); }
          finally { this.mutationVersion++; this.refreshControllerAccessStatus(); }
          await this.refreshCore();
          this.notice = secret ? '内置控制器认证已启用，外部控制端请同步更新密钥' : '内置控制器认证已关闭';
        }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开控制器认证：${(error as Error).message}`; }
  }

  private openBackupManager(): void {
    if (this.profileStore === undefined) { this.notice = '配置目录不可用'; return; }
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({
        builder: BackupManagerDialog({ store: new BackupStore(context, this.profileStore), profiles: this.profileStore,
          readAppearance: () => this.appearanceController?.savedSettings(),
          readGroupIconRevision: () => this.groupIconStore?.revision(),
          readNetworkRevision: () => this.profileStore?.networkBackupSnapshot().revision,
          onRestore: (text: string, selection: BackupRestoreSelection): Promise<BackupRestoreResult> => this.restoreBackup(text, selection) }),
        autoCancel: false, customStyle: true
      });
      this.dialogController.open();
    } catch (_) { this.notice = '无法打开备份目录'; }
  }

  private async restoreBackup(text: string, selection: BackupRestoreSelection): Promise<BackupRestoreResult> {
    if (!this.profileStore) throw new Error('配置目录不可用');
    if (this.updatingProfiles.length || this.tunBusy) throw new Error('配置正在更新，请稍后恢复');
    if ((selection.globals || selection.network) && this.tunEnabled) throw new Error('请先关闭虚拟网卡模式，再恢复全局扩展或网络设置');
    if ((selection.globals || selection.network) && this.coreConnected && !this.internalCore) throw new Error('当前连接外部内核，请仅恢复配置或外观');
    if (selection.network && this.temporaryConfig) throw new Error('请先选择已保存的配置，再恢复端口与共享设置');
    const store: ProfileStore = this.profileStore;
    const active: ClashProfile | undefined = this.profiles.find((p: ClashProfile) => p.id === this.activeProfileId);
    const mode: string = this.coreMode;
    const runtime: BackupRuntime | undefined = selection.globals && active && this.coreConnected ? {
      validate: (globals: BackupGlobals): void => store.validateBackupGlobals(active, globals),
      reload: async (): Promise<void> => { await this.coreApi.loadConfig(active.path); await this.coreApi.setMode(mode); }
    } : undefined;
    const locks: string[] = this.profiles.map((p: ClashProfile) => p.id);
    this.updatingProfiles = locks.length ? locks : ['.backup']; this.mutationVersion++;
    try {
      const result: BackupRestoreResult = await new BackupRestoreCoordinator(store, this.appearanceController, active, this.groupIconStore).restore(text, selection, runtime);
      if (result.appearance && this.appearanceController) {
        this.appearanceMode = this.appearanceController.settings.mode; this.accentInput = this.appearanceController.settings.accent; this.appearanceError = '';
        try { this.groupIcons = this.groupIconStore?.load() ?? []; ++this.groupIconRevision; }
        catch (_) { this.appearanceError = '外观已恢复，代理组图标暂时无法读取'; }
      }
      this.reloadProfiles();
      const restored: string[] = [];
      if (result.count > 0) restored.push(`${result.count} 份配置副本`);
      if (result.globals) restored.push('全局扩展');
      if (result.appearance) restored.push('外观');
      if (result.network) restored.push('端口与共享设置');
      this.notice = `已恢复${restored.join('、')}，原活动配置保持不变${result.network ? '；请确认系统代理端口与当前监听端口一致' : ''}`;
      return result;
    } finally { this.updatingProfiles = []; this.mutationVersion++; this.reloadProfiles(); await this.refreshCore(); }
  }

  private reloadProfiles(): void {
    if (this.profileStore !== undefined) {
      this.profileRevision++;
      this.profiles = this.profileStore.list();
    }
  }

  private removeProfile(profile: ClashProfile): void {
    if (profile.id === this.activeProfileId) { this.notice = '请先切换到其他配置，再删除当前配置'; return; }
    try {
      this.profileStore?.remove(profile);
      this.profiles = this.profiles.filter((item: ClashProfile) => item.id !== profile.id);
      if (this.activeProfileId === profile.id) {
        this.activeProfileId = '';
      }
      this.notice = `已删除「${profile.name}」`;
    } catch (error) {
      this.notice = `删除失败：${(error as Error).message}`;
    }
  }

  private confirmRemoveProfile(profile: ClashProfile): void {
    this.showMessageDialog({
      title: '删除配置', message: `删除「${profile.name}」的本地副本？`,
      primaryButton: { value: '取消', action: () => {} },
      secondaryButton: { value: '删除', fontColor: this.theme.danger, action: () => this.removeProfile(profile) }
    });
  }

  private openEditor(profile?: ClashProfile): void {
    if (this.profileStore === undefined) return;
    try {
      const store: ProfileStore = this.profileStore;
      const content: string = profile === undefined ? DEFAULT_PROFILE : this.profileStore.read(profile);
      this.dialogController = new CustomDialogController({
        builder: ProfileEditorDialog({ title: profile === undefined ? '新建本地配置' : '编辑配置文件',
          initialName: profile?.name ?? '新建配置', initialContent: content,
          providerReferences: profile === undefined ? undefined : (query: string): Promise<string> => store.providerReferences(profile!, content, query),
          onValidate: (name: string, text: string): void => {
            if (!this.profileStore) throw new Error('配置目录不可用');
            this.profileStore.checkDraft(name, text, profile, content);
          },
          onSave: async (name: string, text: string): Promise<void> => {
            if (this.profileStore === undefined) throw new Error('配置目录不可用');
            const saved: ClashProfile = profile === undefined ? this.profileStore.create(name, text) : this.profileStore.save(profile, name, text, content);
            this.reloadProfiles();
            if (profile === undefined || this.profileIsActive(saved.id)) await this.activateProfile(saved);
            else this.notice = `已保存「${saved.name}」`;
          }
        }), autoCancel: false, customStyle: true
      });
      this.dialogController.open();
    } catch (error) {
      this.notice = `打开配置失败：${(error as Error).message}`;
    }
  }

  private openRuleEditor(profile?: ClashProfile): void {
    if (this.temporaryConfig && profile === undefined) { this.notice = '当前运行临时配置，请先选择保存的配置再编辑规则'; return; }
    const store: ProfileStore | undefined = this.profileStore;
    const selected: ClashProfile | undefined = profile ?? this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    if (store === undefined || selected === undefined) { this.notice = '请先导入或新建配置'; return; }
    if (this.tunBusy || this.updatingProfiles.indexOf(selected.id) >= 0) { this.notice = '配置正在更新，请稍后编辑规则'; return; }
    if (this.profileIsActive(selected.id) && this.coreConnected && !this.internalCore) { this.notice = '当前连接外部内核，请在外部内核的配置中编辑规则'; return; }
    try {
      const source: string = store.read(selected), previous: string = store.ruleEditsText(selected);
      const objects: string = store.objectEditsText(selected), merges: string = store.mergeSettings(selected);
      const initial: RuleEdits = parseRuleEditsText(previous);
      const snapshot = store.previewRules(source, initial, false, objects, merges, store.providerCacheContext(selected));
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({
        builder: RuleEditorDialog({ profileName: selected.name, initial, snapshot,
          onValidate: (edits: RuleEdits): void => { store.previewRules(source, edits, false, objects, merges, store.providerCacheContext(selected)); },
          onCopy: (text: string): void => { this.copyText(text, '规则'); },
          onSave: async (edits: RuleEdits): Promise<void> => {
            if (this.tunBusy || this.updatingProfiles.indexOf(selected.id) >= 0) throw new Error('配置正在更新，请稍后重试');
            this.updatingProfiles = [...this.updatingProfiles, selected.id]; this.mutationVersion++;
            try {
              const mode: string = this.coreMode;
              let modeFailed: boolean = false;
              const saved: string = store.saveRuleEdits(selected, source, previous, edits, objects, merges);
              if (this.profileIsActive(selected.id) && this.coreConnected) {
                try { await this.coreApi.loadConfig(selected.path); }
                catch (_) {
                  store.rollbackRuleEdits(selected, saved, previous);
                  // A timed-out request may already have committed; reload the rolled-back sidecar too.
                  try { if (this.profileIsActive(selected.id)) await this.coreApi.loadConfig(selected.path); }
                  catch (_) { throw new Error('规则保存已撤回，内核状态未能确认，请刷新或重新加载配置'); }
                  throw new Error('规则未能应用，原设置已恢复');
                }
                try { await this.coreApi.setMode(mode); }
                catch (_) { modeFailed = true; }
              }
              this.reloadProfiles();
              await this.refreshCore();
              this.notice = `已保存「${selected.name}」的自定义规则，订阅更新后仍保留${modeFailed ? '；代理模式未能恢复，请确认当前模式' : ''}`;
            } finally {
              this.updatingProfiles = this.updatingProfiles.filter((id: string) => id !== selected.id); this.mutationVersion++;
            }
          }
        }), autoCancel: false, customStyle: true
      });
      this.dialogController.open();
    } catch (error) { this.notice = `无法编辑规则：${(error as Error).message}`; }
  }

  private openObjectEditor(profile?: ClashProfile, kind: number = 0, focusName: string = ''): void {
    if (this.temporaryConfig && profile === undefined) { this.notice = '当前运行临时配置，请先选择保存的配置再编辑节点'; return; }
    const store: ProfileStore | undefined = this.profileStore;
    const selected: ClashProfile | undefined = profile ?? this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    if (!store || !selected) { this.notice = '请先导入或新建配置'; return; }
    if (this.tunBusy || this.updatingProfiles.indexOf(selected.id) >= 0) { this.notice = '配置正在更新，请稍后编辑节点和代理组'; return; }
    if (this.profileIsActive(selected.id) && this.coreConnected && !this.internalCore) { this.notice = '当前连接外部内核，请在外部内核的配置文件中编辑'; return; }
    try {
      const source: string = store.read(selected), rules: string = store.ruleEditsText(selected), previous: string = store.objectEditsText(selected);
      const merges: string = store.mergeSettings(selected);
      const initial: ObjectEdits = parseObjectEditsText(previous);
      store.previewObjects(source, initial, rules, true, merges, store.providerCacheContext(selected));
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: ObjectEditorDialog({ store, profileName: selected.name, sourceContent: source, ruleSettings: rules,
        initial, mergeSettings: merges, providerContext: store.providerCacheContext(selected), initialKind: kind, focusName, onCopy: (text: string, label: string): void => { this.copyText(text, label); },
        onSave: async (edits: ObjectEdits): Promise<void> => {
          if (this.tunBusy || this.updatingProfiles.indexOf(selected.id) >= 0) throw new Error('配置正在更新，请稍后重试');
          this.updatingProfiles = [...this.updatingProfiles, selected.id]; this.mutationVersion++;
          try {
            const mode: string = this.coreMode; let modeFailed: boolean = false;
            const saved: string = store.saveObjectEdits(selected, source, rules, previous, edits, merges);
            if (this.profileIsActive(selected.id) && this.coreConnected) {
              try { await this.coreApi.loadConfig(selected.path); }
              catch (_) {
                store.rollbackObjectEdits(selected, saved, previous);
                try { if (this.profileIsActive(selected.id)) await this.coreApi.loadConfig(selected.path); }
                catch (_) { throw new Error('节点和代理组保存已撤回，内核状态未能确认，请重新加载配置'); }
                throw new Error('节点和代理组未能应用，原设置已恢复');
              }
              try { await this.coreApi.setMode(mode); } catch (_) { modeFailed = true; }
            }
            this.reloadProfiles(); await this.refreshCore();
            this.notice = `已保存「${selected.name}」的节点和代理组，订阅更新后仍保留${modeFailed ? '；请确认当前代理模式' : ''}`;
          } finally { this.updatingProfiles = this.updatingProfiles.filter((id: string) => id !== selected.id); this.mutationVersion++; }
        }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开节点和代理组编辑器：${(error as Error).message}`; }
  }

  private openMergeEditor(global: boolean, profile?: ClashProfile, script: boolean = false): void {
    const store: ProfileStore | undefined = this.profileStore;
    const selected: ClashProfile | undefined = profile ?? this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId) ?? (global ? this.profiles[0] : undefined);
    if (!store || (!global && !selected)) { this.notice = '请先导入或新建配置'; return; }
    if (this.tunBusy || (global ? this.updatingProfiles.length > 0 : this.updatingProfiles.indexOf(selected?.id ?? '') >= 0)) { this.notice = '配置正在更新，请稍后编辑扩展'; return; }
    if (this.coreConnected && !this.internalCore && (global || selected?.id === this.activeProfileId)) { this.notice = '当前连接外部内核，请在该内核中编辑扩展配置'; return; }
    try {
      const snapshot: MergeEditSnapshot = store.mergeSnapshot(selected, global, script), active: string = this.activeProfileId;
      const previous: string = script ? (global ? snapshot.globalScript : snapshot.profileScript) : global ? snapshot.globalText : snapshot.profileText;
      this.dialogController?.close();
      const saveExtension = async (text: string): Promise<void> => {
          if (this.tunBusy || this.activeProfileId !== active || this.updatingProfiles.length > 0) throw new Error('当前配置或更新状态已变化，请重新打开扩展编辑器');
          const key: string = selected?.id ?? '.global'; this.updatingProfiles = [...this.updatingProfiles, key]; this.mutationVersion++;
          try {
            const mode: string = this.coreMode, saved: string = store.saveMerge(snapshot, text); let modeFailed: boolean = false;
            if (selected && this.profileIsActive(selected.id) && this.coreConnected) {
              try { await this.coreApi.loadConfig(selected.path); }
              catch (_) {
                store.rollbackMerge(snapshot, saved, previous);
                try { if (this.profileIsActive(selected.id)) await this.coreApi.loadConfig(selected.path); }
                catch (_) { throw new Error('扩展保存已撤回，内核状态未能确认，请重新加载配置'); }
                throw new Error('扩展未能应用，原设置已恢复');
              }
              try { await this.coreApi.setMode(mode); } catch (_) { modeFailed = true; }
            }
            this.reloadProfiles(); await this.refreshCore();
            this.notice = `${global ? '全局' : '订阅'}扩展${script ? '脚本' : '配置'}已保存，订阅更新后仍保留${modeFailed ? '；请确认当前代理模式' : ''}`;
          } finally { this.updatingProfiles = this.updatingProfiles.filter((id: string) => id !== key); this.mutationVersion++; }
        };
      if (script) this.dialogController = new CustomDialogController({ builder: ScriptEditorDialog({ global, profileName: snapshot.profileName, initialContent: previous,
        onPreview: (text: string): ScriptPreview => store.previewScript(snapshot, text), onCopy: (text: string, label: string): void => { this.copyText(text, label); },
        onSave: saveExtension }), autoCancel: false, customStyle: true });
      else this.dialogController = new CustomDialogController({ builder: MergeEditorDialog({ global, profileName: selected?.name ?? '', initialContent: previous,
        onPreview: (text: string): string => store.previewMerge(snapshot, text), onCopy: (text: string): void => { this.copyText(text, '合并配置'); },
        onSave: saveExtension }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开扩展配置：${(error as Error).message}`; }
  }

  private openProfileInfo(profile?: ClashProfile, request?: SubscriptionImport): void {
    this.dialogController = new CustomDialogController({
      builder: ProfileInfoDialog({ title: profile === undefined ? '添加远程订阅' : '编辑配置信息',
        initialName: profile?.name ?? request?.name ?? '', initialUrl: profile?.sourceUrl ?? request?.url ?? this.subscriptionUrl,
        onClosed: (): void => { if (request) subscriptionImports.finish(request.id); },
        initialInterval: profile?.updateInterval ?? 0, requireUrl: profile === undefined,
        initialOptions: profile?.subscription?.options, initialFollowInterval: profile?.subscription?.followInterval ?? profile === undefined,
        onSave: async (name: string, url: string, interval: number | undefined, options: SubscriptionOptions): Promise<void> => {
          if (this.profileStore === undefined) throw new Error('配置目录不可用');
          if (profile === undefined) {
            const saved: ClashProfile = await this.profileStore.importSubscription(name, url, options, interval);
            this.subscriptionUrl = '';
            this.reloadProfiles();
            await this.activateProfile(saved);
          } else {
            if (this.updatingProfiles.indexOf(profile.id) >= 0 || this.tunBusy) throw new Error('配置正在更新，请稍后重试');
            const saved: ClashProfile = this.profileStore.updateInfo(profile, name, url, interval, options);
            if (saved.name !== profile.name && this.activeProfileId === profile.id && this.coreConnected && this.internalCore &&
              (this.profileStore.globalScriptText() || this.profileStore.profileScriptText(saved))) {
              this.updatingProfiles = [...this.updatingProfiles, profile.id]; this.mutationVersion++;
              try {
                const mode: string = this.coreMode;
                try { await this.coreApi.loadConfig(saved.path); }
                catch (_) {
                  this.profileStore.rollbackInfo(saved, saved.name, profile);
                  try { await this.coreApi.loadConfig(profile.path); } catch (_) { throw new Error('配置信息已撤回，请确认内核状态'); }
                  throw new Error('新名称下的脚本未能应用，原配置信息已恢复');
                }
                await this.coreApi.setMode(mode); await this.refreshCore();
              } finally { this.updatingProfiles = this.updatingProfiles.filter((id: string) => id !== profile.id); this.mutationVersion++; }
            }
            this.reloadProfiles();
            this.notice = `已保存「${name}」的信息`;
          }
        }
      }), autoCancel: false, customStyle: true
    });
    this.dialogController.open();
  }

  private async updateSubscription(profile: ClashProfile): Promise<void> {
    if (this.profileStore === undefined || this.updatingProfiles.indexOf(profile.id) >= 0) return;
    this.updatingProfiles = [...this.updatingProfiles, profile.id];
    this.notice = `正在更新「${profile.name}」…`;
    try {
      const active: boolean = this.profileIsActive(profile.id) && this.coreConnected;
      const updated: ClashProfile = await this.profileStore.updateSubscription(profile, active ? async (updated: ClashProfile): Promise<void> => this.activateProfile(updated, true) : undefined);
      this.reloadProfiles();
      if (!active) this.notice = `已更新「${updated.name}」`;
    } catch (error) {
      this.reloadProfiles();
      this.notice = `更新失败：${(error as Error).message}`;
    } finally {
      this.updatingProfiles = this.updatingProfiles.filter((id: string) => id !== profile.id);
    }
  }

  private async openSubscriptionHome(profile: ClashProfile): Promise<void> {
    try {
      const home: string = subscriptionUrl(profile.subscription?.info?.home ?? '', true);
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      await context.openLink(home);
    } catch (_) { this.notice = '无法打开订阅主页，请检查系统浏览器'; }
  }

  private async autoUpdateSubscriptions(): Promise<void> {
    if (this.profileStore === undefined) return;
    for (const profile of this.profiles) {
      if (this.profileStore.isUpdateDue(profile)) await this.updateSubscription(profile);
    }
  }

  private duplicateProfile(profile: ClashProfile): void {
    try {
      const copy: ClashProfile | undefined = this.profileStore?.duplicate(profile);
      this.reloadProfiles();
      this.notice = `已创建「${copy?.name ?? profile.name}」`;
    } catch (error) { this.notice = `复制失败：${(error as Error).message}`; }
  }

  private pinProfile(profile: ClashProfile): void {
    try {
      this.profileStore?.setPinned(profile);
      this.reloadProfiles();
    } catch (error) { this.notice = `置顶失败：${(error as Error).message}`; }
  }

  private async exportProfile(profile: ClashProfile): Promise<void> {
    try {
      if (await this.profileStore?.exportProfile(profile)) this.notice = `已导出「${profile.name}」`;
    } catch (error) { this.notice = `导出失败：${(error as Error).message}`; }
  }

  private async copyText(text: string, label: string = '内容'): Promise<void> {
    try {
      await pasteboard.getSystemPasteboard().setData(pasteboard.createData(pasteboard.MIMETYPE_TEXT_PLAIN, text));
      this.notice = `已复制${label}`;
    } catch (_) { this.notice = '复制失败：系统剪贴板不可用'; }
  }

  private copyProfile(profile: ClashProfile): void {
    try {
      const content: string | undefined = this.profileStore?.effectiveContent(profile);
      if (content !== undefined) this.copyText(content, '配置内容');
    } catch (error) { this.notice = `读取失败：${(error as Error).message}`; }
  }

  private openNodeImport(content: string = ''): void {
    if (this.temporaryConfig) { this.notice = '请先选择保存的配置，再导入节点链接'; return; }
    const store: ProfileStore | undefined = this.profileStore;
    if (!store) { this.notice = '配置目录不可用'; return; }
    this.dialogController?.close();
    this.dialogController = new CustomDialogController({ builder: NodeImportDialog({ initialContent: content,
      onImport: async (result: NodeLinkImport, name: string): Promise<void> => {
        const profile: ClashProfile = store.create(name, result.content);
        this.reloadProfiles(); await this.activateProfile(profile);
      } }), autoCancel: false, customStyle: true });
    this.dialogController.open();
  }

  private async importClipboard(): Promise<void> {
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      const permission = await abilityAccessCtrl.createAtManager().requestPermissionsFromUser(context, ['ohos.permission.READ_PASTEBOARD']);
      if (permission.authResults.length === 0 || permission.authResults[0] !== 0) {
        this.notice = '未授予剪贴板读取权限，请改用文件导入';
        return;
      }
      const content: string = (await pasteboard.getSystemPasteboard().getData()).getPrimaryText();
      if (this.profileStore === undefined) return;
      if (/^\s*[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(content)) { this.openNodeImport(content); return; }
      if (/^[A-Za-z0-9+/_=\s-]+$/.test(content)) {
        try { this.nativeCore.shareLinks(content); this.openNodeImport(content); return; }
        catch (_) { /* Continue with the configuration importer if this is not a node list. */ }
      }
      const profile: ClashProfile = this.profileStore.create('剪贴板配置', content);
      this.reloadProfiles();
      await this.activateProfile(profile);
    } catch (error) { this.notice = `剪贴板导入失败：${(error as Error).message}`; }
  }

  private async exportLogs(): Promise<void> {
    const text: string = this.logEntries.map((entry: UiLogEntry) => `[${entry.time}] [${entry.level}] ${entry.message}`).join('\n');
    try {
      if (await this.profileStore?.exportText('ClashOS.log', text)) this.notice = '日志已导出';
    } catch (error) { this.notice = `日志导出失败：${(error as Error).message}`; }
  }

  private formatBytes(bytes: number): string {
    if (bytes <= 0) {
      return '0 B';
    }
    if (bytes >= 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    }
    if (bytes >= 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
    if (bytes < 1024) {
      return `${Math.round(bytes)} B`;
    }
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  private activeProfileName(): string {
    if (this.temporaryConfig) return '临时配置（控制器）';
    const active: ClashProfile | undefined = this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId);
    return active === undefined ? '未加载配置' : active.name;
  }


  private navigate(index: number): void {
    if (index === 1 && this.selectedTab !== 1) this.showProviderCollections = false;
    this.selectedTab = index;
    this.notice = '';
    this.hoveredAction = '';
    this.hoveredProxyGroup = '';
    this.contentScroller.scrollTo({ xOffset: 0, yOffset: 0 });
    this.navigationScroller.scrollTo({ xOffset: Math.max(0, (this.navigationPositions[index] ?? 0) - 12), yOffset: 0,
      animation: { duration: 160, curve: Curve.EaseOut } });
    if(index === 7) this.refreshDnsStatus();
    if(index === 6) this.refreshGeoStatus();
  }

  private async refreshGeoStatus(): Promise<void> {
    if (!this.internalCore || !this.coreConnected) { this.geoStatus = undefined; return; }
    const version: number = this.mutationVersion;
    try {
      const status: ClashGeoStatus = await this.coreApi.geoStatus();
      if (this.pageActive && version === this.mutationVersion) this.geoStatus = status;
    } catch (_) { if (version === this.mutationVersion) this.geoStatus = undefined; }
  }

  private geoTitle(kind: string): string {
    return kind === 'mmdb' ? 'GeoIP · MMDB' : kind === 'geoip' ? 'GeoIP · DAT' : kind === 'geosite' ? 'GeoSite · DAT' : 'ASN · MMDB';
  }

  private async geoAction(resource: ClashGeoResource, action: string): Promise<void> {
    const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    if (profile === undefined || this.profileStore === undefined || this.geoBusy.indexOf(resource.kind) >= 0) return;
    this.geoBusy = [...this.geoBusy, resource.kind];
    const version: number = this.mutationVersion;
    let imported: string | undefined = undefined;
    try {
      if (action === 'import') {
        imported = await this.profileStore.pickGeoFile();
        if (imported === undefined) return;
        if (version !== this.mutationVersion) throw new Error('配置已切换，请重新选择数据库');
      }
      await this.coreApi.geoAction(resource.kind, profile.path, action, imported ?? '');
      this.notice = action === 'update' ? `${this.geoTitle(resource.kind)} 已开始更新` : action === 'import' ? `${this.geoTitle(resource.kind)} 已导入` : `${this.geoTitle(resource.kind)} 本地数据已删除`;
      await this.refreshGeoStatus();
    } catch (error) { this.notice = `数据库操作失败：${(error as Error).message}`; }
    finally {
      if (imported !== undefined) this.profileStore?.releaseGeoImport(imported);
      this.geoBusy = this.geoBusy.filter((kind: string) => kind !== resource.kind);
    }
  }

  private confirmClearGeo(resource: ClashGeoResource): void {
    this.showMessageDialog({
      title: '删除本地数据库', message: `删除 ${this.geoTitle(resource.kind)}？引用此数据的分流将在重新下载后恢复。`,
      primaryButton: { value: '取消', action: () => {} },
      secondaryButton: { value: '删除', fontColor: this.theme.danger, action: () => this.geoAction(resource, 'clear') }
    });
  }

  private async refreshDnsStatus(): Promise<void> {
    if (!this.internalCore || !this.coreConnected) { this.dnsStatus = undefined; return; }
    const version: number = this.mutationVersion;
    try {
      const status: ClashDnsStatus = await this.coreApi.dnsStatus();
      if (this.pageActive && version === this.mutationVersion) this.dnsStatus = status;
    } catch (_) { if (version === this.mutationVersion) this.dnsStatus = undefined; }
  }

  private async runDnsQuery(): Promise<void> {
    if (this.dnsBusy || !this.coreConnected) return;
    const version: number = this.mutationVersion;
    const name: string = this.dnsName.trim();
    if (name.length === 0) { this.dnsError = '请输入要查询的域名'; return; }
    this.dnsBusy = true; this.dnsError = ''; this.dnsAnswer = undefined;
    try {
      const answer: ClashDnsAnswer = await this.coreApi.queryDns(name, this.dnsType, this.internalCore ? this.dnsServer.trim() : '');
      if (this.pageActive && version === this.mutationVersion) this.dnsAnswer = answer;
    } catch (error) {
      if (this.pageActive && version === this.mutationVersion) this.dnsError = (error as Error).message;
    } finally { this.dnsBusy = false; await this.refreshDnsStatus(); }
  }

  private async clearDnsCache(): Promise<void> {
    if (!this.internalCore || this.dnsBusy) return;
    const version: number = this.mutationVersion;
    try {
      await this.coreApi.clearDnsCache();
      if (version === this.mutationVersion) this.notice = '当前配置的 DNS 缓存已清空';
      await this.refreshDnsStatus();
    } catch (error) { if (version === this.mutationVersion) this.notice = `清空 DNS 缓存失败：${(error as Error).message}`; }
  }

  private dnsTypeName(type: number): string {
    const names: Record<number, string> = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS' };
    return names[type] ?? `TYPE${type}`;
  }

  private dnsResultText(): string {
    const answer: ClashDnsAnswer | undefined = this.dnsAnswer;
    if (answer === undefined) return '';
    return `${answer.Question?.[0]?.name ?? this.dnsName}\tRCODE ${answer.Status}\n` +
      (answer.Answer ?? []).map((record: ClashDnsRecord) => `${record.name}\t${record.TTL}\tIN\t${this.dnsTypeName(record.type)}\t${record.data}`).join('\n');
  }

  private locateGroup(name: string): void {
    const position: number = this.groupPositions[name];
    if (position === undefined) return;
    this.focusedProxyGroup = name;
    this.contentScroller.scrollTo({ xOffset: 0, yOffset: Math.max(0, position - 12),
      animation: { duration: 180, curve: Curve.EaseOut } });
  }

  private updateGroupFocus(offset: number): void {
    if (this.selectedTab !== 1) return;
    let current: string = this.visibleGroups()[0]?.name ?? '';
    this.visibleGroups().forEach((group: ClashProxyGroup) => {
      const position: number = this.groupPositions[group.name];
      if (position !== undefined && position <= offset + 24) current = group.name;
    });
    if (current !== this.focusedProxyGroup) this.focusedProxyGroup = current;
  }

  private hasGroupNavigator(): boolean {
    return this.selectedTab === 1 && !this.showProviderCollections && this.windowWidth >= 780 && this.visibleGroups().length >= 4;
  }

  private onNoticeChanged(): void {
    if (this.notice.length > 0) {
      this.addLog(this.notice.indexOf('失败') >= 0 ? 'ERROR' : 'INFO', this.notice);
    }
  }

  private addLog(level: string, message: string): void {
    const entry: UiLogEntry = {
      id: this.nextLogId++,
      time: this.clockText(new Date()),
      level,
      message
    };
    this.logEntries = [...this.logEntries.slice(-199), entry];
  }

  private clockText(date: Date): string {
    return `${`${date.getHours()}`.padStart(2, '0')}:${`${date.getMinutes()}`.padStart(2, '0')}:${`${date.getSeconds()}`.padStart(2, '0')}`;
  }

  private sampleTraffic(snapshot: ClashSnapshot): void {
    const now: number = Date.now();
    this.lastSyncTime = this.clockText(new Date(now));
    if (!snapshot.connected) {
      this.downloadRate = 0;
      this.uploadRate = 0;
      this.lastSampleAt = 0;
      return;
    }
    if (this.lastSampleAt > 0 && now > this.lastSampleAt) {
      const elapsed: number = (now - this.lastSampleAt) / 1000;
      this.downloadRate = Math.max(0, snapshot.downloadTotal - this.previousDownload) / elapsed;
      this.uploadRate = Math.max(0, snapshot.uploadTotal - this.previousUpload) / elapsed;
      this.downloadSamples = [...this.downloadSamples.slice(-29), this.downloadRate];
      this.uploadSamples = [...this.uploadSamples.slice(-29), this.uploadRate];
    }
    this.previousDownload = snapshot.downloadTotal;
    this.previousUpload = snapshot.uploadTotal;
    this.lastSampleAt = now;
  }

  private rateText(value: number): string {
    return this.coreConnected ? `${this.formatBytes(value)}/s` : '—';
  }

  private trafficPoints(samples: number[], width: number = this.chartWidth, height: number = 108): Array<[number, number]> {
    const points: Array<[number, number]> = [];
    const peak: number = Math.max(1024, ...this.downloadSamples, ...this.uploadSamples);
    samples.forEach((value: number, index: number) => {
      points.push([index / 29 * width, height - value / peak * (height - 4)]);
    });
    return points.length > 1 ? points : [[0, height], [width, height]];
  }

  private modeName(): string {
    return this.coreMode === 'Global' ? '全局' : this.coreMode === 'Direct' ? '直连' : '规则';
  }

  private toggleGroup(name: string): void {
    this.collapsedGroups = this.collapsedGroups.indexOf(name) >= 0 ?
      this.collapsedGroups.filter((item: string) => item !== name) : [...this.collapsedGroups, name];
  }

  private toggleAllGroups(): void {
    this.collapsedGroups = this.collapsedGroups.length === this.proxyGroups.length ? [] :
      this.proxyGroups.map((group: ClashProxyGroup) => group.name);
  }

  private unicodeSymbols(value: string): string[] {
    const symbols: string[] = [];
    for (let offset: number = 0; offset < value.length;) {
      const length: number = (value.codePointAt(offset) ?? 0) > 0xFFFF ? 2 : 1;
      symbols.push(value.slice(offset, offset + length));
      offset += length;
    }
    return symbols;
  }

  private groupEmoji(name: string): string {
    // Keep variation selectors, regional flags and joined emoji together.
    const points: string[] = this.unicodeSymbols(name.trim());
    if (points.length === 0) return '';
    const first: number = points[0].codePointAt(0) ?? 0;
    if (!((first >= 0x1F000 && first <= 0x1FAFF) || (first >= 0x2600 && first <= 0x27BF))) return '';
    let result: string = points[0];
    let joined: boolean = false;
    for (let index: number = 1; index < points.length; index++) {
      const value: number = points[index].codePointAt(0) ?? 0;
      if (value === 0xFE0F || value === 0x200D || (value >= 0x1F3FB && value <= 0x1F3FF) || joined ||
        (index === 1 && first >= 0x1F1E6 && first <= 0x1F1FF && value >= 0x1F1E6 && value <= 0x1F1FF)) {
        result += points[index];
        joined = value === 0x200D;
      } else {
        break;
      }
    }
    return result;
  }

  private groupTitle(name: string): string {
    const emoji: string = this.groupEmoji(name);
    const title: string = name.trim().slice(emoji.length).trim();
    return title.length > 0 ? title : name;
  }

  private groupInitial(name: string): string {
    const symbols: string[] = this.unicodeSymbols(this.groupTitle(name));
    return symbols.find((symbol: string) => /[A-Za-z0-9\u3400-\u9FFF]/.test(symbol)) ?? '#';
  }

  private iconColor(color: string): ColorFilter {
    const cached: ColorFilter | undefined = this.iconFilters.get(color);
    if (cached !== undefined) return cached;
    // Use the ArkUI image filter for both SVG fills and strokes. Alpha remains
    // unchanged, including the transparent cutouts in the navigation mark.
    const red: number = parseInt(color.slice(1, 3), 16) / 255;
    const green: number = parseInt(color.slice(3, 5), 16) / 255;
    const blue: number = parseInt(color.slice(5, 7), 16) / 255;
    const filter: ColorFilter = new ColorFilter([0, 0, 0, red, 0, 0, 0, 0, green, 0, 0, 0, 0, blue, 0, 0, 0, 0, 1, 0]);
    if (this.iconFilters.size >= 64) this.iconFilters.clear();
    this.iconFilters.set(color, filter);
    return filter;
  }

  private groupIcon(type: string): Resource {
    return type === 'Fallback' ? $r('app.media.verge_fallback') :
      type === 'URLTest' ? $r('app.media.verge_speed') :
      type === 'LoadBalance' ? $r('app.media.verge_balance') : $r('app.media.verge_selector');
  }

  private groupIconSource(group: ClashProxyGroup): string {
    const custom: string = this.groupIcons.find((entry: GroupIconEntry) => entry.name === group.name)?.source ?? '';
    return custom ? this.groupIconStore?.displaySource(custom) ?? '' : iconImageUrl(group.icon ?? '');
  }

  private openGroupIcon(group: ClashProxyGroup): void {
    const store: GroupIconStore | undefined = this.groupIconStore;
    if (!store) { this.notice = '图标设置暂不可用，请重新打开应用'; return; }
    try {
      const snapshot = store.snapshot(group.name);
      const staged: string[] = []; let active: boolean = true;
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: GroupIconDialog({ groupName: group.name,
        initialSource: snapshot.source, configured: group.icon ?? '', storageError: snapshot.error,
        fallback: this.groupIcon(group.type), emoji: this.groupEmoji(group.name), resolve: (source: string): string => store.displaySource(source),
        onPick: async (): Promise<string | undefined> => {
          const source: string | undefined = await pickGroupIcon(context, store);
          if (source) {
            if (!active || !this.pageActive) { store.releaseImage(source); throw new Error('图标编辑已结束，请重新打开'); }
            staged.push(source);
          }
          return source;
        },
        onSave: (source: string): void => {
          if (!active || !this.pageActive) throw new Error('图标编辑已结束，请重新打开');
          this.groupIcons = store.save(snapshot, source); ++this.groupIconRevision;
          this.notice = source ? '代理组图标已保存，订阅更新后仍保留' : '已恢复配置中的代理组图标';
        },
        onClose: (): void => { active = false; staged.forEach((source: string) => store.releaseImage(source)); }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开图标设置：${(error as Error).message}`; }
  }

  private resetGroupIcon(group: ClashProxyGroup): void {
    try {
      if (!this.groupIconStore) throw new Error('图标设置暂不可用');
      this.groupIcons = this.groupIconStore.save(this.groupIconStore.snapshot(group.name), ''); ++this.groupIconRevision;
      this.notice = '已恢复配置中的代理组图标';
    } catch (error) { this.notice = `图标未能恢复：${(error as Error).message}`; }
  }

  private nodeColumns(): number {
    return this.windowWidth >= 1320 ? 4 : this.windowWidth >= 1000 ? 3 : this.windowWidth >= 660 ? 2 : 1;
  }

  private visibleProxies(group: ClashProxyGroup): string[] {
    const query: string = this.proxyQuery.trim().toLowerCase();
    const names: string[] = group.proxies.filter((name: string) => query.length === 0 ||
      name.toLowerCase().indexOf(query) >= 0 || group.name.toLowerCase().indexOf(query) >= 0);
    if (this.proxySort === 'delay') {
      names.sort((left: string, right: string) => {
        const a: number = this.nodeDelay(left);
        const b: number = this.nodeDelay(right);
        return (a > 0 ? a : a < 0 ? 999999 : 1000000) - (b > 0 ? b : b < 0 ? 999999 : 1000000);
      });
    }
    return names;
  }

  private visibleGroups(): ClashProxyGroup[] {
    return this.proxyGroups.filter((group: ClashProxyGroup) => group.hidden !== true && (this.proxyQuery.trim().length === 0 ||
      this.visibleProxies(group).length > 0));
  }

  private visibleProfiles(): ClashProfile[] {
    const query: string = this.profileQuery.trim().toLowerCase();
    return this.profiles.filter((profile: ClashProfile) => profile.name.toLowerCase().indexOf(query) >= 0 ||
      profile.fileName.toLowerCase().indexOf(query) >= 0);
  }

  private visibleConnections(): ClashConnection[] {
    const query: string = this.connectionQuery.trim().toLowerCase();
    return this.connections.filter((item: ClashConnection) => item.host.toLowerCase().indexOf(query) >= 0 ||
      item.network.toLowerCase().indexOf(query) >= 0 || item.chains.join(' ').toLowerCase().indexOf(query) >= 0 || item.rule.toLowerCase().indexOf(query) >= 0);
  }

  private visibleLogs(): UiLogEntry[] {
    return this.logEntries.filter((entry: UiLogEntry) => this.logFilter === 'ALL' || entry.level === this.logFilter);
  }

  private connectionRoute(item: ClashConnection): string {
    return item.chains.length > 0 ? item.chains.join(' → ') : item.rule || 'DIRECT';
  }

  private nodeDelay(name: string): number {
    if (this.delayResults[name] !== undefined) return this.delayResults[name];
    return this.proxyNodes.find((node: ClashProxyNode) => node.name === name)?.delay ?? -1;
  }

  private nodeProtocolText(name: string): string {
    if (name === 'DIRECT') return '直连 · UDP';
    if (name === 'REJECT') return '拒绝连接';
    const node: ClashProxyNode | undefined = this.proxyNodes.find((item: ClashProxyNode) => item.name === name);
    return `${node?.type || '代理'}${node?.udp ? ' · UDP' : ''}`;
  }

  private nodeDelayText(name: string): string {
    if (this.testingNodes.indexOf(name) >= 0) return '测速中…';
    const delay: number = this.nodeDelay(name);
    return delay < 0 ? '—' : delay === 0 ? '失败' : `${delay} ms`;
  }

  private setDelay(name: string, value: number, error: string = ''): void {
    const results: Record<string, number> = {};
    const errors: Record<string, string> = {};
    Object.keys(this.delayResults).forEach((key: string) => results[key] = this.delayResults[key]);
    Object.keys(this.delayErrors).forEach((key: string) => errors[key] = this.delayErrors[key]);
    results[name] = value;
    errors[name] = error;
    this.delayResults = results;
    this.delayErrors = errors;
  }

  private async diagnoseCore(): Promise<void> {
    this.diagnosing = true;
    try {
      const result: CoreDiagnostics = await this.coreApi.diagnostics();
      this.showMessageDialog({
        title: result.passed ? '内核自检通过' : '内核自检未通过',
        message: `随机数：${result.random ? '通过' : '失败'}\n密钥派生摘要：${result.md5 ? '通过' : '失败'}\nAES-GCM 加密：${result.aesEncrypt ? '通过' : '失败'}\nAES-GCM 解密：${result.aesDecrypt ? '通过' : '失败'}\n报文认证：${result.authentication ? '通过' : '失败'}${result.shadowsocks === undefined ? ' ' : `\nShadowsocks 三种 AEAD：${result.shadowsocks ? '通过' : '失败'}`}${result.shadowsocks2022 === undefined ? '' : `\nShadowsocks 2022：${result.shadowsocks2022 ? '通过' : '失败'}`}${result.shadowsocksTcp === undefined ? '' : `\nShadowsocks 分帧接收：${result.shadowsocksTcp ? '通过' : '失败'}`}${result.vmess === undefined ? '' : `\nVMess 加密：${result.vmess ? '通过' : '失败'}`}${result.trojan === undefined ? '' : `\nTrojan 请求认证：${result.trojan ? '通过' : '失败'}`}${result.vless === undefined ? '' : `\nVLESS 协议：${result.vless ? '通过' : '失败'}`}${result.certificateStore === undefined ? '' : `\nTLS 证书集合：${result.certificateStore ? '通过' : '失败'}`}\n代理端口监听：${result.listeners ? '通过' : '失败'}\n\nHTTP 127.0.0.1:${result.httpPort}\nSOCKS5 127.0.0.1:${result.socksPort}\n\n该自检不检测节点服务器和系统代理。`,
        primaryButton: { value: '关闭', action: () => {} },
        secondaryButton: { value: '复制结果', action: () => this.copyText(JSON.stringify(result, null, 2), '自检结果') }
      });
      this.notice = result.passed ? '当前设备上的内核加密与端口自检通过' : '当前设备的内核自检失败，请查看详情';
    } catch (error) { this.notice = `自检失败：${(error as Error).message}`; }
    finally { this.diagnosing = false; }
  }

  private async refreshSystemProxy(): Promise<void> {
    const version: number = ++this.systemProxyReadVersion;
    try {
      const proxy: connection.HttpProxy = await connection.getDefaultHttpProxy();
      if (!this.pageActive || version !== this.systemProxyReadVersion) return;
      this.systemProxyHost = proxy.host;
      this.systemProxyPort = proxy.port;
      this.systemProxyError = '';
    } catch (_) {
      if (this.pageActive && version === this.systemProxyReadVersion) this.systemProxyError = '无法读取系统代理设置';
    }
  }

  private onAbilityForeground(): void {
    if (this.pageActive) this.refreshSystemProxy();
  }

  private systemProxyEnabled(): boolean {
    return this.systemProxyError.length === 0 && this.systemProxyHost.trim().length > 0 &&
      Number.isInteger(this.systemProxyPort) && this.systemProxyPort > 0 && this.systemProxyPort <= 65535;
  }

  private systemProxyAction(): string {
    if (this.systemProxyOpening) return '正在打开…';
    if (this.systemProxyError.length > 0) return '代理设置';
    return this.systemProxyEnabled() ? '关闭系统代理' : '开启系统代理';
  }

  private async requestSystemProxyChange(): Promise<void> {
    if (this.systemProxyOpening) return;
    await this.refreshSystemProxy();
    this.showSystemProxyGuide(this.systemProxyError.length > 0 ? undefined : !this.systemProxyEnabled());
  }

  private systemProxyMatchesCore(): boolean {
    return this.internalCore && this.coreConnected && this.httpPort > 0 && this.systemProxyPort === this.httpPort &&
      (this.systemProxyHost.toLowerCase() === this.proxyHost.toLowerCase() ||
        (this.proxyHost === '127.0.0.1' && ['localhost', '127.0.0.1'].indexOf(this.systemProxyHost.toLowerCase()) >= 0) ||
        (this.proxyHost === '::1' && ['::1', '[::1]'].indexOf(this.systemProxyHost.toLowerCase()) >= 0));
  }

  private systemProxyDescription(): string {
    if (this.systemProxyError.length > 0) return this.systemProxyError;
    if (this.systemProxyMatchesCore()) return 'HTTP 流量已交给 ClashOS';
    if (this.systemProxyEnabled()) return `已开启 · ${this.systemProxyHost}:${this.systemProxyPort}`;
    return '系统代理已关闭';
  }

  private showSystemProxyGuide(enable?: boolean): void {
    const host: string = this.internalCore ? this.proxyHost : '内核所在设备的 IP 地址';
    const port: string = this.httpPort > 0 ? `${this.httpPort}` : '当前配置的 HTTP 端口';
    this.showMessageDialog({
      title: enable === undefined ? '系统 HTTP 代理' : enable ? '开启系统代理' : '关闭系统代理',
      message: enable === false ? '进入系统设置 → 网络 → 代理，关闭“使用代理服务器”。\n\n当前版本需在系统设置中完成切换；返回 ClashOS 后会自动更新实际状态。关闭系统代理不会停止内核或虚拟网卡。' :
        `进入系统设置 → 网络 → 代理，开启“使用代理服务器”。\n\n服务器：${host}\n端口：${port}\n忽略：localhost,127.0.0.1,::1\n\n当前版本需在系统设置中完成切换；返回 ClashOS 后会自动更新实际状态。使用期间保持 ClashOS 运行。`,
      primaryButton: { value: '打开代理设置', action: () => this.openSystemNetworkSettings() },
      secondaryButton: { value: '关闭', action: () => {} }
    });
  }

  private async openSystemNetworkSettings(): Promise<void> {
    if (this.systemProxyOpening) return;
    this.systemProxyOpening = true;
    try {
      const context = this.getUIContext().getHostContext() as common.UIAbilityContext;
      // HarmonyOS PC Settings uses this URI for Network > Proxy, including onNewWant.
      await context.startAbility({
        bundleName: 'com.huawei.hmos.settings',
        abilityName: 'com.huawei.hmos.settings.MainAbility',
        uri: 'pc_network_proxy_settings'
      });
    } catch (_) { this.notice = '请手动打开系统设置 → 网络 → 代理'; }
    finally { this.systemProxyOpening = false; }
  }

  private visibleProviders(): ClashProxyProvider[] {
    const query: string = this.providerQuery.trim().toLowerCase();
    return this.proxyProviders.filter((provider: ClashProxyProvider) =>
      provider.name.toLowerCase().indexOf(query) >= 0 || provider.proxies.some((name: string) => name.toLowerCase().indexOf(query) >= 0));
  }

  private visibleRuleProviders(): ClashRuleProvider[] {
    const query: string = this.ruleProviderQuery.trim().toLowerCase();
    return this.ruleProviders.filter((provider: ClashRuleProvider) =>
      `${provider.name} ${provider.behavior} ${provider.format}`.toLowerCase().indexOf(query) >= 0);
  }

  private ruleProviderKey(provider: ClashRuleProvider): string {
    return `${this.activeProfileId}/${provider.name}`;
  }

  private canUpdateRuleProvider(provider: ClashRuleProvider): boolean {
    const kind: string = provider.vehicleType.toLowerCase();
    return this.coreConnected && (kind === 'http' || kind === 'file') && !provider.updating &&
      this.requestingRuleProviders.indexOf(this.ruleProviderKey(provider)) < 0;
  }

  private async ruleProviderAction(provider: ClashRuleProvider, action: string): Promise<void> {
    const key: string = this.ruleProviderKey(provider);
    if (this.requestingRuleProviders.indexOf(key) >= 0) return;
    const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    const version: number = this.mutationVersion;
    let resource: string | undefined = undefined;
    this.requestingRuleProviders = [...this.requestingRuleProviders, key];
    try {
      if (action === 'import') {
        if (profile === undefined || this.profileStore === undefined || !this.internalCore) return;
        resource = await this.profileStore.pickRuleProviderFile();
        if (resource === undefined) return;
        if (version !== this.mutationVersion) throw new Error('当前配置已更改，请重新选择规则文件');
        await this.coreApi.importRuleProviderFile(provider.name, this.connectedRuntime.configPath, resource);
        this.notice = `${provider.name} 已导入，规则已参与分流`;
      } else if (action === 'reset') {
        if (profile === undefined) return;
        await this.coreApi.resetRuleProviderFile(provider.name, this.connectedRuntime.configPath);
        this.notice = `${provider.name} 已恢复配置中的规则文件`;
      } else if (action === 'update') {
        await this.coreApi.updateRuleProvider(provider.name, this.internalCore ? this.connectedRuntime.configPath : '');
        if (version === this.mutationVersion) this.notice = `${provider.name} 已请求更新`;
      } else {
        const data: ClashRulePayload = await this.coreApi.ruleProviderPayload(provider.name);
        if (version !== this.mutationVersion) return;
        const lines: string = data.payload.join('\n');
        if (action === 'copy') this.copyText(lines, '规则集合内容');
        else {
          this.dialogController?.close();
          this.dialogController = new CustomDialogController({
            builder: TextViewerDialog({ title: `${provider.name} · ${provider.behavior.toUpperCase()} / ${provider.format.toUpperCase()}`,
              content: `${data.ruleCount} 条规则${data.truncated ? ` · 仅展示前 ${data.payload.length} 项` : ''}\n\n${lines}` }),
            autoCancel: true, customStyle: true
          });
          this.dialogController.open();
        }
      }
    } catch (error) {
      if (version === this.mutationVersion) this.notice = `规则集合操作失败：${(error as Error).message}`;
    } finally {
      if (resource !== undefined) {
        try { this.profileStore?.releaseRuleImport(resource); }
        catch (_) { this.addLog('WARN', '临时规则文件清理失败'); }
      }
      this.requestingRuleProviders = this.requestingRuleProviders.filter((item: string) => item !== key);
      await this.refreshCore();
    }
  }

  private async updateAllRuleProviders(): Promise<void> {
    const providers: ClashRuleProvider[] = this.ruleProviders.filter((item: ClashRuleProvider) => this.canUpdateRuleProvider(item));
    await Promise.all(providers.map((item: ClashRuleProvider) => this.ruleProviderAction(item, 'update')));
  }

  private canUpdateProvider(provider: ClashProxyProvider): boolean {
    const kind: string = provider.vehicleType.toLowerCase();
    return this.coreConnected && (kind === 'http' || kind === 'file') && !provider.updating &&
      this.requestingProviders.indexOf(provider.name) < 0;
  }

  private async resetProviderFile(provider: ClashProxyProvider): Promise<void> {
    const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    if (profile === undefined) return;
    try {
      await this.coreApi.resetProviderFile(provider.name, this.connectedRuntime.configPath);
      this.notice = `${provider.name} 已恢复配置中的文件路径`;
      await this.refreshCore();
    } catch (error) { this.notice = `恢复文件集合失败：${(error as Error).message}`; }
  }

  private async importProviderFile(provider: ClashProxyProvider): Promise<void> {
    const profile: ClashProfile | undefined = this.profiles.find((item: ClashProfile) => item.id === this.activeProfileId);
    if (profile === undefined || this.profileStore === undefined || !this.internalCore) return;
    const version: number = this.mutationVersion;
    try {
      const content: string | undefined = await this.profileStore.pickProviderContent();
      if (content === undefined) return;
      if (version !== this.mutationVersion) throw new Error('当前配置已更改，请重新选择代理集合');
      this.requestingProviders = [...this.requestingProviders, provider.name];
      await this.coreApi.importProviderFile(provider.name, content, this.connectedRuntime.configPath);
      this.notice = `${provider.name} 已导入文件并更新节点`;
    } catch (error) { this.notice = `导入代理集合失败：${(error as Error).message}`; }
    finally {
      this.requestingProviders = this.requestingProviders.filter((name: string) => name !== provider.name);
      await this.refreshCore();
    }
  }

  private async providerAction(provider: ClashProxyProvider, update: boolean): Promise<void> {
    if (this.requestingProviders.indexOf(provider.name) >= 0) return;
    this.requestingProviders = [...this.requestingProviders, provider.name];
    try {
      if (update) await this.coreApi.updateProvider(provider.name);
      else await this.coreApi.checkProvider(provider.name);
      this.notice = `${provider.name} 已请求${update ? '更新' : '健康检查'}`;
    } catch (error) { this.notice = `代理集合操作失败：${(error as Error).message}`; }
    finally {
      this.requestingProviders = this.requestingProviders.filter((name: string) => name !== provider.name);
      await this.refreshCore();
    }
  }

  private async updateAllProviders(): Promise<void> {
    const providers: ClashProxyProvider[] = this.proxyProviders.filter((provider: ClashProxyProvider) => this.canUpdateProvider(provider));
    await Promise.all(providers.map((provider: ClashProxyProvider) => this.providerAction(provider, true)));
  }

  private providerTime(value: string): string {
    const date: Date = new Date(value);
    if (Number.isNaN(date.getTime())) return '尚未更新';
    return `${date.getFullYear()}/${date.getMonth() + 1}/${date.getDate()} ${this.clockText(date)}`;
  }

  private toggleProvider(name: string): void {
    this.expandedProviders = this.expandedProviders.indexOf(name) >= 0 ?
      this.expandedProviders.filter((item: string) => item !== name) : [...this.expandedProviders, name];
  }

  private async groupAutomation(group: ClashProxyGroup, automatic: boolean): Promise<void> {
    try {
      await this.coreApi.groupAction(group.name, automatic ? 'auto' : 'healthcheck');
      this.notice = automatic ? `${group.name} 已恢复自动选择，正在检查可用节点` : `${group.name} 已请求健康检查`;
      await this.refreshCore();
    } catch (error) { this.notice = `代理组操作失败：${(error as Error).message}`; }
  }

  private isBalancedGroup(group: ClashProxyGroup): boolean {
    return group.type.toLowerCase().replace(/-/g, '') === 'loadbalance';
  }

  private balancePolicyText(group: ClashProxyGroup): string {
    if (group.strategy === 'round-robin') return '轮询';
    if (group.strategy === 'sticky-sessions') return '会话保持';
    return group.strategy === 'consistent-hashing' ? '一致性哈希' : '按请求分配';
  }

  private async clearBalancedSessions(group: ClashProxyGroup): Promise<void> {
    try {
      await this.coreApi.groupAction(group.name, 'reset-sessions');
      this.notice = `${group.name} 的会话分配缓存已清除`;
      await this.refreshCore();
    } catch (error) { this.notice = `清除会话分配失败：${(error as Error).message}`; }
  }

  private async openSystemNetworkCheck(): Promise<void> {
    const version: number = this.mutationVersion, connected: boolean = this.coreConnected;
    const instance: string = this.connectedRuntime.instance;
    try {
      const initial: ClashRuntimeConfig | undefined = this.internalCore && connected ? await this.coreApi.runtimeConfig() : undefined;
      const isCurrent = async (): Promise<boolean> => {
        if (!this.pageActive || version !== this.mutationVersion || connected !== this.coreConnected || instance !== this.connectedRuntime.instance) return false;
        if (initial) {
          try {
            const current = await this.coreApi.runtimeConfig();
            return current.path === initial.path && current.revision === initial.revision && this.pageActive &&
              version === this.mutationVersion && connected === this.coreConnected && instance === this.connectedRuntime.instance;
          }
          catch (_) { return false; }
        }
        return true;
      };
      if (!await isCurrent()) return;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: SystemNetworkDialog({ isCurrent,
        onCopy: (text: string): void => { this.copyText(text, '联网检测报告'); },
        onSettings: (): void => { this.openSystemNetworkSettings(); },
        onFinished: (): void => { this.refreshSystemProxy(); this.refreshCore(); }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (_) { this.notice = '无法打开联网检测，请刷新内核状态后重试'; }
  }

  private async openProbeSeries(name: string = this.selectedProxy): Promise<void> {
    if (!this.coreConnected || !name || name === 'REJECT') return;
    const version: number = this.mutationVersion;
    try {
      const initial: ClashRuntimeConfig | undefined = this.internalCore ? await this.coreApi.runtimeConfig() : undefined;
      let valid: boolean = true;
      const isCurrent = (): boolean => valid && this.pageActive && this.coreConnected && version === this.mutationVersion;
      const check = async (): Promise<void> => {
        if (!isCurrent()) throw new Error('当前配置或连接状态已变化');
        if (initial) {
          try {
            const current: ClashRuntimeConfig = await this.coreApi.runtimeConfig();
            if (current.path !== initial.path || current.revision !== initial.revision) throw new Error('当前配置已变化');
          } catch (error) { valid = false; throw new Error((error as Error).message || '无法确认当前配置'); }
        }
        if (!isCurrent()) throw new Error('当前配置或连接状态已变化');
      };
      if (!isCurrent()) return;
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: ProbeSeriesDialog({ nodeName: name, initialUrl: this.testUrl,
        probe: async (node: string, url: string): Promise<number> => {
          await check();
          try { return await this.coreApi.testDelay(node, url); } finally { await check(); }
        },
        isCurrent, onCopy: (text: string): void => { this.copyText(text, '节点检测报告'); },
        onFinished: (): void => { this.refreshCore(); }
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.notice = `无法打开节点检测：${(error as Error).message}`; }
  }

  private async testNode(name: string, quiet: boolean = false): Promise<void> {
    if (!this.coreConnected || this.testingNodes.indexOf(name) >= 0 || name === 'REJECT') return;
    const revision: number = this.mutationVersion;
    this.testingNodes = [...this.testingNodes, name];
    try {
      const delay: number = await this.coreApi.testDelay(name, this.testUrl.trim());
      if (revision === this.mutationVersion) {
        this.setDelay(name, delay);
        if (!quiet) this.notice = `${name} · ${delay} ms`;
      }
    } catch (error) {
      if (revision === this.mutationVersion) {
        const message: string = probeFailureText((error as Error).message);
        this.setDelay(name, 0, message);
        if (!quiet) this.notice = `测速失败：${message}`;
      }
    } finally {
      this.testingNodes = this.testingNodes.filter((item: string) => item !== name);
    }
  }

  private async testGroup(group?: ClashProxyGroup): Promise<void> {
    if (this.batchTesting || !this.coreConnected) return;
    const unique = new Set<string>();
    (group === undefined ? this.visibleGroups() : [group]).forEach((item: ClashProxyGroup) =>
      this.visibleProxies(item).forEach((name: string) => { if (name !== 'REJECT') unique.add(name); }));
    const names: string[] = Array.from(unique);
    const revision: number = this.mutationVersion;
    this.batchTesting = true;
    try {
      for (let index: number = 0; index < names.length; index += 3) {
        if (this.mutationVersion !== revision) { this.notice = '配置或策略已变化，测速已停止'; return; }
        await Promise.all(names.slice(index, index + 3).map((name: string) => this.testNode(name, true)));
      }
      this.notice = `测速结束，共 ${names.length} 个节点或策略`;
    } finally {
      this.batchTesting = false;
    }
  }

  private async closeConnection(item: ClashConnection): Promise<void> {
    try {
      await this.coreApi.closeConnection(item.id);
      this.notice = `已断开 ${item.host}`;
      await this.refreshCore();
    } catch (error) { this.notice = `断开失败：${(error as Error).message}`; }
  }

  private async closeAllConnections(): Promise<void> {
    try {
      await this.coreApi.closeAllConnections();
      this.notice = '已请求断开全部连接';
      await this.refreshCore();
    } catch (error) { this.notice = `断开失败：${(error as Error).message}`; }
  }

  private async closeProxyConnections(name: string): Promise<void> {
    try {
      const count: number = await this.coreApi.closeProxyConnections(name);
      this.notice = `已断开 ${count} 个经过 ${name} 的连接`;
      await this.refreshCore();
    } catch (error) { this.notice = `断开失败：${(error as Error).message}`; }
  }

  private connectionDetails(item: ClashConnection): void {
    this.showMessageDialog({
      title: '连接详情',
      message: `${item.host}${item.port.length > 0 ? `:${item.port}` : ''}\n协议：${item.network.toUpperCase()}\n代理链：${this.connectionRoute(item)}\n规则：${item.rule}\n上传：${this.formatBytes(item.upload)}\n下载：${this.formatBytes(item.download)}\n开始时间：${item.start || '未知'}`,
      primaryButton: { value: '关闭', action: () => {} },
      secondaryButton: { value: '复制详情', action: () => this.copyText(JSON.stringify(item, null, 2), '连接详情') }
    });
  }

  @Builder
  private connectionContextMenu(item: ClashConnection) {
    Menu() {
      MenuItem({ content: '查看详情', startIcon: $r('app.media.verge_info') }).onClick(() => this.connectionDetails(item));
      MenuItem({ content: '复制目标地址' }).onClick(() => this.copyText(`${item.host}${item.port.length > 0 ? `:${item.port}` : ''}`, '目标地址'));
      MenuItem({ content: '复制代理链' }).onClick(() => this.copyText(this.connectionRoute(item), '代理链'));
      MenuItem({ content: '断开连接', startIcon: $r('app.media.verge_close') }).contentFontColor(this.theme.danger)
        .onClick(() => this.closeConnection(item));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  private visibleRules(): ClashRule[] {
    const query: string = this.ruleQuery.trim().toLowerCase();
    return this.rules.filter((rule: ClashRule) => `${rule.type} ${rule.payload} ${rule.proxy} ${rule.noResolve ? 'no-resolve' : ''}`.toLowerCase().indexOf(query) >= 0);
  }

  @Builder
  private ruleContextMenu(rule: ClashRule) {
    Menu() {
      MenuItem({ content: '编辑自定义规则', startIcon: $r('app.media.verge_rules') }).enabled(this.activeProfileId.length > 0 && !this.temporaryConfig)
        .onClick(() => this.openRuleEditor());
      MenuItem({ content: '复制规则' }).onClick(() => this.copyText(
        `${rule.type.toUpperCase()},${rule.payload.length > 0 ? `${rule.payload},` : ''}${rule.proxy}${rule.noResolve ? ',no-resolve' : ''}`, '规则'));
      MenuItem({ content: '复制匹配内容' }).onClick(() => this.copyText(rule.payload, '匹配内容'));
      MenuItem({ content: '复制代理策略' }).onClick(() => this.copyText(rule.proxy, '代理策略'));
      MenuItem({ content: '编辑当前配置' }).enabled(this.activeProfileId.length > 0 && !this.temporaryConfig)
        .onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private profileContextMenu(profile: ClashProfile) {
    Menu() {
      MenuItemGroup() {
        MenuItem({ content: '使用配置', startIcon: $r('app.media.verge_check') })
          .enabled(!this.profileIsActive(profile.id)).onClick(() => this.activateProfile(profile));
        MenuItem({ content: this.updatingProfiles.indexOf(profile.id) >= 0 ? '更新中…' : '更新订阅', startIcon: $r('app.media.verge_refresh') })
          .enabled(profile.sourceUrl.length > 0 && this.updatingProfiles.indexOf(profile.id) < 0)
          .onClick(() => this.updateSubscription(profile));
        MenuItem({ content: '编辑信息', startIcon: $r('app.media.verge_info') }).onClick(() => this.openProfileInfo(profile));
        if (profile.sourceUrl.length > 0 && profile.subscription?.info?.home) {
          MenuItem({ content: '订阅主页', startIcon: $r('app.media.verge_connections') }).onClick(() => this.openSubscriptionHome(profile));
        }
        MenuItem({ content: '编辑配置文件', startIcon: $r('app.media.verge_file') }).onClick(() => this.openEditor(profile));
        MenuItem({ content: '编辑规则', startIcon: $r('app.media.verge_rules') }).onClick(() => this.openRuleEditor(profile));
        MenuItem({ content: '编辑节点', startIcon: $r('app.media.verge_proxies') }).onClick(() => this.openObjectEditor(profile, 0));
        MenuItem({ content: '编辑扩展配置' }).onClick(() => this.openMergeEditor(false, profile));
        MenuItem({ content: '编辑扩展脚本' }).onClick(() => this.openMergeEditor(false, profile, true));
        MenuItem({ content: '编辑代理组', startIcon: $r('app.media.verge_proxies') }).onClick(() => this.openObjectEditor(profile, 1));
      }
      MenuItemGroup() {
        MenuItem({ content: profile.pinned ? '取消置顶' : '置顶配置' }).onClick(() => this.pinProfile(profile));
        MenuItem({ content: '创建副本' }).onClick(() => this.duplicateProfile(profile));
        MenuItem({ content: '导出文件', startIcon: $r('app.media.verge_download') }).onClick(() => this.exportProfile(profile));
        MenuItem({ content: '复制配置内容' }).onClick(() => this.copyProfile(profile));
        MenuItem({ content: '复制订阅链接' }).enabled(profile.sourceUrl.length > 0)
          .onClick(() => this.copyText(profile.sourceUrl, '订阅链接'));
        MenuItem({ content: '复制文件路径' }).onClick(() => this.copyText(profile.path, '文件路径'));
      }
      MenuItemGroup() {
        MenuItem({ content: profile.id === this.activeProfileId ? '当前配置使用中' : '删除配置', startIcon: $r('app.media.verge_trash') })
          .contentFontColor(this.theme.danger).enabled(profile.id !== this.activeProfileId)
          .onClick(() => this.confirmRemoveProfile(profile));
      }
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private profileAreaMenu() {
    Menu() {
      MenuItem({ content: '新建本地配置', startIcon: $r('app.media.verge_file') }).onClick(() => this.openEditor());
      MenuItem({ content: '导入本地文件', startIcon: $r('app.media.verge_import') }).onClick(() => this.importProfile());
      MenuItem({ content: '添加远程订阅' }).onClick(() => this.openProfileInfo());
      MenuItem({ content: '从剪贴板导入' }).onClick(() => this.importClipboard());
      MenuItem({ content: '导入节点链接' }).onClick(() => this.openNodeImport());
      MenuItem({ content: '全局扩展配置' }).onClick(() => this.openMergeEditor(true));
      MenuItem({ content: '全局扩展脚本' }).onClick(() => this.openMergeEditor(true, undefined, true));
      MenuItem({ content: '刷新配置列表', startIcon: $r('app.media.verge_refresh') }).onClick(() => this.reloadProfiles());
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private nodeContextMenu(group: ClashProxyGroup, name: string) {
    Menu() {
      MenuItem({ content: '编辑配置节点' }).enabled(!this.temporaryConfig && this.activeProfileId.length > 0 && name !== 'DIRECT' && name !== 'REJECT' && (!this.coreConnected || this.internalCore))
        .onClick(() => this.openObjectEditor(undefined, 0, name));
      if (!this.isBalancedGroup(group)) {
        MenuItem({ content: name === group.now ? '当前选择' : '选择此节点', startIcon: $r('app.media.verge_check') })
          .enabled(name !== group.now && this.coreConnected && this.pendingProxy.length === 0)
          .onClick(() => this.chooseProxy(group.name, name));
        MenuItem({ content: '切换并关闭组内连接' }).enabled(this.coreConnected && this.pendingProxy.length === 0)
          .onClick(() => this.chooseProxy(group.name, name, true));
      }
      MenuItem({ content: '测试延迟', startIcon: $r('app.media.verge_chart') })
        .enabled(this.coreConnected && name !== 'REJECT' && this.testingNodes.indexOf(name) < 0).onClick(() => this.testNode(name));
      MenuItem({ content: '连续检测节点', startIcon: $r('app.media.verge_chart') }).enabled(this.coreConnected && name !== 'REJECT')
        .onClick(() => this.openProbeSeries(name));
      MenuItem({ content: '查看测速结果' }).enabled(this.nodeDelay(name) >= 0)
        .onClick(() => this.notice = this.delayErrors[name] || `${name} · ${this.nodeDelayText(name)}`);
      MenuItem({ content: '断开经过此节点的连接' }).enabled(this.coreConnected).onClick(() => this.closeProxyConnections(name));
      MenuItem({ content: '复制节点名称' }).onClick(() => this.copyText(name, '节点名称'));
      MenuItem({ content: '复制所属代理组' }).onClick(() => this.copyText(group.name, '代理组名称'));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private groupContextMenu(group: ClashProxyGroup) {
    Menu() {
      MenuItem({ content: '编辑代理组配置' }).enabled(!this.temporaryConfig && this.activeProfileId.length > 0 && (!this.coreConnected || this.internalCore))
        .onClick(() => this.openObjectEditor(undefined, 1, group.name));
      MenuItem({ content: '自定义图标' }).onClick(() => this.openGroupIcon(group));
      MenuItem({ content: '恢复配置图标' }).enabled(this.groupIcons.some((entry: GroupIconEntry) => entry.name === group.name))
        .onClick(() => this.resetGroupIcon(group));
      MenuItem({ content: this.collapsedGroups.indexOf(group.name) >= 0 ? '展开代理组' : '收起代理组' })
        .onClick(() => this.toggleGroup(group.name));
      MenuItem({ content: '测试此组延迟', startIcon: $r('app.media.verge_chart') })
        .enabled(this.coreConnected && !this.batchTesting).onClick(() => this.testGroup(group));
      if (this.internalCore && (group.type === 'URLTest' || group.type === 'Fallback' || this.isBalancedGroup(group))) {
        MenuItem({ content: group.checking ? '正在健康检查…' : '立即健康检查', startIcon: $r('app.media.verge_refresh') })
          .enabled(this.coreConnected && !group.checking).onClick(() => this.groupAutomation(group, false));
        if (!this.isBalancedGroup(group)) {
          MenuItem({ content: '恢复自动选择', startIcon: $r('app.media.verge_check') })
            .enabled(this.coreConnected && (group.manual ?? '').length > 0).onClick(() => this.groupAutomation(group, true));
        } else if (group.strategy === 'sticky-sessions') {
          MenuItem({ content: '清除会话分配缓存' }).enabled(this.coreConnected)
            .onClick(() => this.clearBalancedSessions(group));
        }
      }
      MenuItem({ content: '断开此组连接' }).enabled(this.coreConnected).onClick(() => this.closeProxyConnections(group.name));
      MenuItem({ content: this.isBalancedGroup(group) ? '复制最近出站' : '复制当前节点' })
        .enabled(this.isBalancedGroup(group) ? (group.lastSelected ?? '').length > 0 : group.now.length > 0)
        .onClick(() => this.copyText(this.isBalancedGroup(group) ? group.lastSelected ?? '' : group.now, '节点名称'));
      MenuItem({ content: '复制全部节点名称' }).onClick(() => this.copyText(group.proxies.join('\n'), '节点列表'));
      MenuItem({ content: '刷新代理组', startIcon: $r('app.media.verge_refresh') }).onClick(() => { ++this.groupIconRevision; this.refreshCore(); });
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private logContextMenu(entry: UiLogEntry) {
    Menu() {
      MenuItem({ content: '复制此条日志' }).onClick(() => this.copyText(`[${entry.time}] [${entry.level}] ${entry.message}`, '日志'));
      MenuItem({ content: '复制全部日志' }).onClick(() => this.copyText(
        this.logEntries.map((item: UiLogEntry) => `[${item.time}] [${item.level}] ${item.message}`).join('\n'), '全部日志'));
      MenuItem({ content: '导出日志', startIcon: $r('app.media.verge_download') }).onClick(() => this.exportLogs());
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private icon(source: Resource, size: number = 20, color: string = 'textSecondary') {
    Image(source)
      .fillColor(this.filledIcon(source) ? this.colorFor(color) : Color.Transparent)
      .width(size)
      .height(size)
      .colorFilter(this.iconColor(this.colorFor(color)))
      .draggable(false);
  }

  private colorFor(role: string): string {
    switch (role) {
      case 'text': return this.theme.text;
      case 'textMuted': return this.theme.textMuted;
      case 'primary': return this.theme.primary;
      case 'onPrimary': return this.theme.onPrimary;
      case 'success': return this.theme.success;
      case 'warning': return this.theme.warning;
      case 'danger': return this.theme.danger;
      case 'purple': return this.theme.purple;
      default: return this.theme.textSecondary;
    }
  }

  private filledIcon(source: Resource): boolean {
    return source.id === $r('app.media.verge_home').id || source.id === $r('app.media.verge_profiles').id ||
      source.id === $r('app.media.verge_connections').id || source.id === $r('app.media.verge_more').id ||
      source.id === $r('app.media.verge_fallback').id;
  }

  @Builder
  private navigationItem(index: number) {
    Button({ type: ButtonType.Normal }) {
      if (this.windowWidth < 1000) {
        Column({ space: 3 }) {
          this.icon(this.navIcons[index], 20, 'text');
          Text(this.navItems[index]).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold)
            .fontColor(this.theme.text).maxLines(1);
        }.width(this.windowWidth < 560 ? 42 : 48);
      } else {
        Row({ space: 9 }) {
          this.icon(this.navIcons[index], 23, 'text');
          Text(this.navItems[index])
            .fontSize(this.theme.font(this.windowWidth >= 1180 ? 16 : 14)).fontFamily(this.theme.fontFamily)
            .fontWeight(FontWeight.Bold)
            .fontColor(this.theme.text)
            .maxLines(1);
        }
        .padding({ left: this.windowWidth >= 1180 ? 18 : 12, right: this.windowWidth >= 1180 ? 18 : 12 });
      }
    }
    .height(this.windowWidth < 1000 ? 48 : this.theme.navigationItemHeight)
    .padding(0)
    .borderRadius(this.theme.cardRadius)
    .backgroundColor(this.selectedTab === index ? this.theme.navigationSelected :
      this.hoverTab === index ? this.theme.navigationHover : Color.Transparent)
    .onHover((hovered: boolean) => this.hoverTab = hovered ? index : -1)
    .accessibilityText(`${this.navItems[index]}${this.selectedTab === index ? '，当前页面' : ''}`)
    .keyboardShortcut(`${this.navOrder.indexOf(index) + 1}`, [ModifierKey.CTRL], () => this.navigate(index))
    .onAreaChange((_old: Area, area: Area) => this.navigationPositions[index] = Number(area.position.x))
    .onClick(() => this.navigate(index));
  }

  @Builder
  private navigationTraffic() {
    Row({ space: 12 }) {
      Stack({ alignContent: Alignment.BottomStart }) {
        Divider().color(this.theme.border).margin({ bottom: 12 });
        Polyline().points(this.trafficPoints(this.uploadSamples, 62, 28))
          .stroke(this.theme.warning).strokeWidth(1.5).fill(Color.Transparent);
        Polyline().points(this.trafficPoints(this.downloadSamples, 62, 28))
          .stroke(this.theme.primary).strokeWidth(1.5).fill(Color.Transparent);
      }.width(62).height(30).clip(true);
      Column({ space: 3 }) {
        Text(`↑ ${this.rateText(this.uploadRate)}`).fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning);
        Text(`↓ ${this.rateText(this.downloadRate)}`).fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
      }.alignItems(HorizontalAlign.Start).constraintSize({ minWidth: 66 });
    }.padding({ left: 18 }).height(36)
      .border({ width: { left: 1 }, color: this.theme.border });
  }

  @Builder
  private navigationBar() {
    Row({ space: this.windowWidth >= 1180 ? 24 : 12 }) {
      Button({ type: ButtonType.Normal }) {
        Row({ space: 11 }) {
          Image($r('app.media.verge_mark')).fillColor(this.theme.text).colorFilter(this.iconColor(this.theme.text)).width(30).height(30).draggable(false);
          if (this.windowWidth >= 1000) {
            Text('ClashOS').fontSize(this.theme.font(21)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text);
          }
        }
      }
      .height(this.theme.navigationItemHeight).padding(0).backgroundColor(Color.Transparent)
      .accessibilityText('ClashOS 首页')
      .onClick(() => this.navigate(0));
      Scroll(this.navigationScroller) {
        Row({ space: 4 }) {
          ForEach(this.navOrder, (index: number) => {
            this.navigationItem(index);
          }, (index: number) => `${index}`);
        }.height(this.windowWidth < 1000 ? 48 : this.theme.navigationItemHeight);
      }
      .layoutWeight(1)
      .align(Alignment.Start)
      .scrollable(ScrollDirection.Horizontal)
      .scrollBar(BarState.Off);
      if (this.windowWidth >= 1440) {
        this.navigationTraffic();
      }
    }
    .width('100%')
    .height(this.theme.navigationHeight)
    .padding({ left: this.windowWidth >= 780 ? 24 : 16, right: this.windowWidth >= 780 ? 24 : 16 })
    .backgroundColor(this.theme.chrome)
    .border({ width: { bottom: 1 }, color: this.theme.border });
  }

  @Builder
  private iconButton(source: Resource, label: string, action: () => void, active: boolean = false) {
    Button({ type: ButtonType.Normal }) {
      this.icon(source, 19, active ? 'primary' : 'textSecondary');
    }
    .width(34).height(34).borderRadius(this.theme.radius(5))
    .backgroundColor(active ? this.theme.primaryHover :
      this.hoveredAction === label ? this.theme.navigationHover : Color.Transparent)
    .hoverEffect(HoverEffect.None)
    .onHover((hovered: boolean) => this.hoveredAction = hovered ? label : '')
    .accessibilityText(label)
    .onClick(action);
  }

  @Builder
  private proxyToolbarMenu() {
    Menu() {
      MenuItem({ content: '编辑节点' }).enabled(!this.temporaryConfig && this.activeProfileId.length > 0 && (!this.coreConnected || this.internalCore)).onClick(() => this.openObjectEditor(undefined, 0));
      MenuItem({ content: '编辑代理组' }).enabled(!this.temporaryConfig && this.activeProfileId.length > 0 && (!this.coreConnected || this.internalCore)).onClick(() => this.openObjectEditor(undefined, 1));
      MenuItem({ content: this.collapsedGroups.length === this.proxyGroups.length ? '展开全部代理组' : '收起全部代理组' })
        .onClick(() => this.toggleAllGroups());
      MenuItem({ content: this.proxySort === 'delay' ? '按配置顺序排列' : '按节点延迟排列' })
        .onClick(() => this.proxySort = this.proxySort === 'delay' ? 'default' : 'delay');
      MenuItem({ content: this.batchTesting ? '正在测试延迟…' : '测试全部节点延迟', startIcon: $r('app.media.verge_speed') })
        .enabled(this.coreConnected && !this.batchTesting).onClick(() => this.testGroup());
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private outlineButton(label: string, source: Resource, action: () => void, enabled: boolean = true) {
    Button({ type: ButtonType.Normal }) {
      Row({ space: 7 }) {
        this.icon(source, 16, 'primary');
        Text(label).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
      }
    }
    .height(34)
    .padding({ left: 12, right: 12 })
    .borderRadius(this.theme.radius(5))
    .border({ width: 1, color: this.theme.primaryBorder })
    .backgroundColor(this.theme.surface)
    .enabled(enabled).onClick(action);
  }

  @Builder
  private primaryButton(label: string, source: Resource, action: () => void) {
    Button({ type: ButtonType.Normal }) {
      Row({ space: 7 }) {
        this.icon(source, 16, 'onPrimary');
        Text(label).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary);
      }
    }
    .height(34)
    .padding({ left: 14, right: 14 })
    .borderRadius(this.theme.radius(5))
    .backgroundColor(this.theme.primary)
    .onClick(action);
  }

  @Builder
  private modeButton(label: string, mode: string) {
    Button(label, { type: ButtonType.Normal })
      .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
      .fontColor(this.coreMode === mode ? this.theme.onPrimary : this.theme.primary)
      .backgroundColor(this.coreMode === mode ? this.theme.primary : this.theme.surface)
      .height(32)
      .width(58 * Math.max(1, this.theme.fontScale))
      .borderRadius(this.theme.radius(0))
      .onClick(() => this.changeMode(mode));
  }

  @Builder
  private modeControl() {
    Row({ space: 0 }) {
      this.modeButton('规则', 'Rule');
      Divider().vertical(true).height(32).color(this.theme.primaryBorder);
      this.modeButton('全局', 'Global');
      Divider().vertical(true).height(32).color(this.theme.primaryBorder);
      this.modeButton('直连', 'Direct');
    }
    .border({ width: 1, color: this.theme.primaryBorder })
    .borderRadius(this.theme.radius(5))
    .clip(true);
  }

  @Builder
  private proxyPageMenu() {
    if (this.showProviderCollections) {
      this.providerToolbarMenu();
    } else {
      this.proxyToolbarMenu();
    }
  }

  @Builder
  private providerToolbarMenu() {
    Menu() {
      MenuItem({ content: '更新全部代理集合', startIcon: $r('app.media.verge_refresh') })
        .enabled(this.coreConnected && this.proxyProviders.some((provider: ClashProxyProvider) => this.canUpdateProvider(provider)))
        .onClick(() => this.updateAllProviders());
      MenuItem({ content: '编辑当前配置', startIcon: $r('app.media.verge_file') })
        .enabled(this.activeProfileId.length > 0 && !this.temporaryConfig).onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private pageActions() {
    Row({ space: 8 }) {
      if (this.selectedTab === 1) {
        Button(this.showProviderCollections ? '代理组' : '代理集合', { type: ButtonType.Normal })
          .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).height(34)
          .padding({ left: 12, right: 12 }).borderRadius(this.theme.radius(5))
          .border({ width: 1, color: this.theme.primaryBorder }).backgroundColor(this.showProviderCollections ? this.theme.primarySoft : Color.Transparent)
          .onClick(() => {
            this.showProviderCollections = !this.showProviderCollections;
            this.showProxySearch = false;
            this.contentScroller.scrollTo({ xOffset: 0, yOffset: 0 });
          });
        if (!this.showProviderCollections) { this.modeControl(); }
        this.iconButton($r('app.media.verge_search'), '搜索节点', () => {
          this.showProxySearch = !this.showProxySearch;
          if (!this.showProxySearch) { this.proxyQuery = ''; this.providerQuery = ''; }
        }, this.showProxySearch);
        this.iconButton($r('app.media.verge_refresh'), '刷新代理组', () => this.refreshCore());
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_more'), 20, 'textSecondary');
        }.width(30).height(34).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
          .accessibilityText(this.showProviderCollections ? '代理集合操作' : '代理组操作')
          .bindMenu(this.proxyPageMenu());
      } else if (this.selectedTab === 2) {
        this.outlineButton('编辑规则', $r('app.media.verge_rules'), () => this.openRuleEditor());
        Button(this.showRuleProviders ? '路由规则' : '规则集合', { type: ButtonType.Normal })
          .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).height(34).padding({ left: 12, right: 12 }).borderRadius(this.theme.radius(5))
          .border({ width: 1, color: this.theme.primaryBorder }).backgroundColor(this.showRuleProviders ? this.theme.primarySoft : Color.Transparent)
          .onClick(() => { this.showRuleProviders = !this.showRuleProviders; this.contentScroller.scrollTo({ xOffset: 0, yOffset: 0 }); });
        this.modeControl();
        this.iconButton($r('app.media.verge_refresh'), '刷新规则', () => this.refreshCore());
        if (this.showRuleProviders) {
          Button({ type: ButtonType.Normal }) {
            this.icon($r('app.media.verge_more'), 20, 'textSecondary');
          }.width(30).height(34).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
            .accessibilityText('规则集合操作').bindMenu(this.ruleProvidersMenu());
        }
      } else if (this.selectedTab === 4) {
        this.outlineButton('新建配置', $r('app.media.verge_file'), () => this.openEditor());
        this.primaryButton('导入配置', $r('app.media.verge_import'), () => this.importProfile());
      } else if (this.selectedTab === 5) {
        this.outlineButton('导出日志', $r('app.media.verge_download'), () => this.exportLogs());
        this.outlineButton('清空', $r('app.media.verge_trash'), () => {
          this.logEntries = [];
          this.notice = '';
        });
      } else if (this.selectedTab === 7) {
        if (this.internalCore) this.outlineButton('清空 DNS 缓存', $r('app.media.verge_trash'), () => this.clearDnsCache());
        this.iconButton($r('app.media.verge_refresh'), '刷新 DNS 状态', () => this.refreshDnsStatus());
      } else if (this.selectedTab === 6) {
        this.outlineButton('备份与恢复', $r('app.media.verge_download'), () => this.openBackupManager());
        this.iconButton($r('app.media.verge_refresh'), '刷新状态', () => this.refreshCore());
      } else {
        this.iconButton($r('app.media.verge_refresh'), '刷新状态', () => this.refreshCore());
      }
    }
  }

  @Builder
  private pageTitle() {
    Text(this.selectedTab === 1 ? this.showProviderCollections ? '代理集合' : '代理组' :
      this.selectedTab === 2 && this.showRuleProviders ? '规则集合' : this.navItems[this.selectedTab])
      .fontSize(this.theme.font(22)).fontFamily(this.theme.fontFamily)
      .fontWeight(FontWeight.Bold)
      .fontColor(this.theme.text)
      .maxLines(1);
  }

  @Builder
  private pageHeader() {
    Column({ space: 0 }) {
      if (this.windowWidth < 640 && this.selectedTab !== 0 && this.selectedTab !== 3 && this.selectedTab !== 6) {
        Row() {
          this.pageTitle();
        }.width('100%').height(44);
        Scroll() {
          this.pageActions();
        }.width('100%').height(44).scrollable(ScrollDirection.Horizontal).scrollBar(BarState.Off);
      } else {
        Row({ space: 12 }) {
          this.pageTitle();
          Blank();
          this.pageActions();
        }.width('100%').height(this.theme.pageHeaderHeight);
      }
    }
    .width('100%')
    .padding({ left: this.windowWidth >= 780 ? 26 : 16, right: this.windowWidth >= 780 ? 22 : 16 })
    .backgroundColor(this.theme.chrome)
    .border({ width: { bottom: 1 }, color: this.theme.border });
  }

  @Builder
  private noticeBar() {
    if (this.notice.length > 0) {
      Row({ space: 10 }) {
        this.icon($r('app.media.verge_info'), 17, 'primary');
        Text(this.notice).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).layoutWeight(1);
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_close'), 15, 'textSecondary');
        }
        .width(26).height(26).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
        .accessibilityText('关闭提示')
        .onClick(() => this.notice = '');
      }
      .width('100%')
      .padding({ left: 14, right: 8, top: 9, bottom: 9 })
      .borderRadius(this.theme.radius(6))
      .backgroundColor(this.theme.primarySoft)
      .margin({ bottom: 16 });
    }
  }

  @Builder
  private cardTitle(title: string, source: Resource) {
    Row({ space: 9 }) {
      this.icon(source, 18, 'textSecondary');
      Text(title).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text);
    }
    .width('100%');
  }

  @Builder
  private emptyState(title: string, detail: string, source: Resource) {
    Column({ space: 10 }) {
      this.icon(source, 34, 'textMuted');
      Text(title).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
      Text(detail).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).textAlign(TextAlign.Center);
    }
    .width('100%')
    .padding({ top: 48, bottom: 48, left: 24, right: 24 });
  }

  @Builder
  private overview() {
    Column({ space: 16 }) {
      if (this.geoStatus !== undefined && this.geoStatus.resources.some((resource: ClashGeoResource) => resource.required && !resource.ready)) {
        Row({ space: 12 }) {
          this.icon($r('app.media.verge_info'), 18, 'warning');
          Text('分流数据库尚未就绪，可在设置中查看下载状态').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1);
          Button('查看数据库', { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary)
            .backgroundColor(Color.Transparent).onClick(() => this.navigate(6));
        }.width('100%').padding(14).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.warningSoft);
      }
      if (this.coreConnected && this.ruleProviders.some((provider: ClashRuleProvider) => !provider.ready)) {
        Row({ space: 12 }) {
          this.icon($r('app.media.verge_info'), 18, 'warning');
          Text('规则集合尚未就绪，受影响的请求暂时拒绝转发').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1);
          Button('查看规则集合', { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary)
            .backgroundColor(Color.Transparent).onClick(() => { this.navigate(2); this.showRuleProviders = true; });
        }.width('100%').padding(14).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.warningSoft);
      }
      GridRow({ columns: { sm: 1, md: 3, lg: 3 }, gutter: 16 }) {
        GridCol({ span: { sm: 1, md: 2, lg: 2 } }) {
          this.trafficCard();
        }
        GridCol({ span: 1 }) {
          this.networkCard();
        }
      }
      GridRow({ columns: { sm: 1, md: 2, lg: 4 }, gutter: 16 }) {
        GridCol() {
          this.summaryCard({ title: '活动连接', value: this.coreConnected ? `${this.activeConnections}` : '—',
            detail: '当前连接数', source: $r('app.media.verge_connections'), color: 'primary' });
        }
        GridCol() {
          this.summaryCard({ title: '上传总量', value: this.coreConnected ? this.formatBytes(this.uploadTotal) : '—',
            detail: '本次内核运行', source: $r('app.media.verge_upload'), color: 'warning' });
        }
        GridCol() {
          this.summaryCard({ title: '下载总量', value: this.coreConnected ? this.formatBytes(this.downloadTotal) : '—',
            detail: '本次内核运行', source: $r('app.media.verge_download'), color: 'primary' });
        }
        GridCol() {
          this.summaryCard({ title: '内存占用', value: this.coreConnected && this.coreMemory > 0 ? this.formatBytes(this.coreMemory) : '—',
            detail: '内核所在进程 · RSS', source: $r('app.media.verge_memory'), color: 'purple' });
        }
      }
      GridRow({ columns: { sm: 1, md: 2, lg: 2 }, gutter: 16 }) {
        GridCol() {
          Column({ space: 18 }) {
            this.cardTitle('当前代理', $r('app.media.verge_proxies'));
            Row({ space: 12 }) {
              Column({ space: 6 }) {
                Text(this.selectedProxy || '尚未选择节点')
                  .fontSize(this.theme.font(18)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text)
                  .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                Text(this.selectedGroupName || '导入配置后选择代理组')
                  .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted)
                  .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
              }
              .alignItems(HorizontalAlign.Start).layoutWeight(1);
              this.icon($r('app.media.verge_arrow'), 20, 'primary');
            }
            Row({ space: 8 }) {
              this.typeChip(`${this.modeName()}模式`);
              Text(`${this.proxyGroups.length} 个代理组`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.width('100%');
          }
          .width('100%').height(166).padding(20).borderRadius(this.theme.radius(8))
          .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface)
          .onClick(() => this.navigate(1));
        }
        GridCol() {
          Column({ space: 18 }) {
            this.cardTitle('当前配置', $r('app.media.verge_profiles'));
            Row({ space: 12 }) {
              Column({ space: 6 }) {
                Text(this.activeProfileName())
                  .fontSize(this.theme.font(18)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text)
                  .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                Text(this.profiles.length > 0 ? `已保存 ${this.profiles.length} 份本地配置` : '支持 YAML / YML / JSON 配置')
                  .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
              }
              .alignItems(HorizontalAlign.Start).layoutWeight(1);
              this.icon($r('app.media.verge_arrow'), 20, 'primary');
            }
            Row({ space: 8 }) {
              this.typeChip('本地配置');
              Text(this.coreConnected ? `${this.ruleCount} 条规则` : '等待内核连接').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.width('100%');
          }
          .width('100%').height(166).padding(20).borderRadius(this.theme.radius(8))
          .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface)
          .onClick(() => this.navigate(4));
        }
      }
      this.coreCard();
    }
    .width('100%');
  }

  @Builder
  private trafficCard() {
    Column({ space: 17 }) {
      Row() {
        Row({ space: 8 }) {
          this.icon($r('app.media.verge_chart'), 18, 'textSecondary');
          Text('实时流量').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text);
        }
        Blank();
        Text('实时更新').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.width('100%');
      Row({ space: 30 }) {
        Column({ space: 5 }) {
          Row({ space: 6 }) {
            this.icon($r('app.media.verge_download'), 16, 'primary');
            Text('下载').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
          }
          Text(this.rateText(this.downloadRate)).fontSize(this.theme.font(25)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.primary);
        }.alignItems(HorizontalAlign.Start);
        Column({ space: 5 }) {
          Row({ space: 6 }) {
            this.icon($r('app.media.verge_upload'), 16, 'warning');
            Text('上传').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
          }
          Text(this.rateText(this.uploadRate)).fontSize(this.theme.font(25)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.warning);
        }.alignItems(HorizontalAlign.Start);
      }.width('100%');
      Stack({ alignContent: Alignment.BottomStart }) {
        Column() {
          ForEach([0, 1, 2, 3], (index: number) => {
            Divider().color(this.theme.divider).strokeWidth(1).margin({ top: index === 0 ? 0 : 35 });
          }, (index: number) => `${index}`);
        }.width('100%').height(112);
        Polyline().points(this.trafficPoints(this.uploadSamples)).stroke(this.theme.warning).strokeWidth(2).fill(Color.Transparent);
        Polyline().points(this.trafficPoints(this.downloadSamples)).stroke(this.theme.primary).strokeWidth(2).fill(Color.Transparent);
        if (Math.max(0, ...this.downloadSamples, ...this.uploadSamples) === 0) {
          Text(this.coreConnected ? '暂无流量变化' : '连接内核后显示流量')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%').textAlign(TextAlign.Center).margin({ bottom: 42 });
        }
      }
      .width('100%').height(112)
      .onAreaChange((_old: Area, area: Area) => this.chartWidth = Number(area.width));
    }
    .width('100%').height(274).padding(20).borderRadius(this.theme.radius(8))
    .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
  }

  @Builder
  private networkCard() {
    Column({ space: 0 }) {
      this.cardTitle('网络设置', $r('app.media.verge_settings'));
      Row() {
        Column({ space: 5 }) {
          Text('系统代理').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
          Text(this.systemProxyDescription()).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.systemProxyMatchesCore() ? this.theme.success : this.theme.textMuted)
            .maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        Button(this.systemProxyAction(), { type: ButtonType.Normal })
          .height(28).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).borderRadius(this.theme.radius(5))
          .padding({ left: 10, right: 10 }).backgroundColor(this.theme.primarySoft)
          .enabled(!this.systemProxyOpening).onClick(() => this.requestSystemProxyChange());
      }.width('100%').height(74);
      Divider().color(this.theme.divider);
      Row() {
        Column({ space: 5 }) {
          Text('虚拟网卡模式').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
          Text(this.tunBusy ? '正在切换…' : this.tunEnabled ? 'TCP / UDP 转发已开启' : '接管应用网络请求').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        Toggle({ type: ToggleType.Switch, isOn: this.tunEnabled })
          .enabled(!this.tunBusy && (this.tunEnabled || (this.internalCore && this.coreConnected && this.socksPort > 0)))
          .width(36).height(22).selectedColor(this.theme.primary).onChange((value: boolean) => this.setTunEnabled(value));
      }.width('100%').height(74);
      Divider().color(this.theme.divider);
      Row() {
        Text('代理模式').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1);
        Text(this.modeName()).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
        this.icon($r('app.media.verge_chevron'), 16, 'textMuted');
      }
      .width('100%').height(49)
      .onClick(() => this.navigate(2));
    }
    .width('100%').height(274).padding(20).borderRadius(this.theme.radius(8))
    .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
  }

  @Builder
  private summaryCard(options: SummaryCardOptions) {
    Column({ space: 13 }) {
      Row() {
        Text(options.title).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1);
        this.icon(options.source, 18, options.color);
      }.width('100%');
      Row({ space: 10 }) {
        Text(options.value).fontSize(this.theme.font(25)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).flexShrink(0);
        Text(options.detail).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).margin({ top: 8 })
          .layoutWeight(1).maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
      }.width('100%');
    }
    .width('100%').height(112 * Math.max(1, this.theme.fontScale)).padding(20).borderRadius(this.theme.radius(8))
    .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
  }

  @Builder
  private coreCard() {
    Row({ space: 12 }) {
      this.icon($r('app.media.verge_server'), 23, 'textMuted');
      Column({ space: 5 }) {
        Text(this.coreConnected ? this.coreVersion : '内核未连接')
          .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.textSecondary);
        Text(this.backgroundCore ? '后台 VPN 内核' : this.internalCore ? '内置内核' : 'External Controller').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.alignItems(HorizontalAlign.Start).layoutWeight(1);
      Text(this.coreConnected ? '运行中' : '离线').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.coreConnected ? this.theme.success : this.theme.textMuted);
      this.icon($r('app.media.verge_arrow'), 17, 'textMuted');
    }
    .width('100%').padding(18).borderRadius(this.theme.radius(8))
    .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface)
    .onClick(() => this.navigate(6));
  }

  @Builder
  private typeChip(label: string) {
    Text(label).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary)
      .padding({ left: 5, right: 5, top: 1, bottom: 1 })
      .border({ width: 1, color: this.theme.primaryBorder }).borderRadius(this.theme.radius(3));
  }

  @Builder
  private searchField(value: string, placeholder: string, onChange: (value: string) => void) {
    Row({ space: 8 }) {
      this.icon($r('app.media.verge_search'), 18, 'textMuted');
      TextInput({ text: value, placeholder }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
        .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(36).padding(0).layoutWeight(1)
        .backgroundColor(Color.Transparent).placeholderColor(this.theme.textMuted)
        .onChange(onChange);
    }
    .height(40).padding({ left: 12, right: 10 }).width('100%')
    .border({ width: 1, color: this.theme.border }).borderRadius(this.theme.radius(6)).backgroundColor(this.theme.surface);
  }

  @Builder
  private providerContextMenu(provider: ClashProxyProvider) {
    Menu() {
      if (this.internalCore && provider.vehicleType.toLowerCase() === 'file') {
        MenuItem({ content: '导入集合文件', startIcon: $r('app.media.verge_import') })
          .enabled(this.requestingProviders.indexOf(provider.name) < 0).onClick(() => this.importProviderFile(provider));
        MenuItem({ content: '恢复配置中的文件路径', startIcon: $r('app.media.verge_file') })
          .enabled(this.requestingProviders.indexOf(provider.name) < 0).onClick(() => this.resetProviderFile(provider));
      }
      MenuItem({ content: '更新代理集合', startIcon: $r('app.media.verge_refresh') })
        .enabled(this.canUpdateProvider(provider)).onClick(() => this.providerAction(provider, true));
      MenuItem({ content: provider.checking ? '正在检查…' : '健康检查', startIcon: $r('app.media.verge_speed') })
        .enabled(this.coreConnected && !provider.checking && provider.proxies.length > 0)
        .onClick(() => this.providerAction(provider, false));
      MenuItem({ content: this.expandedProviders.indexOf(provider.name) >= 0 ? '收起节点' : '查看节点' })
        .onClick(() => this.toggleProvider(provider.name));
      MenuItem({ content: '复制集合名称' }).onClick(() => this.copyText(provider.name, '集合名称'));
      MenuItem({ content: '复制全部节点名称' }).onClick(() => this.copyText(provider.proxies.join('\n'), '节点列表'));
      MenuItem({ content: '编辑当前配置', startIcon: $r('app.media.verge_file') }).enabled(this.activeProfileId.length > 0 && !this.temporaryConfig)
        .onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private providerNodeMenu(name: string) {
    Menu() {
      MenuItem({ content: '测试延迟', startIcon: $r('app.media.verge_speed') })
        .enabled(this.coreConnected && this.testingNodes.indexOf(name) < 0).onClick(() => this.testNode(name));
      MenuItem({ content: '连续检测节点', startIcon: $r('app.media.verge_chart') }).enabled(this.coreConnected && name !== 'REJECT')
        .onClick(() => this.openProbeSeries(name));
      MenuItem({ content: '复制节点名称' }).onClick(() => this.copyText(name, '节点名称'));
      MenuItem({ content: '断开经过此节点的连接', startIcon: $r('app.media.verge_close') })
        .enabled(this.coreConnected).onClick(() => this.closeProxyConnections(name));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private providerCard(provider: ClashProxyProvider) {
    Column({ space: 0 }) {
      Row({ space: 12 }) {
        this.icon($r('app.media.verge_server'), 29, 'primary');
        Column({ space: 7 }) {
          Text(provider.name).fontSize(this.theme.font(17)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Row({ space: 8 }) {
            this.typeChip(provider.vehicleType.toLowerCase() === 'file' ? '本地文件' : provider.vehicleType.toLowerCase() === 'inline' ? '内联' : provider.vehicleType);
            Text(`${provider.proxies.length} 个节点`).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            if (provider.checking) { Text('检查中').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary); }
          }
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        if (provider.updating || this.requestingProviders.indexOf(provider.name) >= 0) {
          LoadingProgress().width(20).height(20).color(this.theme.primary);
        } else {
          Button({ type: ButtonType.Normal }) {
            this.icon($r('app.media.verge_refresh'), 18, 'primary');
          }.width(32).height(32).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.primarySoft)
            .enabled(this.canUpdateProvider(provider)).accessibilityText(`更新 ${provider.name}`)
            .onClick(() => this.providerAction(provider, true));
        }
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_more'), 20, 'textSecondary');
        }.width(30).height(32).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
          .accessibilityText(`${provider.name} 的操作`).bindMenu(this.providerContextMenu(provider));
      }.width('100%').padding({ left: 20, right: 16, top: 18, bottom: 16 });
      if (provider.error.length > 0) {
        Text(`${provider.error}${provider.proxies.length > 0 ? ' · 已保留现有节点' : ''}`)
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis })
          .width('100%').padding({ left: 20, right: 20, bottom: 12 });
      }
      if (this.internalCore && provider.vehicleType.toLowerCase() === 'file' && provider.proxies.length === 0) {
        Row() {
          this.outlineButton('导入集合文件', $r('app.media.verge_import'), () => this.importProviderFile(provider));
        }.width('100%').padding({ left: 20, right: 20, bottom: 12 });
      }
      Row() {
        Text(provider.vehicleType.toLowerCase() === 'inline' ? '节点来自当前配置' : this.providerTime(provider.updatedAt))
          .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
        Button(this.expandedProviders.indexOf(provider.name) >= 0 ? '收起节点' : '查看节点', { type: ButtonType.Normal })
          .height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).backgroundColor(Color.Transparent)
          .onClick(() => this.toggleProvider(provider.name));
      }.width('100%').padding({ left: 20, right: 12, bottom: 10 });
      if (this.expandedProviders.indexOf(provider.name) >= 0) {
        Divider().color(this.theme.divider);
        Scroll() {
          Column({ space: 0 }) {
            ForEach(provider.proxies, (name: string) => {
              Row({ space: 10 }) {
                Text(name).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1)
                  .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                Text(this.nodeProtocolText(name)).fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
                Text(this.nodeDelayText(name)).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).width(70).textAlign(TextAlign.End);
              }.width('100%').height(44).padding({ left: 20, right: 20 })
                .border({ width: { bottom: 1 }, color: this.theme.divider })
                .bindContextMenu(this.providerNodeMenu(name), ResponseType.RightClick);
            }, (name: string) => name);
            if (provider.proxies.length === 0) {
              Text(provider.updating ? '正在获取节点…' : '暂无节点').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).padding(24);
            }
          }.width('100%');
        }.width('100%').constraintSize({ maxHeight: 308 }).scrollBar(BarState.Auto);
      }
    }.width('100%').borderRadius(this.theme.radius(8)).clip(true).backgroundColor(this.theme.surface)
      .bindContextMenu(this.providerContextMenu(provider), ResponseType.RightClick);
  }

  @Builder
  private providersPage() {
    Column({ space: 12 }) {
      if (this.showProxySearch) {
        this.searchField(this.providerQuery, '搜索代理集合或节点', (value: string) => this.providerQuery = value);
      }
      if (this.visibleProviders().length > 0) {
        ForEach(this.visibleProviders(), (provider: ClashProxyProvider) => {
          this.providerCard(provider);
        }, (provider: ClashProxyProvider) => JSON.stringify(provider));
      } else {
        Column() {
          this.emptyState(this.providerQuery.length > 0 ? '没有匹配的代理集合' : '暂无代理集合',
            this.providerQuery.length > 0 ? '尝试其他集合或节点名称' : '配置中的 proxy-providers 会显示在这里', $r('app.media.verge_server'));
        }.width('100%').borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface);
      }
    }.width('100%');
  }

  @Builder
  private proxyPage() {
    if (this.showProviderCollections) {
      this.providersPage();
    } else {
    Column({ space: 8 }) {
      if (this.showProxySearch) {
        this.searchField(this.proxyQuery, '搜索代理组或节点', (value: string) => this.proxyQuery = value);
      }
      if (this.batchTesting) {
        Row({ space: 8 }) {
          LoadingProgress().width(16).height(16).color(this.theme.primary);
          Text('正在测试节点延迟…').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
        }.width('100%').padding({ left: 8, top: 4, bottom: 4 });
      }
      if (this.visibleGroups().length > 0) {
        ForEach(this.visibleGroups(), (group: ClashProxyGroup) => {
          this.proxyGroupCard(group);
        }, (group: ClashProxyGroup) => JSON.stringify(group));
      } else {
        Column() {
          this.emptyState(this.proxyQuery.length > 0 ? '没有匹配的节点' : '暂无代理组',
            this.proxyQuery.length > 0 ? '尝试其他节点名称或地区' : '导入配置并连接内核后，在这里切换节点', $r('app.media.verge_proxies'));
        }.width('100%').borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface);
      }
    }.width('100%');
    }
  }

  @Builder
  private proxyGroupCard(group: ClashProxyGroup) {
    Column({ space: 0 }) {
      Row({ space: 14 }) {
        Stack() {
          ProxyGroupIcon({ source: this.groupIconSource(group), revision: this.groupIconRevision, emoji: this.groupEmoji(group.name),
            fallback: this.groupIcon(group.type), iconSize: 32, color: group.type === 'Fallback' ? this.theme.warning :
              group.type === 'URLTest' ? this.theme.primary : group.type === 'LoadBalance' ? this.theme.purple : this.theme.success });
        }.width(38).height(42);
        Column({ space: 8 }) {
          Text(this.groupTitle(group.name)).fontSize(this.theme.font(18)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Row({ space: 9 }) {
            this.typeChip(group.type);
            if (this.isBalancedGroup(group)) {
              Text(group.checking ? '检查中' : this.balancePolicyText(group)).fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
            } else if (group.type === 'URLTest' || group.type === 'Fallback') {
              Text(group.checking ? '检查中' : (group.manual ?? '').length > 0 ? '手动固定' : '自动')
                .fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
            }
            Text(this.isBalancedGroup(group) ? (group.lastSelected ? `最近 ${group.lastSelected}` : '按请求分配节点') :
              group.now || (group.type === 'URLTest' || group.type === 'Fallback' ? '暂无可用节点' : '尚未选择')).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted)
              .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis }).layoutWeight(1);
          }.width('100%');
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        Image($r('app.media.verge_chevron')).width(21).height(21)
          .colorFilter(this.iconColor(this.theme.text))
          .rotate({ angle: this.collapsedGroups.indexOf(group.name) >= 0 && this.proxyQuery.length === 0 ? 0 : 180 });
      }
      .width('100%').height(78).padding({ left: 20, right: 22 })
      .backgroundColor(this.hoveredProxyGroup === group.name ? this.theme.surfaceHover : Color.Transparent)
      .onHover((hovered: boolean) => this.hoveredProxyGroup = hovered ? group.name : '')
      .bindContextMenu(this.groupContextMenu(group), ResponseType.RightClick)
      .onClick(() => this.toggleGroup(group.name));
      if (this.collapsedGroups.indexOf(group.name) < 0 || this.proxyQuery.length > 0) {
        Divider().color(this.theme.divider);
        GridRow({ columns: this.nodeColumns(), gutter: 10 }) {
          ForEach(this.visibleProxies(group), (name: string) => {
            GridCol() {
              this.proxyNodeCard(group, name);
            }
          }, (name: string) => `${group.name}-${name}`);
        }.width('100%').padding({ left: 18, right: 18, top: 14, bottom: 18 });
        if (group.proxies.length === 0) {
          Text('此代理组暂无候选节点').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).padding(20);
        }
      }
    }
    .width('100%').borderRadius(this.theme.radius(8)).clip(true).backgroundColor(this.theme.surface)
    .onAreaChange((_old: Area, area: Area) => {
      this.groupPositions[group.name] = Number(area.globalPosition.y) - this.contentTop +
        this.contentScroller.currentOffset().yOffset;
    });
  }

  @Builder
  private groupNavigator() {
    Scroll() {
      Column({ space: 2 }) {
        ForEach(this.visibleGroups(), (group: ClashProxyGroup) => {
          Button({ type: ButtonType.Normal }) {
            if (this.groupIconSource(group)) {
              ProxyGroupIcon({ source: this.groupIconSource(group), revision: this.groupIconRevision, iconSize: 16, fallback: this.groupIcon(group.type) });
            } else {
              Text(this.groupInitial(group.name)).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily)
                .fontWeight(this.focusedProxyGroup === group.name ? FontWeight.Bold : FontWeight.Regular)
                .fontColor(this.focusedProxyGroup === group.name ? this.theme.primary : this.theme.textMuted);
            }
          }
          .width(24).height(24).borderRadius(this.theme.radius(5))
          .backgroundColor(this.focusedProxyGroup === group.name || this.hoveredProxyGroup === group.name ?
            this.theme.primaryHover : Color.Transparent)
          .accessibilityText(`跳转到 ${group.name}${this.focusedProxyGroup === group.name ? '，当前位置' : ''}`)
          .onHover((hovered: boolean) => this.hoveredProxyGroup = hovered ? group.name : '')
          .onClick(() => this.locateGroup(group.name));
        }, (group: ClashProxyGroup) => group.name);
      }.padding({ top: 12, bottom: 12 });
    }
    .width(28).height('100%').scrollBar(BarState.Off)
    .align(Alignment.Top);
  }

  @Builder
  private proxyNodeCard(group: ClashProxyGroup, name: string) {
    Button({ type: ButtonType.Normal }) {
      Row({ space: 8 }) {
        Rect().width(3).height(27).radius(2).fill(name === group.now ? this.theme.primary : this.theme.border);
        Column({ space: 7 }) {
          Text(name).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(name === group.now ? this.theme.primary : this.theme.text)
            .fontWeight(name === group.now ? FontWeight.Medium : FontWeight.Regular)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis }).width('100%');
          Text(this.nodeProtocolText(name))
            .fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(name === group.now ? this.theme.primary : this.theme.textMuted);
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        Column({ space: 6 }) {
          Text(this.nodeDelayText(name)).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily)
            .fontColor(this.testingNodes.indexOf(name) >= 0 ? this.theme.textMuted : this.nodeDelay(name) === 0 ? this.theme.danger : this.nodeDelay(name) > 0 ? this.theme.success : this.theme.textMuted);
          if (name === group.now) {
            this.icon($r('app.media.verge_check'), 15, 'primary');
          }
        }.alignItems(HorizontalAlign.End);
      }.width('100%');
    }
    .height(68).width('100%').padding({ left: 10, right: 12 }).borderRadius(this.theme.radius(6))
    .backgroundColor(name === group.now ? this.theme.primarySoft :
      this.hoveredProxyNode === `${group.name}/${name}` ? this.theme.primaryHover : this.theme.field)
    .border({ width: 1, color: name === group.now ? this.theme.primaryBorder : this.theme.divider })
    .accessibilityText(`${name}${this.isBalancedGroup(group) ? '，负载均衡候选，点击测试延迟' : name === group.now ? '，当前选择' : ''}`)
    .enabled(this.pendingProxy.length === 0)
    .onHover((hovered: boolean) => this.hoveredProxyNode = hovered ? `${group.name}/${name}` : '')
    .bindContextMenu(this.nodeContextMenu(group, name), ResponseType.RightClick)
    .onClick(() => this.chooseProxy(group.name, name));
  }

  @Builder
  private rulesPage() {
    if (this.showRuleProviders) { this.ruleProvidersPage(); }
    else { this.ruleRoutingPage(); }
  }

  @Builder
  private ruleProvidersMenu() {
    Menu() {
      MenuItem({ content: '更新全部规则集合', startIcon: $r('app.media.verge_refresh') })
        .enabled(this.ruleProviders.some((provider: ClashRuleProvider) => this.canUpdateRuleProvider(provider)))
        .onClick(() => this.updateAllRuleProviders());
      MenuItem({ content: '编辑当前配置', startIcon: $r('app.media.verge_file') }).enabled(this.activeProfileId.length > 0 && !this.temporaryConfig)
        .onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private ruleProviderMenu(provider: ClashRuleProvider) {
    Menu() {
      MenuItem({ content: '查看规则', startIcon: $r('app.media.verge_rules') }).enabled(provider.ready)
        .onClick(() => this.ruleProviderAction(provider, 'view'));
      MenuItem({ content: '更新规则集合', startIcon: $r('app.media.verge_refresh') }).enabled(this.canUpdateRuleProvider(provider))
        .onClick(() => this.ruleProviderAction(provider, 'update'));
      if (this.internalCore && provider.vehicleType.toLowerCase() === 'file') {
        MenuItem({ content: '导入规则文件', startIcon: $r('app.media.verge_import') })
          .onClick(() => this.ruleProviderAction(provider, 'import'));
        MenuItem({ content: '恢复配置中的文件路径', startIcon: $r('app.media.verge_file') })
          .onClick(() => this.ruleProviderAction(provider, 'reset'));
      }
      MenuItem({ content: '复制集合名称' }).onClick(() => this.copyText(provider.name, '规则集合名称'));
      MenuItem({ content: '复制当前展示的规则' }).enabled(provider.ready).onClick(() => this.ruleProviderAction(provider, 'copy'));
      MenuItem({ content: '编辑当前配置', startIcon: $r('app.media.verge_file') }).enabled(this.activeProfileId.length > 0 && !this.temporaryConfig)
        .onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private ruleProviderCard(provider: ClashRuleProvider) {
    Column({ space: 12 }) {
      Row({ space: 12 }) {
        this.icon($r('app.media.verge_rules'), 26, 'primary');
        Column({ space: 6 }) {
          Text(provider.name).fontSize(this.theme.font(16)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Row({ space: 7 }) {
            this.typeChip(`${provider.behavior.toUpperCase()} · ${provider.format.toUpperCase()}`);
            Text(`${provider.ruleCount} 条规则`).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
          }
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        if (provider.updating || this.requestingRuleProviders.indexOf(this.ruleProviderKey(provider)) >= 0) {
          LoadingProgress().width(20).height(20).color(this.theme.primary);
        } else {
          Text(provider.ready ? '已就绪' : '未就绪').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(provider.ready ? this.theme.success : this.theme.warning);
        }
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_more'), 20, 'textSecondary');
        }.width(30).height(32).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
          .accessibilityText(`${provider.name} 的规则集合操作`).bindMenu(this.ruleProviderMenu(provider));
      }.width('100%');
      if (provider.error.length > 0) {
        Text(`${provider.error}${provider.ready ? ' · 正在使用已保留的规则' : ''}`)
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(provider.ready ? this.theme.warning : this.theme.danger).width('100%')
          .maxLines(3).textOverflow({ overflow: TextOverflow.Ellipsis });
      }
      Row({ space: 8 }) {
        Text(provider.vehicleType.toLowerCase() === 'inline' ? '规则来自当前配置' :
          `${provider.vehicleType} · ${this.providerTime(provider.updatedAt)}`)
          .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
        if (this.internalCore && provider.vehicleType.toLowerCase() === 'file' && !provider.ready) {
          this.outlineButton('导入规则文件', $r('app.media.verge_import'), () => this.ruleProviderAction(provider, 'import'));
        } else {
          Button('查看规则', { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.primary)
            .backgroundColor(Color.Transparent).enabled(provider.ready).onClick(() => this.ruleProviderAction(provider, 'view'));
        }
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_refresh'), 18, 'primary');
        }.width(30).height(30).borderRadius(this.theme.radius(5)).backgroundColor(Color.Transparent)
          .enabled(this.canUpdateRuleProvider(provider)).accessibilityText(`更新规则集合 ${provider.name}`)
          .onClick(() => this.ruleProviderAction(provider, 'update'));
      }.width('100%');
    }.width('100%').padding(18).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface)
      .bindContextMenu(this.ruleProviderMenu(provider), ResponseType.RightClick);
  }

  @Builder
  private ruleProvidersPage() {
    Column({ space: 12 }) {
      this.searchField(this.ruleProviderQuery, '搜索规则集合、行为或格式', (value: string) => this.ruleProviderQuery = value);
      if (this.visibleRuleProviders().length > 0) {
        ForEach(this.visibleRuleProviders(), (provider: ClashRuleProvider) => {
          this.ruleProviderCard(provider);
        }, (provider: ClashRuleProvider) => JSON.stringify(provider));
      } else {
        Column() {
          this.emptyState(this.ruleProviderQuery.length > 0 ? '没有匹配的规则集合' : '暂无规则集合',
            '配置中的 rule-providers 会显示在这里，支持 YAML / TEXT / MRS', $r('app.media.verge_rules'));
        }.width('100%').borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface);
      }
    }.width('100%').bindContextMenu(this.ruleProvidersMenu(), ResponseType.RightClick);
  }

  @Builder
  private ruleRoutingPage() {
    Column({ space: 16 }) {
      GridRow({ columns: { sm: 1, md: 3, lg: 3 }, gutter: 16 }) {
        GridCol() {
          this.summaryCard({ title: '规则总数', value: this.coreConnected ? `${this.ruleCount}` : '—', detail: '当前配置',
            source: $r('app.media.verge_rules'), color: 'primary' });
        }
        GridCol() {
          this.summaryCard({ title: '运行模式', value: this.modeName(), detail: '规则 / 全局 / 直连',
            source: $r('app.media.verge_shield'), color: 'success' });
        }
        GridCol() {
          this.summaryCard({ title: '代理组', value: `${this.proxyGroups.length}`, detail: '分流策略',
            source: $r('app.media.verge_proxies'), color: 'warning' });
        }
      }
      this.searchField(this.ruleQuery, '搜索规则、匹配内容或策略', (value: string) => this.ruleQuery = value);
      Column({ space: 0 }) {
        Row() {
          Text('规则类型').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('23%');
          Text('匹配内容').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
          Text('代理策略').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('28%');
        }.width('100%').height(46).padding({ left: 20, right: 20 }).backgroundColor(this.theme.surfaceHover);
        Divider().color(this.theme.divider);
        if (this.visibleRules().length > 0) {
          ForEach(this.visibleRules(), (rule: ClashRule) => {
            Row({ space: 10 }) {
              Text(rule.type.toUpperCase()).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('23%');
              Text(rule.payload || '*').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1)
                .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
              Text(rule.proxy).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('28%')
                .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
            }.width('100%').height(43).padding({ left: 20, right: 20 })
              .border({ width: { bottom: 1 }, color: this.theme.divider })
              .bindContextMenu(this.ruleContextMenu(rule), ResponseType.RightClick);
          }, (rule: ClashRule, index: number) => `${index}-${rule.type}-${rule.payload}-${rule.proxy}-${rule.noResolve}`);
        } else {
          this.emptyState(this.ruleQuery.length > 0 ? '没有匹配的规则' : '暂无规则',
            '导入配置后显示实际分流规则', $r('app.media.verge_rules'));
        }
      }.width('100%').borderRadius(this.theme.radius(8)).clip(true).border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
    }.width('100%');
  }

  @Builder
  private connectionsPage() {
    Column({ space: 16 }) {
      if (this.windowWidth < 780) {
        this.searchField(this.connectionQuery, '搜索目标地址、规则或代理链', (value: string) => this.connectionQuery = value);
        this.connectionActions();
      } else {
        Row({ space: 24 }) {
          Row() {
            this.searchField(this.connectionQuery, '搜索目标地址、规则或代理链', (value: string) => this.connectionQuery = value);
          }.layoutWeight(1);
          this.connectionActions();
        }.width('100%');
      }
      Column({ space: 0 }) {
        Scroll() {
          this.connectionsTable();
        }.width('100%').height(48 + this.visibleConnections().length * 54)
          .scrollable(ScrollDirection.Horizontal).scrollBar(BarState.Auto);
        if (this.visibleConnections().length === 0) {
          this.emptyState(this.connectionQuery.length > 0 ? '没有匹配的连接' : '暂无活动连接',
            this.coreConnected ? '经过代理的连接会显示在这里' : '连接内核后查看请求与流量', $r('app.media.verge_connections'));
        }
      }.width('100%').borderRadius(this.theme.cardRadius).clip(true)
        .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
    }.width('100%');
  }

  @Builder
  private connectionActions() {
    Row({ space: 16 }) {
      Text(`${this.activeConnections} 个活动连接`).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
      Blank();
      Button('断开全部', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger)
        .backgroundColor(this.theme.dangerSoft).borderRadius(this.theme.radius(5)).enabled(this.coreConnected && this.activeConnections > 0)
        .onClick(() => this.closeAllConnections());
    }.width(this.windowWidth < 780 ? '100%' : 232);
  }

  @Builder
  private connectionsTable() {
    Column({ space: 0 }) {
      Row() {
        Text('协议').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width(54);
        Text('目标地址').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
        Text('代理链 / 规则').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('32%');
        Text('上传').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width(90);
        Text('下载').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width(90);
        Blank().width(30);
      }.width('100%').height(47).padding({ left: 20, right: 20 }).backgroundColor(this.theme.surfaceHover);
      Divider().color(this.theme.divider);
      ForEach(this.visibleConnections(), (item: ClashConnection) => {
        Row() {
          Text(item.network.toUpperCase() || '—').fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontColor(item.network === 'udp' ? this.theme.purple : this.theme.textSecondary).width(54);
          Text(`${item.host}${item.port.length > 0 ? `:${item.port}` : ''}`).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Text(this.connectionRoute(item)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('32%')
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Text(this.formatBytes(item.upload)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning).width(90);
          Text(this.formatBytes(item.download)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).width(90);
          Button('•••', { type: ButtonType.Normal }).width(30).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted)
            .backgroundColor(Color.Transparent).borderRadius(this.theme.radius(4)).accessibilityText('连接操作')
            .bindMenu(this.connectionContextMenu(item));
        }.width('100%').height(54).padding({ left: 20, right: 20 })
          .border({ width: { bottom: 1 }, color: this.theme.divider })
          .bindContextMenu(this.connectionContextMenu(item), ResponseType.RightClick)
          .onClick(() => this.connectionDetails(item));
      }, (item: ClashConnection) => JSON.stringify(item));
    }.width(Math.max(820, this.windowWidth - 26));
  }

  @Builder
  private profilesPage() {
    Column({ space: 16 }) {
      Flex({ direction: this.windowWidth < 1000 ? FlexDirection.Column : FlexDirection.Row }) {
        TextInput({ text: this.subscriptionUrl, placeholder: '粘贴 Clash 订阅链接' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
          .height(40).layoutWeight(this.windowWidth < 1000 ? 0 : 1).width('100%')
          .backgroundColor(this.theme.surface).borderRadius(this.theme.radius(6))
          .border({ width: 1, color: this.theme.border }).onChange((value: string) => this.subscriptionUrl = value)
          .margin(this.windowWidth < 1000 ? { bottom: 12 } : { right: 12 });
        Flex({ wrap: FlexWrap.Wrap }) {
          Row() { this.primaryButton('添加订阅', $r('app.media.verge_import'), () => this.openProfileInfo()); }.height(40).margin({ right: 10 });
          Row() { this.outlineButton('剪贴板导入', $r('app.media.verge_file'), () => this.importClipboard()); }.height(40).margin({ right: 10 });
          Row() { this.outlineButton('节点链接', $r('app.media.verge_import'), () => this.openNodeImport()); }.height(40).margin({ right: 10 });
          Row() { this.outlineButton('全局扩展', $r('app.media.verge_settings'), () => this.openMergeEditor(true)); }.height(40).margin({ right: 10 });
          Row() { this.outlineButton('全局脚本', $r('app.media.verge_file'), () => this.openMergeEditor(true, undefined, true)); }.height(40);
        }.width(this.windowWidth < 1000 ? '100%' : 560);
      }.width('100%');
      this.searchField(this.profileQuery, '搜索配置文件', (value: string) => this.profileQuery = value);
      if (this.visibleProfiles().length > 0) {
        GridRow({ columns: { sm: 1, md: 2, lg: 3 }, gutter: 16 }) {
          ForEach(this.visibleProfiles(), (profile: ClashProfile) => {
            GridCol() {
              this.profileCard(profile);
            }
          }, (profile: ClashProfile) => `${profile.id}:${this.profileRevision}`);
        }.width('100%');
      } else {
        Column({ space: 0 }) {
          this.emptyState(this.profileQuery.length > 0 ? '没有匹配的配置' : '还没有配置文件',
            '导入本地 YAML、YML 或 JSON 配置开始使用', $r('app.media.verge_profiles'));
          if (this.profiles.length === 0) {
            this.primaryButton('导入配置', $r('app.media.verge_import'), () => this.importProfile());
          }
        }.width('100%').padding({ bottom: 32 }).borderRadius(this.theme.radius(8))
          .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
      }
    }.width('100%')
      .bindContextMenu(this.profileAreaMenu(), ResponseType.RightClick);
  }

  @Builder
  private profileCard(profile: ClashProfile) {
    Column({ space: 15 }) {
      Row({ space: 11 }) {
        Stack() {
          this.icon($r('app.media.verge_file'), 23, this.profileIsActive(profile.id) ? 'primary' : 'textSecondary');
        }.width(42).height(44).borderRadius(this.theme.radius(7)).backgroundColor(this.profileIsActive(profile.id) ? this.theme.primarySoft : this.theme.field);
        Column({ space: 6 }) {
          Text(profile.name).fontSize(this.theme.font(15)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text)
            .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
          Text(`${profile.pinned ? '置顶 · ' : ''}${profile.sourceUrl.length > 0 ? '远程订阅' : '本地文件'} · ${profile.format}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
        }.alignItems(HorizontalAlign.Start).layoutWeight(1);
        if (this.profileIsActive(profile.id)) {
          this.icon($r('app.media.verge_check'), 19, 'primary');
        }
      }.width('100%');
      Row() {
        Text(this.formatBytes(profile.size)).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
        Text(`更新于 ${profile.updatedAt}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.width('100%');
      if (profile.sourceUrl.length > 0 && subscriptionTraffic(profile.subscription)) {
        Text(subscriptionTraffic(profile.subscription)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      }
      if (profile.sourceUrl.length > 0 && subscriptionExpiry(profile.subscription)) {
        Text(subscriptionExpiry(profile.subscription)).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily)
          .fontColor((profile.subscription?.info?.usage?.expire ?? 0) * 1000 <= Date.now() ? this.theme.warning : this.theme.textMuted).width('100%');
      }
      Divider().color(this.theme.divider);
      Row({ space: 10 }) {
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_more'), 18, 'textMuted');
        }.width(30).height(30)
          .backgroundColor(Color.Transparent).borderRadius(this.theme.radius(4)).accessibilityText('配置操作')
          .bindMenu(this.profileContextMenu(profile));
        Button(this.profileIsActive(profile.id) ? '当前使用' : '使用配置', { type: ButtonType.Normal })
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).height(30)
          .padding({ left: 9, right: 9 }).borderRadius(this.theme.radius(4))
          .backgroundColor(this.profileIsActive(profile.id) ? this.theme.primarySoft : this.theme.field)
          .onClick(() => this.activateProfile(profile));
        Blank();
        Button({ type: ButtonType.Normal }) {
          this.icon($r('app.media.verge_trash'), 17, 'textMuted');
        }.width(30).height(30).borderRadius(this.theme.radius(4)).backgroundColor(Color.Transparent)
          .accessibilityText(`删除配置 ${profile.name}`)
          .enabled(profile.id !== this.activeProfileId)
          .onClick(() => this.confirmRemoveProfile(profile));
      }.width('100%');
    }
    .width('100%').padding(18).borderRadius(this.theme.cardRadius)
    .backgroundColor(this.hoveredProfile === profile.id ? this.theme.surfaceHover : this.theme.surface)
    .border({ width: this.profileIsActive(profile.id) ? 1.5 : 1,
      color: this.profileIsActive(profile.id) ? this.theme.primaryBorder : this.theme.border })
    .onHover((hovered: boolean) => this.hoveredProfile = hovered ? profile.id : '')
    .bindContextMenu(this.profileContextMenu(profile), ResponseType.RightClick);
  }

  @Builder
  private logsPage() {
    Column({ space: 16 }) {
      Row({ space: 5 }) {
        ForEach(['ALL', 'DEBUG', 'INFO', 'WARN', 'ERROR'], (level: string) => {
          Button(level === 'ALL' ? '全部' : level, { type: ButtonType.Normal })
            .height(30).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).padding({ left: 12, right: 12 })
            .fontColor(this.logFilter === level ? this.theme.primary : this.theme.textMuted)
            .backgroundColor(this.logFilter === level ? this.theme.primarySoft : Color.Transparent)
            .onClick(() => this.logFilter = level);
        }, (level: string) => level);
        Blank();
        Text(`${this.visibleLogs().length} 条记录`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.width('100%');
      Column({ space: 0 }) {
        if (this.visibleLogs().length > 0) {
          ForEach(this.visibleLogs(), (entry: UiLogEntry) => {
            Row({ space: 14 }) {
              Text(entry.time).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontFamily('monospace').fontColor(this.theme.textMuted).width(67);
              Text(entry.level).fontSize(this.theme.font(10)).fontFamily(this.theme.fontFamily).fontFamily('monospace').width(42)
                .fontColor(entry.level === 'ERROR' ? this.theme.danger : entry.level === 'WARN' ? this.theme.warning : this.theme.success);
              Text(entry.message).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontFamily('monospace').fontColor(this.theme.textSecondary)
                .layoutWeight(1).copyOption(CopyOptions.LocalDevice);
            }.width('100%').alignItems(VerticalAlign.Top)
              .padding({ left: 18, right: 18, top: 13, bottom: 13 })
              .border({ width: { bottom: 1 }, color: this.theme.divider })
              .bindContextMenu(this.logContextMenu(entry), ResponseType.RightClick);
          }, (entry: UiLogEntry) => `${entry.id}`);
        } else {
          this.emptyState('暂无日志', '连接状态和操作记录会显示在这里', $r('app.media.verge_logs'));
        }
      }.width('100%').constraintSize({ minHeight: 260 }).borderRadius(this.theme.radius(8)).clip(true)
        .border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
    }.width('100%');
  }

  @Builder
  private dnsResultMenu() {
    Menu() {
      MenuItem({ content: '复制查询结果' }).enabled(this.dnsAnswer !== undefined)
        .onClick(() => this.copyText(this.dnsResultText(), 'DNS 查询结果'));
      MenuItem({ content: '复制域名' }).onClick(() => this.copyText(this.dnsName.trim(), '域名'));
      MenuItem({ content: '清空 DNS 缓存', startIcon: $r('app.media.verge_trash') })
        .enabled(this.internalCore && this.coreConnected && !this.dnsBusy).onClick(() => this.clearDnsCache());
      MenuItem({ content: '编辑当前 DNS 配置', startIcon: $r('app.media.verge_file') })
        .enabled(this.activeProfileId.length > 0 && !this.temporaryConfig).onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private dnsRecordMenu(record: ClashDnsRecord) {
    Menu() {
      MenuItem({ content: '复制记录' }).onClick(() => this.copyText(`${record.name} ${record.TTL} IN ${this.dnsTypeName(record.type)} ${record.data}`, 'DNS 记录'));
      MenuItem({ content: '复制记录值' }).onClick(() => this.copyText(record.data, '记录值'));
      MenuItem({ content: '查询此名称' }).onClick(() => { this.dnsName = record.name; this.runDnsQuery(); });
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private testsPage() {
    Column({ space: 16 }) {
      Column({ space: 14 }) {
        this.cardTitle('系统代理联网检测', $r('app.media.verge_connections'));
        Text('检查当前系统网络能否访问网站，分别显示 HTTP 错误状态和连接失败。节点测速成功后，可在这里确认系统代理的实际访问结果。')
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
        Text(this.systemProxyDescription()).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
        Row({ space: 12 }) {
          this.outlineButton('系统联网检测', $r('app.media.verge_test'), () => this.openSystemNetworkCheck());
          this.outlineButton('系统代理设置', $r('app.media.verge_settings'), () => this.openSystemNetworkSettings());
        }.width('100%');
      }.width('100%').padding(20).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface)
        .border({ width: 1, color: this.theme.border }).bindContextMenu(this.systemNetworkMenu(), ResponseType.RightClick);
      Column({ space: 16 }) {
        Row() {
          this.cardTitle('DNS 查询', $r('app.media.verge_connections'));
        }.width('100%');
        Text(this.internalCore && this.dnsServer.trim().length > 0 ? '指定服务器查询用于诊断，不会改写当前配置。' :
          '使用当前配置的解析服务器和域名策略，结果同时用于内核连接与 IP 规则。')
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
        Flex({ direction: this.windowWidth < 640 ? FlexDirection.Column : FlexDirection.Row }) {
          TextInput({ text: this.dnsName, placeholder: '输入域名（支持 Punycode）' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
            .height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5))
            .layoutWeight(this.windowWidth < 640 ? 0 : 1).width('100%').enabled(!this.dnsBusy)
            .onChange((value: string) => this.dnsName = value).onSubmit(() => this.runDnsQuery())
            .margin(this.windowWidth < 640 ? { bottom: 12 } : { right: 12 });
          Row({ space: 10 }) {
            Select([{ value: 'A' }, { value: 'AAAA' }, { value: 'CNAME' }, { value: 'NS' }, { value: 'MX' }, { value: 'TXT' }, { value: 'SOA' }, { value: 'HTTPS' }])
              .value(this.dnsType).width(108).height(40).font({ size: this.theme.font(13), family: this.theme.fontFamily }).backgroundColor(this.theme.field)
              .enabled(!this.dnsBusy).onSelect((_index: number, value: string) => this.dnsType = value);
            Button(this.dnsBusy ? '查询中…' : '查询 DNS', { type: ButtonType.Normal })
              .height(40).padding({ left: 18, right: 18 }).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary)
              .borderRadius(this.theme.radius(5)).backgroundColor(this.theme.primary).enabled(this.coreConnected && !this.dnsBusy)
              .onClick(() => this.runDnsQuery());
          }.height(40);
        }.width('100%');
        if(this.internalCore) {
          TextInput({ text: this.dnsServer, placeholder: '指定解析服务器（可选，例如 tls://1.1.1.1；留空使用当前配置）' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
            .height(38).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).width('100%')
            .enabled(!this.dnsBusy).onChange((value: string) => this.dnsServer = value).onSubmit(() => this.runDnsQuery());
        }
        if (this.dnsStatus !== undefined) {
          Text(`${this.dnsStatus.enabled ? '自定义 DNS' : '系统 DNS'} · ${this.dnsStatus.nameservers} 个解析服务器 · ${this.dnsStatus.policies} 条策略 · ${this.dnsStatus.hosts} 项 hosts · ${this.dnsStatus.cacheEntries} 项缓存`)
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          Text(this.dnsStatus.listening ? `DNS 监听 ${this.dnsStatus.listen ?? ''} · UDP / TCP · ${this.dnsStatus.listenerQueries ?? 0} 次查询` +
            ((this.dnsStatus.listenerRejected ?? 0) > 0 ? ` · ${this.dnsStatus.listenerRejected} 次拒绝` : '') :
            this.dnsStatus.listen ? `DNS 监听未启用 · ${this.dnsStatus.listen}` : '未配置独立 DNS 监听')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.dnsStatus.listening ? this.theme.success : this.theme.textMuted).width('100%');
          if (this.dnsStatus.warnings.length > 0) {
            Text(this.dnsStatus.warnings.join('\n')).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning).width('100%');
          }
        }
        if (this.dnsError.length > 0) {
          Text(this.dnsError).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').copyOption(CopyOptions.LocalDevice);
        }
        if (this.dnsAnswer !== undefined) {
          Divider().color(this.theme.divider);
          Row({ space: 10 }) {
            Text(this.dnsAnswer.Status === 0 ? 'NOERROR' : this.dnsAnswer.Status === 3 ? 'NXDOMAIN' : `RCODE ${this.dnsAnswer.Status}`)
              .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.dnsAnswer.Status === 0 ? this.theme.success : this.theme.warning);
            Text(this.dnsAnswer.server ?? '当前内核 DNS').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1)
              .maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
            Text(this.dnsAnswer.cached ? '命中缓存' : this.dnsAnswer.delay !== undefined ? `${this.dnsAnswer.delay} ms` : '')
              .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary);
            Button({ type: ButtonType.Normal }) {
              this.icon($r('app.media.verge_more'), 20);
            }.width(30).height(30).backgroundColor(Color.Transparent).borderRadius(this.theme.radius(5))
              .accessibilityText('DNS 查询结果操作').bindMenu(this.dnsResultMenu());
          }.width('100%');
          ForEach(this.dnsAnswer.Answer ?? [], (record: ClashDnsRecord) => {
            Column({ space: 8 }) {
              Row({ space: 10 }) {
                this.typeChip(this.dnsTypeName(record.type));
                Text(record.name).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).layoutWeight(1)
                  .maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
                Text(`TTL ${record.TTL}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
              }.width('100%');
              Text(record.data).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontFamily('monospace').fontColor(this.theme.text).width('100%')
                .copyOption(CopyOptions.LocalDevice);
            }.width('100%').padding(14).borderRadius(this.theme.radius(6)).backgroundColor(this.theme.field)
              .bindContextMenu(this.dnsRecordMenu(record), ResponseType.RightClick);
          }, (record: ClashDnsRecord) => JSON.stringify(record));
          if ((this.dnsAnswer.Answer ?? []).length === 0) {
            Text(this.dnsAnswer.Status === 3 ? '该域名不存在，DNS 返回 NXDOMAIN。' : '查询成功，当前类型没有返回记录。')
              .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          }
        }
      }.width('100%').padding(20).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface)
        .border({ width: 1, color: this.theme.border }).bindContextMenu(this.dnsResultMenu(), ResponseType.RightClick);
      Column({ space: 16 }) {
        this.cardTitle('代理连通性', $r('app.media.verge_test'));
        Text(this.selectedProxy || '尚未选择代理节点').fontSize(this.theme.font(16)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text)
          .maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis }).width('100%');
        Text(this.testUrl).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
        Row({ space: 12 }) {
          Button(this.testingNodes.indexOf(this.selectedProxy) >= 0 ? '检测中…' : '检测当前节点', { type: ButtonType.Normal })
            .height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary).padding({ left: 14, right: 14 }).borderRadius(this.theme.radius(5))
            .backgroundColor(this.theme.primary).enabled(this.coreConnected && this.selectedProxy.length > 0 && this.testingNodes.indexOf(this.selectedProxy) < 0)
            .onClick(() => this.testNode(this.selectedProxy));
          this.outlineButton('连续检测', $r('app.media.verge_chart'), () => this.openProbeSeries(), this.coreConnected && this.selectedProxy.length > 0 && this.selectedProxy !== 'REJECT');
          if (this.internalCore) this.outlineButton('内核自检', $r('app.media.verge_shield'), () => this.diagnoseCore());
          Blank();
          Text(this.selectedProxy.length > 0 ? this.nodeDelayText(this.selectedProxy) : '—')
            .fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.nodeDelay(this.selectedProxy) > 0 ? this.theme.success : this.theme.textMuted);
        }.width('100%');
        if ((this.delayErrors[this.selectedProxy] ?? '').length > 0) {
          Text(this.delayErrors[this.selectedProxy]).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
        }
      }.width('100%').padding(20).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface).border({ width: 1, color: this.theme.border });
    }.width('100%');
  }

  @Builder
  private systemNetworkMenu() {
    Menu() {
      MenuItem({ content: '系统联网检测', startIcon: $r('app.media.verge_test') }).onClick(() => this.openSystemNetworkCheck());
      MenuItem({ content: '打开系统代理设置', startIcon: $r('app.media.verge_settings') }).onClick(() => this.openSystemNetworkSettings());
      MenuItem({ content: '刷新系统代理状态', startIcon: $r('app.media.verge_refresh') }).onClick(() => this.refreshSystemProxy());
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE);
  }

  @Builder
  private geoResourceMenu(resource: ClashGeoResource) {
    Menu() {
      MenuItem({ content: '更新数据库', startIcon: $r('app.media.verge_refresh') })
        .enabled(!resource.updating && this.geoBusy.indexOf(resource.kind) < 0).onClick(() => this.geoAction(resource, 'update'));
      MenuItem({ content: '导入数据库文件', startIcon: $r('app.media.verge_import') })
        .enabled(!resource.updating && this.geoBusy.indexOf(resource.kind) < 0).onClick(() => this.geoAction(resource, 'import'));
      MenuItem({ content: '复制下载地址' }).onClick(() => this.copyText(resource.sourceUrl, '数据库下载地址'));
      MenuItem({ content: '编辑当前配置', startIcon: $r('app.media.verge_file') })
        .onClick(() => this.openEditor(this.profiles.find((profile: ClashProfile) => profile.id === this.activeProfileId)));
      MenuItem({ content: '删除本地数据', startIcon: $r('app.media.verge_trash') })
        .enabled(resource.ready && !resource.updating).onClick(() => this.confirmClearGeo(resource));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private geoSettings() {
    Column({ space: 0 }) {
      Row({ space: 9 }) {
        this.icon($r('app.media.verge_connections'), 18, 'textSecondary');
        Text('地理数据库').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).layoutWeight(1);
        this.iconButton($r('app.media.verge_refresh'), '刷新数据库状态', () => this.refreshGeoStatus());
      }.width('100%').padding(20);
      if (this.geoStatus !== undefined) {
        Text(`GeoIP 使用 ${this.geoStatus.mode === 'dat' ? 'DAT' : 'MMDB'} · ${this.geoStatus.autoUpdate ? `每 ${this.geoStatus.interval} 小时自动更新` : '自动更新已关闭'}`)
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%').padding({ left: 20, right: 20, bottom: 16 });
        ForEach(this.geoStatus.resources, (resource: ClashGeoResource) => {
          Column({ space: 10 }) {
            Row({ space: 10 }) {
              Text(this.geoTitle(resource.kind)).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).layoutWeight(1);
              if (resource.required) this.typeChip('当前配置使用');
              Text(resource.updating ? '更新中…' : resource.ready ? '已加载' : '未下载')
                .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(resource.ready ? this.theme.success : this.theme.textMuted);
            }.width('100%');
            Row({ space: 10 }) {
              Column({ space: 5 }) {
                Text(resource.ready ? `${resource.imported ? '本地导入' : '下载缓存'} · ${this.formatBytes(resource.bytes)}${resource.categories > 0 ? ` · ${resource.categories} 个分类` : ''}` :
                  resource.required ? '首次使用时下载，也可导入本地文件' : '当前配置未引用，可按需下载')
                  .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
                if (resource.updatedAt.length > 0) Text(`更新于 ${resource.updatedAt}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
              }.layoutWeight(1).alignItems(HorizontalAlign.Start);
              Button(resource.updating ? '更新中…' : '更新', { type: ButtonType.Normal })
                .height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).padding({ left: 14, right: 14 }).borderRadius(this.theme.radius(5))
                .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
                .enabled(!resource.updating && this.geoBusy.indexOf(resource.kind) < 0).onClick(() => this.geoAction(resource, 'update'));
              Button('导入', { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).padding({ left: 14, right: 14 })
                .borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary).backgroundColor(this.theme.field)
                .enabled(!resource.updating && this.geoBusy.indexOf(resource.kind) < 0).onClick(() => this.geoAction(resource, 'import'));
              Button({ type: ButtonType.Normal }) { this.icon($r('app.media.verge_more'), 18); }
                .width(28).height(30).backgroundColor(Color.Transparent).accessibilityText(`${this.geoTitle(resource.kind)} 操作`)
                .bindMenu(this.geoResourceMenu(resource));
            }.width('100%');
            if (resource.error.length > 0) Text(resource.error).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').copyOption(CopyOptions.LocalDevice);
          }.width('100%').padding(20).border({ width: { top: 1 }, color: this.theme.divider })
            .bindContextMenu(this.geoResourceMenu(resource), ResponseType.RightClick);
        }, (resource: ClashGeoResource) => JSON.stringify(resource));
      } else {
        Text('正在读取数据库状态…').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%').padding(20);
      }
    }.width('100%').borderRadius(this.theme.radius(8)).clip(true).backgroundColor(this.theme.surface).border({ width: 1, color: this.theme.border });
  }

  @Builder
  private inboundSettingsMenu() {
    Menu() {
      MenuItem({ content: '配置局域网共享' }).enabled(this.coreConnected && !this.tunBusy && !this.tunEnabled)
        .onClick(() => this.openInboundSettings());
      MenuItem({ content: '复制本机代理地址' }).enabled(this.httpPort > 0)
        .onClick(() => this.copyText(`${this.proxyHost.indexOf(':') >= 0 ? `[${this.proxyHost}]` : this.proxyHost}:${this.httpPort}`, '本机代理地址'));
    }
  }

  @Builder
  private snifferMenu() {
    Menu() {
      MenuItem({ content: this.sniffing ? '关闭域名嗅探' : '开启域名嗅探' }).enabled(this.coreConnected && !this.tunBusy)
        .onClick(() => this.setSniffing(!this.sniffing));
      MenuItem({ content: '编辑嗅探配置' }).enabled(this.coreConnected && !this.tunBusy).onClick(() => this.openSnifferSettings());
      MenuItem({ content: '编辑全局扩展配置' }).onClick(() => this.openMergeEditor(true));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private proxyPortMenu(socks: boolean) {
    Menu() {
      MenuItem({ content: '修改代理端口', startIcon: $r('app.media.verge_settings') })
        .enabled(this.internalCore && this.coreConnected).onClick(() => this.openProxyPorts());
      MenuItem({ content: '复制端口' }).enabled((socks ? this.socksPort : this.httpPort) > 0)
        .onClick(() => this.copyText(`${socks ? this.socksPort : this.httpPort}`, '端口'));
      MenuItem({ content: '复制代理地址' }).enabled((socks ? this.socksPort : this.httpPort) > 0)
        .onClick(() => this.copyText(`${this.internalCore ? `${this.proxyHost.indexOf(':') >= 0 ? `[${this.proxyHost}]` : this.proxyHost}:` : ''}${socks ? this.socksPort : this.httpPort}`, '代理地址'));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }

  @Builder
  private proxyPortRow(socks: boolean) {
    Row({ space: 10 }) {
      Row() {
        this.settingRow({ title: socks ? 'SOCKS5 代理' : 'HTTP 代理', detail: this.internalCore ? '当前监听端口 · 点击修改' : '当前内核监听端口',
          value: !this.coreConnected ? '未连接' : (socks ? this.socksPort : this.httpPort) > 0 ?
            `${this.internalCore ? `${this.proxyHost.indexOf(':') >= 0 ? `[${this.proxyHost}]` : this.proxyHost}:` : ''}${socks ? this.socksPort : this.httpPort}` : '关闭' });
      }.layoutWeight(1).onClick(() => this.openProxyPorts());
      if (this.internalCore) {
        Button('修改', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .padding({ left: 14, right: 14 }).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
          .accessibilityText(`修改${socks ? 'SOCKS5' : 'HTTP'}代理端口`)
          .enabled(this.coreConnected && !this.tunEnabled && !this.tunBusy)
          .onClick(() => this.openProxyPorts());
      }
    }.width('100%').padding({ right: 16 })
      .backgroundColor(this.hoveredAction === (socks ? 'SOCKS5 代理' : 'HTTP 代理') ? this.theme.surfaceHover : Color.Transparent)
      .onHover((hovered: boolean) => this.hoveredAction = hovered ? (socks ? 'SOCKS5 代理' : 'HTTP 代理') : '')
      .accessibilityText(`${socks ? 'SOCKS5 代理' : 'HTTP 代理'}，${socks ? this.socksPort : this.httpPort}，点击修改`)
      .bindContextMenu(this.proxyPortMenu(socks), ResponseType.RightClick);
  }

  @Builder
  private appearanceModeButton(label: string, mode: string) {
    Button(label, { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
      .fontColor(this.appearanceMode === mode ? this.theme.onPrimary : this.theme.textSecondary)
      .backgroundColor(this.appearanceMode === mode ? this.theme.primary : this.theme.field)
      .padding({ left: 16, right: 16 }).accessibilityText(`${label}外观${this.appearanceMode === mode ? '，当前选中' : ''}`)
      .onClick(() => this.setAppearance(mode, this.appearanceController?.settings.accent ?? DEFAULT_ACCENT));
  }

  private setAppearance(mode: string, accent: string, styles?: NativeStyles | null): void {
    try {
      if (!this.appearanceController) throw new Error('外观设置暂不可用，请重新打开应用');
      this.appearanceController.save(mode, accent, styles);
      this.appearanceMode = this.appearanceController.settings.mode;
      this.accentInput = this.appearanceController.settings.accent;
      this.appearanceError = '';
    } catch (error) { this.appearanceError = (error as Error).message || '外观未能保存，原设置已保留'; }
  }

  private openNativeStyles(): void {
    const appearance: AppearanceController | undefined = this.appearanceController;
    if (!appearance) { this.appearanceError = '外观设置暂不可用，请重新打开应用'; return; }
    try {
      const expected = appearance.savedSettings();
      this.dialogController?.close();
      this.dialogController = new CustomDialogController({ builder: NativeStyleDialog({ initialStyles: appearance.settings.styles, accent: appearance.settings.accent,
        onSave: (value: NativeStyles): void => {
          if (!this.pageActive || !sameAppearance(expected, appearance.savedSettings())) throw new Error('外观设置已变化，请重新打开样式编辑器');
          appearance.save(appearance.settings.mode, appearance.settings.accent, value);
          this.appearanceMode = appearance.settings.mode; this.accentInput = appearance.settings.accent; this.appearanceError = ''; this.notice = '自定义样式已保存，重启后保留';
        }, onCopy: (text: string): Promise<void> => this.copyText(text, '自定义样式')
      }), autoCancel: false, customStyle: true });
      this.dialogController.open();
    } catch (error) { this.appearanceError = (error as Error).message || '无法打开样式编辑器'; }
  }

  @Builder
  private appearanceMenu() {
    Menu() {
      MenuItem({ content: '自定义样式' }).onClick(() => this.openNativeStyles());
      MenuItem({ content: '恢复默认样式' }).onClick(() => this.setAppearance(this.appearanceMode, this.appearanceController?.settings.accent ?? DEFAULT_ACCENT, null));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE);
  }

  @Builder
  private appearanceSettings() {
    Column({ space: 16 }) {
      Row({ space: 9 }) {
        this.icon($r('app.media.verge_settings'), 18, 'textSecondary');
        Text('外观').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).layoutWeight(1);
        Text(this.theme.dark ? '当前深色' : '当前浅色').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.width('100%');
      Row({ space: 10 }) {
        this.appearanceModeButton('跟随系统', 'system');
        this.appearanceModeButton('浅色', 'light');
        this.appearanceModeButton('深色', 'dark');
      }.width('100%');
      Text('主题色').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).width('100%');
      Flex({ wrap: FlexWrap.Wrap }) {
        ForEach(this.accentOptions, (color: string, index: number) => {
          Button({ type: ButtonType.Normal }) {
            Row({ space: 6 }) {
              Circle({ width: 14, height: 14 }).fill(color);
              Text(this.accentNames[index]).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
            }
          }.height(34).borderRadius(this.theme.radius(5)).padding({ left: 10, right: 10 }).margin({ right: 8, bottom: 6 })
            .backgroundColor(this.theme.field).border({ width: 1, color: this.accentInput.toUpperCase() === color ? this.theme.primary : this.theme.border })
            .accessibilityText(`主题色：${this.accentNames[index]}`).onClick(() => this.setAppearance(this.appearanceMode, color));
        });
      }.width('100%');
      Row({ space: 10 }) {
        TextInput({ text: this.accentInput, placeholder: '#RRGGBB' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38).maxLength(7)
          .accessibilityText('自定义主题色').fontColor(this.theme.text).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).layoutWeight(1)
          .onChange((value: string) => { this.accentInput = value; this.appearanceError = ''; });
        Button('应用', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).onClick(() => this.setAppearance(this.appearanceMode, this.accentInput));
        Button('恢复默认', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.setAppearance('system', DEFAULT_ACCENT, null));
      }.width('100%');
      Row({ space: 10 }) {
        Button('自定义样式', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.openNativeStyles());
        Text(`字号 ${Math.round(this.theme.fontScale * 100)}% · 圆角 ${this.theme.cardRadius} · 边距 ${this.theme.contentGap}`)
          .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
      }.width('100%');
      Text('外观会自动保存。为保证文字清晰，会根据浅色或深色适当调整主题色的明暗。')
        .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      if (this.appearanceError) Text(this.appearanceError).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
    }.width('100%').padding(20).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface).border({ width: 1, color: this.theme.border })
      .bindContextMenu(this.appearanceMenu(), ResponseType.RightClick);
  }

  @Builder
  private settingsPage() {
    Column({ space: 16 }) {
      this.appearanceSettings();
      Column({ space: 0 }) {
        Row({ space: 9 }) {
          this.icon($r('app.media.verge_server'), 18, 'textSecondary');
          Text('内核设置').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).layoutWeight(1);
          Text(!this.coreConnected ? '未连接' : this.backgroundCore ? '后台 VPN 内核' : this.internalCore ? '内置内核' : '外部内核').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
        }.width('100%').padding(20);
        Divider().color(this.theme.divider);
        Column({ space: 14 }) {
          Flex({ direction: this.windowWidth < 640 ? FlexDirection.Column : FlexDirection.Row }) {
            Column({ space: 5 }) {
              Text('控制器地址').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
              Text('External Controller').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.alignItems(HorizontalAlign.Start).width(this.windowWidth < 640 ? '100%' : 150)
              .margin(this.windowWidth < 640 ? { bottom: 10 } : { right: 24 });
            TextInput({ text: this.endpoint, placeholder: 'http://127.0.0.1:9090' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
              .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field)
              .border({ width: 1, color: this.theme.border }).width('100%').layoutWeight(this.windowWidth < 640 ? 0 : 1)
              .onChange((value: string) => this.endpoint = value);
          }.width('100%');
          Flex({ direction: this.windowWidth < 640 ? FlexDirection.Column : FlexDirection.Row }) {
            Column({ space: 5 }) {
              Text('访问密钥').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
              Text('外部内核 Secret · 可选').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.alignItems(HorizontalAlign.Start).width(this.windowWidth < 640 ? '100%' : 150)
              .margin(this.windowWidth < 640 ? { bottom: 10 } : { right: 24 });
            TextInput({ text: this.secret, placeholder: '未设置' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Password)
              .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field)
              .border({ width: 1, color: this.theme.border }).width('100%').layoutWeight(this.windowWidth < 640 ? 0 : 1)
              .onChange((value: string) => this.secret = value);
          }.width('100%');
          Row({ space: 12 }) {
            Column({ space: 5 }) {
              Text('内置控制器认证').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
              Text(`${this.controllerAccessStatus} · 与外部内核密钥独立`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.alignItems(HorizontalAlign.Start).layoutWeight(1);
            this.outlineButton('管理密钥', $r('app.media.verge_settings'), () => this.openControllerAccess());
          }.width('100%');
          Row() {
            Text(this.coreConnected ? this.coreVersion : '未连接内核')
              .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.coreConnected ? this.theme.success : this.theme.textMuted).layoutWeight(1);
            if (this.internalCore) {
              Button(this.diagnosing ? '自检中…' : '内核自检', { type: ButtonType.Normal })
                .height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).borderRadius(this.theme.radius(5))
                .margin({ right: 10 }).enabled(!this.diagnosing).onClick(() => this.diagnoseCore());
            }
            if (this.backgroundCore) {
              Button('关闭 TUN', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary)
                .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).margin({ right: 10 }).enabled(!this.tunBusy)
                .onClick(() => this.setTunEnabled(false));
            }
            this.primaryButton('测试连接', $r('app.media.verge_refresh'), () => this.connectCore());
          }.width('100%');
        }.width('100%').padding(20);
      }.width('100%').borderRadius(this.theme.radius(8)).clip(true).border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
      if (this.internalCore) {
        Row({ space: 16 }) {
          Column({ space: 5 }) {
            Text('内核运行设置').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
            Text(this.temporaryConfig ? '临时配置 · 日志级别、IPv6、重新加载' : '代理模式、日志级别、IPv6、重新加载')
              .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
          }.alignItems(HorizontalAlign.Start).layoutWeight(1);
          this.outlineButton('运行设置', $r('app.media.verge_settings'), () => this.openRuntimeConfig());
        }.width('100%').padding(20).borderRadius(this.theme.radius(8)).backgroundColor(this.theme.surface).border({ width: 1, color: this.theme.border });
        this.geoSettings();
      }
      Column({ space: 0 }) {
        Row({ space: 9 }) {
          this.icon($r('app.media.verge_connections'), 18, 'textSecondary');
          Text('代理设置').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).layoutWeight(1);
          if (this.internalCore) this.outlineButton('端口设置', $r('app.media.verge_settings'), () => this.openProxyPorts());
        }.width('100%').padding(20);
        Divider().color(this.theme.divider);
        Row({ space: 12 }) {
          Column({ space: 5 }) {
            Text('系统代理').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
            Text(this.systemProxyDescription()).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily)
              .fontColor(this.systemProxyMatchesCore() ? this.theme.success : this.theme.textMuted);
          }.alignItems(HorizontalAlign.Start).layoutWeight(1);
          Button(this.systemProxyAction(), { type: ButtonType.Normal })
            .height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).borderRadius(this.theme.radius(5))
            .padding({ left: 12, right: 12 }).backgroundColor(this.theme.primarySoft)
            .enabled(!this.systemProxyOpening).onClick(() => this.requestSystemProxyChange());
          this.outlineButton('配置', $r('app.media.verge_settings'), () => this.showSystemProxyGuide());
        }.width('100%').padding({ left: 20, right: 20, top: 16, bottom: 16 })
          .border({ width: { bottom: 1 }, color: this.theme.divider });
        Row({ space: 16 }) {
          Column({ space: 5 }) {
            Text('虚拟网卡模式').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
            Text(this.tunBusy ? '正在切换…' : this.tunError || '通过系统 VPN 接管网络请求')
              .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.tunError.length > 0 ? this.theme.danger : this.theme.textMuted);
          }.alignItems(HorizontalAlign.Start).layoutWeight(1);
          Toggle({ type: ToggleType.Switch, isOn: this.tunEnabled }).width(36).height(22).selectedColor(this.theme.primary)
            .enabled(!this.tunBusy && (this.tunEnabled || (this.internalCore && this.coreConnected && this.socksPort > 0)))
            .onChange((value: boolean) => this.setTunEnabled(value));
        }.width('100%').padding({ left: 20, right: 20, top: 16, bottom: 16 })
          .border({ width: { bottom: 1 }, color: this.theme.divider });
        this.proxyPortRow(false);
        this.proxyPortRow(true);
        if (this.internalCore) {
          Row({ space: 12 }) {
            Column({ space: 5 }) {
              Text('域名嗅探').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
              Text(this.sniffing ? '已开启 · 按当前协议和端口配置识别' : '已关闭 · 使用请求中的原地址').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.alignItems(HorizontalAlign.Start).layoutWeight(1);
            this.outlineButton('嗅探配置', $r('app.media.verge_settings'), () => this.openSnifferSettings());
            Toggle({ type: ToggleType.Switch, isOn: this.sniffing }).width(36).height(22).selectedColor(this.theme.primary)
              .enabled(this.coreConnected && !this.tunBusy && !this.snifferBusy).accessibilityText('域名嗅探开关').onChange((value: boolean) => this.setSniffing(value));
          }.width('100%').padding(20).border({ width: { top: 1 }, color: this.theme.divider }).bindContextMenu(this.snifferMenu(), ResponseType.RightClick);
          Row({ space: 12 }) {
            Column({ space: 5 }) {
              Text('局域网共享').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
              Text(this.allowLan ? '已开启 · 允许其他设备连接' : '已关闭 · 仅允许本机连接').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
            }.alignItems(HorizontalAlign.Start).layoutWeight(1);
            this.outlineButton('共享设置', $r('app.media.verge_settings'), () => this.openInboundSettings());
          }.width('100%').padding(20).border({ width: { top: 1 }, color: this.theme.divider })
            .bindContextMenu(this.inboundSettingsMenu(), ResponseType.RightClick);
        }
      }.width('100%').borderRadius(this.theme.radius(8)).clip(true).border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
      Column({ space: 14 }) {
        this.cardTitle('节点测速', $r('app.media.verge_chart'));
        TextInput({ text: this.testUrl, placeholder: 'https://www.gstatic.com/generate_204' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
          .fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field)
          .onChange((value: string) => this.testUrl = value);
        Row() {
          Text(this.internalCore ? '验证 HTTP / HTTPS 测试地址，默认超时 5 秒' : '通过当前内核检测测试地址')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
          this.outlineButton('保存', $r('app.media.verge_check'), () => {
            if (!/^https?:\/\/[^\s]+$/.test(this.testUrl.trim())) {
              this.notice = '请输入有效的 HTTP 或 HTTPS 地址';
              return;
            }
            this.persistSettings();
            this.notice = '测速设置已保存';
          });
        }.width('100%');
      }.width('100%').padding(20).borderRadius(this.theme.radius(8)).border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
      Column({ space: 0 }) {
        Row({ space: 9 }) {
          Image($r('app.media.verge_mark')).fillColor(this.theme.text).colorFilter(this.iconColor(this.theme.text)).width(21).height(21);
          Text('关于').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text);
        }.width('100%').padding(20);
        Divider().color(this.theme.divider);
        this.settingRow({ title: 'ClashOS', detail: 'HarmonyOS', value: '1.0.0' });
        Row() { this.settingRow({ title: '开源许可', detail: 'HevSocks5Tunnel / Mbed TLS / libyaml 等', value: '查看' }); }
          .width('100%').onClick(() => this.showLicenses());
      }.width('100%').borderRadius(this.theme.radius(8)).clip(true).border({ width: 1, color: this.theme.border }).backgroundColor(this.theme.surface);
    }.width('100%');
  }

  @Builder
  private settingRow(options: SettingRowOptions) {
    Row({ space: 16 }) {
      Column({ space: 5 }) {
        Text(options.title).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
        Text(options.detail).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.alignItems(HorizontalAlign.Start).layoutWeight(1);
      Text(options.value).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
    }.width('100%').padding({ left: 20, right: 20, top: 16, bottom: 16 })
      .border({ width: { bottom: 1 }, color: this.theme.divider });
  }

  @Builder
  private statusBar() {
    Row({ space: 8 }) {
      Circle({ width: 6, height: 6 }).fill(this.coreConnected ? this.theme.success : this.theme.textMuted);
      Text(this.coreConnected ? '内核运行中' : '内核离线').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary);
      if (this.tunEnabled) {
        Text('TUN').fontSize(this.theme.font(9)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).padding({ left: 5, right: 5, top: 2, bottom: 2 })
          .borderRadius(this.theme.radius(3)).backgroundColor(this.theme.primarySoft);
      }
      if (this.windowWidth >= 800) {
        Text('·').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
        Text(this.activeProfileName()).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted)
          .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis }).constraintSize({ maxWidth: 220 });
      }
      Blank();
      if (this.windowWidth >= 560) {
        Text(`↑ ${this.rateText(this.uploadRate)}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning);
      }
      Text(`↓ ${this.rateText(this.downloadRate)}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).margin({ left: 8 });
      if (this.windowWidth >= 1080) {
        Text(`同步于 ${this.lastSyncTime}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).margin({ left: 14 });
      }
    }.width('100%').height(32).padding({ left: 20, right: 20 })
      .backgroundColor(this.theme.chrome).border({ width: { top: 1 }, color: this.theme.border });
  }

  build() {
    Column({ space: 0 }) {
      this.navigationBar();
      this.pageHeader();
      Row({ space: 0 }) {
        Scroll(this.contentScroller) {
          Column({ space: 0 }) {
            this.noticeBar();
            if (this.selectedTab === 0) {
              this.overview();
            } else if (this.selectedTab === 1) {
              this.proxyPage();
            } else if (this.selectedTab === 2) {
              this.rulesPage();
            } else if (this.selectedTab === 3) {
              this.connectionsPage();
            } else if (this.selectedTab === 4) {
              this.profilesPage();
            } else if (this.selectedTab === 5) {
              this.logsPage();
            } else if (this.selectedTab === 7) {
              this.testsPage();
            } else {
              this.settingsPage();
            }
          }
          .width('100%')
          .padding({ left: this.theme.contentGap, right: this.hasGroupNavigator() ? 4 : this.theme.contentGap,
            top: this.theme.contentGap, bottom: 20 });
        }
        .height('100%').layoutWeight(1)
        .align(Alignment.Top)
        .scrollBar(BarState.Auto)
        .onAreaChange((_old: Area, area: Area) => {
          const top: number = Number(area.globalPosition.y);
          const shift: number = this.contentTop - top;
          Object.keys(this.groupPositions).forEach((name: string) => this.groupPositions[name] += shift);
          this.contentTop = top;
        })
        .onDidScroll(() => this.updateGroupFocus(this.contentScroller.currentOffset().yOffset));
        if (this.hasGroupNavigator()) {
          this.groupNavigator();
        }
      }.width('100%').layoutWeight(1);
      this.statusBar();
    }
    .width('100%').height('100%').backgroundColor(this.theme.canvas)
    .onAreaChange((_old: Area, area: Area) => this.windowWidth = Number(area.width));
  }
}
