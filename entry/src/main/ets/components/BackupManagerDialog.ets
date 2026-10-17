import { VergePalette } from '../theme/VergeTheme';
import { BackupStore } from '../service/BackupStore';
import { ProfileStore, ClashProfile } from '../service/ProfileStore';
import { BackupEntry, BackupPreviewRow, WebDavSettings, BackupGlobals, BackupRestoreSelection, BackupRestoreResult } from '../service/BackupTypes';
import { AppearanceSettings } from '../theme/AppearanceTypes';
import { utf8Bytes } from '../service/TextCodec';
import { WebDavClient } from '../service/WebDavClient';

@CustomDialog
export struct BackupManagerDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  store?: BackupStore;
  profiles?: ProfileStore;
  readAppearance: () => AppearanceSettings | undefined = (): AppearanceSettings | undefined => undefined;
  readGroupIconRevision: () => string | undefined = (): string | undefined => undefined;
  onRestore: (text: string, selection: BackupRestoreSelection) => Promise<BackupRestoreResult> = async (_text: string, _selection: BackupRestoreSelection): Promise<BackupRestoreResult> => { throw new Error('恢复服务不可用'); };
  @State remoteMode: boolean = false;
  @State localEntries: BackupEntry[] = [];
  @State remoteEntries: BackupEntry[] = [];
  @State server: string = '';
  @State username: string = '';
  @State password: string = '';
  @State busy: string = '';
  @State error: string = '';
  @State notice: string = '';
  @State previewing: boolean = false;
  @State creating: boolean = false;
  @State createRows: ClashProfile[] = [];
  @State createSelected: string[] = [];
  @State includeGlobals: boolean = true;
  @State includeAppearance: boolean = true;
  @State restoreGlobals: boolean = false;
  @State restoreAppearance: boolean = false;
  @State hasGlobals: boolean = false;
  @State hasAppearance: boolean = false;
  @State globalSummary: string = '';
  @State appearanceSummary: string = '';
  @State previewReady: boolean = false;
  @State previewRows: BackupPreviewRow[] = [];
  @State selected: number[] = [];
  @State previewTime: string = '';
  @State migrationNotes: string = '';
  @State dialogWidth: number = 900;
  private pendingText: string = '';
  private pendingUpload: boolean = false;
  private expectedGlobals?: BackupGlobals;
  private expectedAppearance?: AppearanceSettings;
  private expectedGroupIcons?: string;
  private expectedNames: string = '';
  private client?: WebDavClient;
  private clientKey: string = '';
  private alive: boolean = true;

  aboutToAppear(): void {
    try {
      this.localEntries = this.store?.list() ?? [];
      const settings: WebDavSettings = this.store?.loadSettings() ?? { url: '', username: '', password: '' };
      this.server = settings.url; this.username = settings.username; this.password = settings.password;
    } catch (error) { this.error = (error as Error).message; }
  }

  aboutToDisappear(): void { this.alive = false; this.client?.close(); this.pendingText = ''; this.clientKey = ''; this.password = ''; }

  private settings(): WebDavSettings { return { url: this.server.trim(), username: this.username, password: this.password }; }

  private connection(): WebDavClient {
    const settings: WebDavSettings = this.settings();
    const key: string = JSON.stringify(settings);
    if (this.client === undefined || key !== this.clientKey) {
      this.client?.close(); this.client = new WebDavClient(settings); this.clientKey = key;
    }
    return this.client;
  }

  private async perform(label: string, action: () => Promise<void>): Promise<void> {
    if (this.busy.length > 0) return;
    this.busy = label; this.error = ''; this.notice = '';
    try { await action(); }
    catch (error) { if (this.alive) this.error = (error as Error).message || '备份操作失败'; }
    finally {
      if (this.alive) {
        this.busy = '';
        try { this.localEntries = this.store?.list() ?? []; } catch (_) { if (!this.error) this.error = '无法读取本地备份列表'; }
      }
    }
  }

  private create(upload: boolean = false): void {
    if (this.busy.length) return;
    try {
      this.createRows = this.profiles?.list() ?? []; this.createSelected = this.createRows.map((profile: ClashProfile) => profile.id);
      this.pendingUpload = upload; this.includeGlobals = true; this.includeAppearance = true;
      this.creating = true; this.error = ''; this.notice = '';
    } catch (error) { this.error = (error as Error).message; }
  }

  private confirmCreate(): void {
    this.perform(this.pendingUpload ? '正在备份并上传…' : '正在创建备份…', async (): Promise<void> => {
      if (this.store === undefined) throw new Error('备份目录不可用');
      const client: WebDavClient | undefined = this.pendingUpload ? this.connection() : undefined;
      const entry: BackupEntry = this.store.create({ profileIds: this.createSelected, includeGlobals: this.includeGlobals, includeAppearance: this.includeAppearance });
      this.creating = false;
      if (client !== undefined) {
        try { await client.upload(entry, this.store.read(entry)); }
        catch (error) { throw new Error(`${(error as Error).message}；本地备份已保留`); }
        if (!this.alive) return;
        this.remoteEntries = await client.list(); this.notice = '备份已上传并校验，本地副本已保留';
      } else this.notice = '已创建本地备份';
    });
  }

  private connect(): void {
    this.perform('正在连接 WebDAV…', async (): Promise<void> => {
      const client: WebDavClient = this.connection();
      const entries: BackupEntry[] = await client.list();
      if (!this.alive) return;
      this.store?.saveSettings(this.settings()); this.remoteEntries = entries;
      this.notice = `WebDAV 设置已保存，找到 ${entries.length} 份备份`;
    });
  }

  private importBackup(): void {
    this.perform('正在导入备份…', async (): Promise<void> => {
      const text: string | undefined = await this.profiles?.pickBackup();
      if (text === undefined || !this.alive) return;
      const entry: BackupEntry | undefined = this.store?.importText(text);
      if (entry === undefined) throw new Error('备份目录不可用');
      this.openPreview(text); this.notice = '备份已导入本地，可选择配置进行恢复';
    });
  }

  private openPreview(text: string): void {
    if (this.profiles === undefined) throw new Error('配置目录不可用');
    this.pendingText = text; this.restoreGlobals = false; this.restoreAppearance = false;
    this.refreshPreview(); this.previewing = true;
  }

  private refreshPreview(): void {
    if (this.profiles === undefined) throw new Error('配置目录不可用');
    this.previewReady = false;
    const preview = this.profiles.inspectBackup(this.pendingText, this.restoreGlobals);
    this.previewRows = preview.rows; this.previewTime = preview.archive.createdAt;
    this.migrationNotes = (preview.archive.migrationNotes ?? []).join('\n');
    this.hasGlobals = preview.archive.globals !== undefined; this.hasAppearance = preview.archive.appearance !== undefined;
    this.globalSummary = preview.archive.globals ? `YAML：${preview.archive.globals.merge ? `${utf8Bytes(preview.archive.globals.merge).length} 字节` : '空，将清除现有扩展'}；脚本：${preview.archive.globals.script ? `${utf8Bytes(preview.archive.globals.script).length} 字节` : '空，将清除现有脚本'}` : '';
    const appearance: AppearanceSettings | undefined = preview.archive.appearance;
    this.appearanceSummary = appearance ? `${appearance.mode === 'system' ? '跟随系统' : appearance.mode === 'dark' ? '深色' : '浅色'} · ${appearance.accent}` : '';
    if (preview.archive.groupIcons) this.appearanceSummary += ` · ${preview.archive.groupIcons.entries.length} 个代理组图标（替换本机覆盖）`;
    this.expectedGlobals = preview.currentGlobals; this.expectedNames = preview.namesSnapshot;
    try { this.expectedAppearance = this.readAppearance(); } catch (_) { this.expectedAppearance = undefined; }
    try { this.expectedGroupIcons = this.readGroupIconRevision(); } catch (_) { this.expectedGroupIcons = undefined; }
    this.selected = preview.rows.filter((row: BackupPreviewRow) => row.valid).map((row: BackupPreviewRow) => row.index);
    this.previewReady = true;
  }

  private preview(entry: BackupEntry): void {
    this.perform(entry.remote ? '正在下载并校验备份…' : '正在校验备份…', async (): Promise<void> => {
      if (this.store === undefined) throw new Error('备份目录不可用');
      const text: string = entry.remote ? await this.connection().download(entry) : this.store.read(entry);
      if (!this.alive) return;
      this.profiles?.inspectBackup(text);
      if (entry.remote) this.store.importText(text);
      this.openPreview(text);
    });
  }

  private restore(): void {
    this.perform('正在恢复配置…', async (): Promise<void> => {
      if (this.profiles === undefined) throw new Error('配置目录不可用');
      const result: BackupRestoreResult = await this.onRestore(this.pendingText, { profiles: this.selected, globals: this.restoreGlobals, appearance: this.restoreAppearance,
        expectedGlobals: this.expectedGlobals, expectedAppearance: this.expectedAppearance, expectedGroupIcons: this.expectedGroupIcons, expectedNames: this.expectedNames });
      this.previewing = false; this.pendingText = ''; this.previewRows = []; this.selected = [];
      const parts: string[] = [];
      if (result.count > 0) parts.push(`${result.count} 份配置副本`);
      if (result.globals) parts.push(result.reloaded ? '全局扩展（已加载）' : '全局扩展（下次加载时生效）');
      if (result.appearance) parts.push('外观');
      this.notice = `已恢复${parts.join('、')}；活动配置保持不变`;
    });
  }

  private upload(entry: BackupEntry): void {
    this.perform('正在上传并校验…', async (): Promise<void> => {
      if (this.store === undefined) throw new Error('备份目录不可用');
      const client: WebDavClient = this.connection();
      await client.upload(entry, this.store.read(entry));
      if (!this.alive) return;
      this.remoteEntries = await client.list(); this.notice = '上传后校验通过，本地备份已保留';
    });
  }

  private download(entry: BackupEntry): void {
    this.perform('正在下载备份…', async (): Promise<void> => {
      const text: string = await this.connection().download(entry);
      if (!this.alive) return;
      this.store?.importText(text); this.notice = 'WebDAV 备份已保存到本地';
    });
  }

  private exportBackup(entry: BackupEntry, zip: boolean = false): void {
    this.perform('正在导出备份…', async (): Promise<void> => {
      if (zip ? await this.store?.exportZip(entry) : await this.store?.export(entry)) this.notice = zip ? 'ZIP 备份已导出，可在 ClashOS 或 Clash Verge 中导入' : '备份已导出';
    });
  }

  private confirmDelete(entry: BackupEntry): void {
    this.getUIContext().showAlertDialog({ title: entry.remote ? '删除 WebDAV 备份' : '删除本地备份',
      message: `删除 ${entry.name}？已恢复的配置不会被删除。`,
      primaryButton: { value: '取消', action: () => {} },
      secondaryButton: { value: '删除', fontColor: this.theme.danger, action: () => {
        this.perform('正在删除备份…', async (): Promise<void> => {
          if (entry.remote) {
            const client: WebDavClient = this.connection(); await client.remove(entry);
            if (this.alive) this.remoteEntries = await client.list();
          } else this.store?.remove(entry);
          if (this.alive) this.notice = '备份已删除';
        });
      } }
    });
  }

  private forget(): void {
    try {
      this.store?.forgetSettings(); this.client?.close(); this.client = undefined; this.clientKey = '';
      this.server = ''; this.username = ''; this.password = ''; this.remoteEntries = []; this.notice = '已清除本机保存的 WebDAV 账户';
    } catch (_) { this.error = 'WebDAV 账户未能清除'; }
  }

  private time(value: string): string { const date = new Date(value); return Number.isNaN(date.getTime()) ? '时间未知' : date.toLocaleString(); }
  private formatSize(bytes: number): string { return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`; }

  @Builder
  private action(label: string, callback: () => void, primary: boolean = false) {
    Button(label, { type: ButtonType.Normal }).fontSize(12).height(34).borderRadius(5)
      .fontColor(primary ? this.theme.onPrimary : this.theme.primary).backgroundColor(primary ? this.theme.primary : this.theme.primarySoft)
      .enabled(this.busy.length === 0).onClick(callback);
  }

  @Builder
  private entryMenu(entry: BackupEntry) {
    Menu() {
      MenuItem({ content: '预览并恢复' }).onClick(() => this.preview(entry));
      if (entry.remote) {
        MenuItem({ content: '下载到本地', startIcon: $r('app.media.verge_download') }).onClick(() => this.download(entry));
      } else {
        MenuItem({ content: '导出备份', startIcon: $r('app.media.verge_download') }).onClick(() => this.exportBackup(entry));
        MenuItem({ content: '导出 ZIP（兼容 Clash Verge）' }).onClick(() => this.exportBackup(entry, true));
        MenuItem({ content: '上传到 WebDAV', startIcon: $r('app.media.verge_upload') }).onClick(() => this.upload(entry));
      }
      MenuItem({ content: '删除备份', startIcon: $r('app.media.verge_trash') }).onClick(() => this.confirmDelete(entry));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE).enabled(this.busy.length === 0);
  }

  @Builder
  private backupRow(entry: BackupEntry) {
    Row({ space: 12 }) {
      Image($r('app.media.verge_file')).width(24).height(24);
      Column({ space: 5 }) {
        Text(this.time(entry.updatedAt)).fontSize(14).fontWeight(FontWeight.Medium).fontColor(this.theme.text);
        Text(`${this.formatSize(entry.bytes)} · ${entry.name}`).fontSize(11).fontColor(this.theme.textMuted)
          .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
      }.layoutWeight(1).alignItems(HorizontalAlign.Start);
      this.action('预览恢复', () => this.preview(entry));
      Button({ type: ButtonType.Normal }) { Image($r('app.media.verge_more')).width(19).height(19); }
        .width(32).height(34).backgroundColor(Color.Transparent).enabled(this.busy.length === 0)
        .accessibilityText(`${entry.remote ? 'WebDAV' : '本地'}备份操作`).bindMenu(this.entryMenu(entry));
    }.width('100%').padding(14).backgroundColor(this.theme.surface).borderRadius(7)
      .bindContextMenu(this.entryMenu(entry), ResponseType.RightClick);
  }

  @Builder
  private createContent() {
    Column({ space: 12 }) {
      Text('选择本次备份的配置与设置。配置原文及其中的凭据会保留；应用单独保存的 WebDAV 账户和内置控制器密钥不会额外打包。')
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      Row({ space: 10 }) {
        this.action('选择全部配置', () => this.createSelected = this.createRows.map((profile: ClashProfile) => profile.id));
        this.action('取消全选', () => this.createSelected = []);
        Text(`已选 ${this.createSelected.length} / ${this.createRows.length}`).fontSize(12).fontColor(this.theme.textMuted);
      }.width('100%');
      Scroll() {
        Column({ space: 8 }) {
          ForEach(this.createRows, (profile: ClashProfile) => {
            Row({ space: 12 }) {
              Checkbox({ name: `backup-${profile.id}` }).select(this.createSelected.indexOf(profile.id) >= 0).selectedColor(this.theme.primary)
                .accessibilityText(`备份配置：${profile.name}`).enabled(this.busy.length === 0)
                .onChange((checked: boolean) => this.createSelected = checked ? this.createSelected.indexOf(profile.id) < 0 ? [...this.createSelected, profile.id] : this.createSelected : this.createSelected.filter((id: string) => id !== profile.id));
              Text(profile.name).fontSize(14).fontColor(this.theme.text).layoutWeight(1).maxLines(2);
            }.width('100%').padding(14).borderRadius(7).backgroundColor(this.theme.surface);
          }, (profile: ClashProfile) => profile.id);
          if (!this.createRows.length) Text('当前没有配置，仍可备份全局扩展与外观。').fontSize(12).fontColor(this.theme.textMuted).width('100%').padding(14);
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
      Row({ space: 10 }) {
        Checkbox({ name: 'backup-globals' }).select(this.includeGlobals).selectedColor(this.theme.primary).enabled(this.busy.length === 0)
          .accessibilityText('备份全局扩展与脚本').onChange((checked: boolean) => this.includeGlobals = checked);
        Text('包含全局 YAML 扩展与 JavaScript 脚本').fontSize(13).fontColor(this.theme.text).layoutWeight(1);
      }.width('100%');
      Row({ space: 10 }) {
        Checkbox({ name: 'backup-appearance' }).select(this.includeAppearance).selectedColor(this.theme.primary).enabled(this.busy.length === 0)
          .accessibilityText('备份外观').onChange((checked: boolean) => this.includeAppearance = checked);
        Text('包含外观：颜色模式、主题色与代理组图标（含本机图片）').fontSize(13).fontColor(this.theme.text).layoutWeight(1);
      }.width('100%');
      Row({ space: 10 }) {
        Blank(); this.action('返回备份列表', () => this.creating = false);
        Button(this.pendingUpload ? '创建并上传所选内容' : '创建所选备份', { type: ButtonType.Normal }).height(36).fontSize(13).borderRadius(5)
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary)
          .enabled(this.busy.length === 0 && (this.createSelected.length > 0 || this.includeGlobals || this.includeAppearance)).onClick(() => this.confirmCreate());
      }.width('100%');
    }.width('100%').layoutWeight(1);
  }

  @Builder
  private previewContent() {
    Column({ space: 12 }) {
      Text(`备份时间：${this.time(this.previewTime)}`).fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      if (this.migrationNotes) Text(this.migrationNotes).fontSize(11).fontColor(this.theme.textSecondary).width('100%');
      Text(this.restoreGlobals ? '将替换全局扩展并重新加载当前内置配置。应用端口覆盖、认证和账户设置保留；扩展中的端口字段可能改变实际监听端口。' : '配置恢复为独立副本，不切换活动配置。全局设置默认保留，可在下方单独选择。')
        .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
      if (this.hasGlobals) {
        Row({ space: 10 }) {
          Checkbox({ name: 'restore-globals' }).select(this.restoreGlobals).selectedColor(this.theme.primary).enabled(this.busy.length === 0)
            .accessibilityText('恢复全局扩展与脚本').onChange((checked: boolean) => {
              if (checked === this.restoreGlobals) return;
              this.restoreGlobals = checked; this.error = '';
              try { this.refreshPreview(); this.notice = '已按所选全局扩展重新校验，请确认配置选择'; }
              catch (error) { this.error = (error as Error).message; }
            });
          Column({ space: 4 }) {
            Text('恢复备份中的全局扩展与脚本').fontSize(13).fontColor(this.theme.text);
            Text(this.globalSummary).fontSize(11).fontColor(this.theme.textMuted);
          }.layoutWeight(1).alignItems(HorizontalAlign.Start);
        }.width('100%');
      }
      if (this.hasAppearance) {
        Row({ space: 10 }) {
          Checkbox({ name: 'restore-appearance' }).select(this.restoreAppearance).selectedColor(this.theme.primary).enabled(this.busy.length === 0)
            .accessibilityText('恢复外观').onChange((checked: boolean) => this.restoreAppearance = checked);
          Text(`恢复外观：${this.appearanceSummary}`).fontSize(13).fontColor(this.theme.text).layoutWeight(1);
        }.width('100%');
      }
      Row({ space: 10 }) {
        this.action('选择全部可用配置', () => this.selected = this.previewRows.filter((row: BackupPreviewRow) => row.valid).map((row: BackupPreviewRow) => row.index));
        this.action('取消全选', () => this.selected = []);
        Text(`已选 ${this.selected.length} / ${this.previewRows.length}`).fontSize(12).fontColor(this.theme.textMuted);
      }.width('100%');
      Scroll() {
        Column({ space: 8 }) {
          ForEach(this.previewRows, (row: BackupPreviewRow) => {
            Row({ space: 12 }) {
              Checkbox({ name: `restore-${row.index}` }).select(this.selected.indexOf(row.index) >= 0)
                .selectedColor(this.theme.primary).enabled(row.valid && this.busy.length === 0)
                .onChange((checked: boolean) => this.selected = checked ? this.selected.indexOf(row.index) < 0 ? [...this.selected, row.index] : this.selected : this.selected.filter((value: number) => value !== row.index));
              Column({ space: 5 }) {
                Text(row.name).fontSize(14).fontColor(this.theme.text).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                if (row.restoreName !== row.name) Text(`恢复为：${row.restoreName}`).fontSize(11).fontColor(this.theme.textMuted).maxLines(2);
                Text(row.valid ? `配置可加载 · ${row.resources} 份集合缓存` : '当前内核无法加载此配置，已跳过；原文仍保留在备份中')
                  .fontSize(11).fontColor(row.valid ? this.theme.textMuted : this.theme.warning);
                if (!row.valid && row.error) Text(row.error).fontSize(11).fontColor(this.theme.warning).maxLines(2);
              }.layoutWeight(1).alignItems(HorizontalAlign.Start);
            }.width('100%').padding(14).backgroundColor(this.theme.surface).borderRadius(7);
          }, (row: BackupPreviewRow) => `${row.index}`);
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
      Row({ space: 10 }) {
        Blank();
        this.action('返回备份列表', () => { this.previewing = false; this.pendingText = ''; this.previewRows = []; this.selected = []; });
        Button('恢复选中内容', { type: ButtonType.Normal }).height(36).fontSize(13).borderRadius(5)
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(this.previewReady && (this.selected.length > 0 || this.restoreGlobals || this.restoreAppearance) && this.busy.length === 0)
          .onClick(() => this.restore());
      }.width('100%');
    }.width('100%').layoutWeight(1);
  }

  build() {
    Column({ space: 14 }) {
      Row() {
        Text(this.creating ? '新建备份' : this.previewing ? '恢复备份' : '配置备份与恢复').fontSize(21).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button('关闭', { type: ButtonType.Normal }).height(32).fontSize(12).backgroundColor(this.theme.field)
          .fontColor(this.theme.textSecondary).borderRadius(5).onClick(() => { this.client?.close(); this.controller?.close(); });
      }.width('100%');
      if (this.creating) {
        this.createContent();
      } else if (this.previewing) {
        this.previewContent();
      } else {
        Text('备份可包含配置原文及其凭据、扩展/脚本、可视化修改、集合缓存，以及可选的全局扩展和外观。不会额外收集应用端口覆盖、WebDAV 账户、内置控制器密钥和地理数据库。')
          .fontSize(12).fontColor(this.theme.textSecondary).width('100%');
        Row({ space: 8 }) {
          Button('本地备份', { type: ButtonType.Normal }).height(36).fontSize(13).borderRadius(5)
            .backgroundColor(this.remoteMode ? this.theme.surface : this.theme.primarySoft).fontColor(this.remoteMode ? this.theme.textSecondary : this.theme.primary)
            .enabled(this.busy.length === 0).onClick(() => this.remoteMode = false);
          Button('WebDAV', { type: ButtonType.Normal }).height(36).fontSize(13).borderRadius(5)
            .backgroundColor(this.remoteMode ? this.theme.primarySoft : this.theme.surface).fontColor(this.remoteMode ? this.theme.primary : this.theme.textSecondary)
            .enabled(this.busy.length === 0).onClick(() => this.remoteMode = true);
          Blank();
          if (!this.remoteMode && this.dialogWidth >= 640) {
            this.action('导入备份', () => this.importBackup()); this.action('新建备份', () => this.create(), true);
          }
        }.width('100%');
        if (this.remoteMode) {
          Column({ space: 10 }) {
            TextInput({ text: this.server, placeholder: 'WebDAV 目录，如 https://dav.example.com/dav/' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
              .height(38).fontSize(13).backgroundColor(this.theme.surface).borderRadius(5).enabled(this.busy.length === 0)
              .onChange((value: string) => { if (this.server !== value) { this.server = value; this.remoteEntries = []; } });
            Row({ space: 10 }) {
              TextInput({ text: this.username, placeholder: '用户名' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).layoutWeight(1)
                .backgroundColor(this.theme.surface).borderRadius(5).enabled(this.busy.length === 0).onChange((value: string) => { if (this.username !== value) { this.username = value; this.remoteEntries = []; } });
              TextInput({ text: this.password, placeholder: '密码' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Password).height(38).fontSize(13).layoutWeight(1)
                .backgroundColor(this.theme.surface).borderRadius(5).enabled(this.busy.length === 0).onChange((value: string) => { if (this.password !== value) { this.password = value; this.remoteEntries = []; } });
            }.width('100%');
            Text(this.server.trim().startsWith('http:') ? 'HTTP 会明文传输凭据和备份，建议使用 HTTPS。备份存放在指定目录下的 ClashOS 文件夹。' :
              '备份存放在指定目录下的 ClashOS 文件夹。账号只保存到本机，不包含在配置备份中。')
              .fontSize(11).fontColor(this.theme.textMuted).width('100%');
            Row({ space: 8 }) {
              this.action('保存并刷新', () => this.connect()); this.action('新建并上传', () => this.create(true), true);
              this.action('清除本机账户', () => this.forget());
            }.width('100%');
          }.width('100%');
        } else if (this.dialogWidth < 640) {
          Row({ space: 8 }) { this.action('导入备份', () => this.importBackup()); this.action('新建备份', () => this.create(), true); }.width('100%');
        }
        Scroll() {
          Column({ space: 9 }) {
            if ((this.remoteMode ? this.remoteEntries : this.localEntries).length === 0) {
              Text(this.remoteMode ? '保存并刷新后显示 WebDAV 备份' : '暂无本地备份，点击“新建备份”保存当前配置')
                .fontSize(13).fontColor(this.theme.textMuted).width('100%').textAlign(TextAlign.Center).padding(40);
            }
            ForEach(this.remoteMode ? this.remoteEntries : this.localEntries, (entry: BackupEntry) => this.backupRow(entry),
              (entry: BackupEntry) => `${entry.remote}/${entry.name}/${entry.etag}`);
          }.width('100%');
        }.width('100%').layoutWeight(1).align(Alignment.Top);
      }
      if (this.busy.length > 0) {
        Row({ space: 10 }) { LoadingProgress().width(18).height(18).color(this.theme.primary); Text(this.busy).fontSize(12).fontColor(this.theme.textSecondary); }.width('100%');
      }
      if (this.error.length > 0) Text(this.error).fontSize(12).fontColor(this.theme.danger).width('100%');
      if (this.notice.length > 0) Text(this.notice).fontSize(12).fontColor(this.theme.success).width('100%');
    }.width('92%').height('86%').constraintSize({ maxWidth: 1080 }).padding(24).borderRadius(10)
      .backgroundColor(this.theme.field).onAreaChange((_old: Area, area: Area) => this.dialogWidth = Number(area.width));
  }
}
