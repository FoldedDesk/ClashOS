import { VergePalette } from '../theme/VergeTheme';
import { ConfigCodeEditor } from './ConfigCodeEditor';
import { ConfigEditorController } from '../service/ConfigEditorController';
import { SubscriptionOptions, subscriptionOptions } from '../service/SubscriptionTypes';
@CustomDialog
export struct ProfileEditorDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  title: string = '编辑配置';
  initialName: string = '';
  initialContent: string = '';
  providerReferences: ((query: string) => Promise<string>) | undefined = undefined;
  onSave: (name: string, content: string) => Promise<void> = async (_name: string, _content: string): Promise<void> => {};
  onValidate: (name: string, content: string) => void = (_name: string, _content: string): void => {};
  @State name: string = '';
  @State content: string = '';
  @State error: string = '';
  @State saving: boolean = false;
  @State editorReady: boolean = false;
  @State validation: string = '';
  private editor: ConfigEditorController = new ConfigEditorController();

  aboutToAppear(): void {
    this.name = this.initialName;
    this.content = this.initialContent;
  }

  private async save(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true;
    this.error = '';
    try {
      this.content = await this.editor.text();
      await this.onSave(this.name, this.content);
      this.controller?.close();
    } catch (error) {
      this.error = (error as Error).message || '无法保存配置';
      this.editor.markError(this.error).catch(() => {});
    } finally {
      this.saving = false;
    }
  }

  private async validate(): Promise<void> {
    if (this.saving || !this.editorReady) return;
    this.saving = true; this.error = ''; this.validation = '';
    try { this.content = await this.editor.text(); this.onValidate(this.name, this.content); this.validation = '原生配置校验通过'; }
    catch (error) { this.error = (error as Error).message; this.editor.markError(this.error).catch(() => {}); }
    finally { this.saving = false; }
  }

  build() {
    Column({ space: 16 }) {
      Row() {
        Text(this.title).fontSize(this.theme.font(19)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button('取消', { type: ButtonType.Normal }).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(34).fontColor(this.theme.textSecondary)
          .backgroundColor(Color.Transparent).enabled(!this.saving).onClick(() => this.controller?.close());
      }.width('100%');
      TextInput({ text: this.name, placeholder: '配置名称' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).height(40)
        .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving).onChange((value: string) => this.name = value);
      ConfigCodeEditor({ editor: this.editor, initialContent: this.initialContent, disabled: this.saving,
        providerReferences: this.providerReferences,
        onReady: (ready: boolean): void => { this.editorReady = ready; },
        onChange: (revision: number): void => { if (this.editor.changedSinceRead(revision)) { this.validation = ''; this.error = ''; } } });
      if (this.error.length > 0) {
        Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').maxLines(3);
      }
      if (this.validation && !this.error) Text(this.validation).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.success).width('100%');
      Row() {
        Text('Tab 缩进 · Ctrl+F 查找 · 原生校验后保存').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1).maxLines(2);
        Button('校验配置', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary)
          .backgroundColor(this.theme.primarySoft).borderRadius(this.theme.radius(5)).margin({ right: 10 }).enabled(this.editorReady && !this.saving)
          .onClick(() => this.validate());
        Button(this.saving ? '正在保存…' : '保存配置', { type: ButtonType.Normal })
          .height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).borderRadius(this.theme.radius(5))
          .padding({ left: 18, right: 18 }).enabled(this.editorReady && !this.saving)
          .onClick(() => this.save());
      }.width('100%');
    }
    .width('88%').height('82%').constraintSize({ maxWidth: 1100 }).padding(24)
    .borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}

@CustomDialog
export struct ProfileInfoDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  title: string = '编辑订阅信息';
  initialName: string = '';
  initialUrl: string = '';
  initialInterval: number = 0;
  initialOptions?: SubscriptionOptions;
  initialFollowInterval: boolean = false;
  requireUrl: boolean = false;
  onSave: (name: string, url: string, interval: number | undefined, options: SubscriptionOptions) => Promise<void> =
    async (_name: string, _url: string, _interval: number | undefined, _options: SubscriptionOptions): Promise<void> => {};
  @State name: string = '';
  @State url: string = '';
  @State interval: string = '0';
  @State userAgent: string = '';
  @State timeout: string = '20';
  @State route: string = 'system';
  @State followInterval: boolean = false;
  @State saving: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    this.name = this.initialName;
    this.url = this.initialUrl;
    this.interval = `${this.initialInterval}`;
    const options: SubscriptionOptions = subscriptionOptions(this.initialOptions);
    this.userAgent = options.userAgent; this.timeout = `${options.timeoutSeconds}`; this.route = options.route;
    this.followInterval = this.initialFollowInterval;
  }

  private async save(): Promise<void> {
    this.error = '';
    if (this.requireUrl && this.url.trim().length === 0) {
      this.error = '请输入订阅地址';
      return;
    }
    const interval: number = Number(this.interval);
    if (!this.followInterval && (!Number.isInteger(interval) || interval < 0 || interval > 10080)) {
      this.error = '更新间隔应为 0 至 10080 分钟';
      return;
    }
    this.saving = true;
    try {
      const options: SubscriptionOptions = subscriptionOptions({ userAgent: this.userAgent, timeoutSeconds: Number(this.timeout), route: this.route });
      await this.onSave(this.name, this.url.trim(), this.followInterval ? undefined : interval, options);
      this.controller?.close();
    } catch (error) {
      this.error = (error as Error).message || '无法保存订阅';
    } finally {
      this.saving = false;
    }
  }

  build() {
    Column({ space: 14 }) {
      Text(this.title).fontSize(this.theme.font(19)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Scroll() {
        Column({ space: 14 }) {
          Text('名称').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          TextInput({ text: this.name, placeholder: this.requireUrl ? '留空使用服务端提供的订阅名称' : '配置名称' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).enabled(!this.saving)
            .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).onChange((value: string) => this.name = value);
          Text('订阅地址').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          TextInput({ text: this.url, placeholder: this.requireUrl ? 'https://…' : '可选，填写后支持更新' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
            .height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving)
            .onChange((value: string) => this.url = value);
          Row({ space: 8 }) {
            Checkbox({ name: 'subscription-follow-interval' }).select(this.followInterval).selectedColor(this.theme.primary).enabled(!this.saving)
              .onChange((value: boolean) => this.followInterval = value).accessibilityText('跟随服务端更新间隔');
            Text('跟随服务端更新间隔').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text);
          }.width('100%');
          if (this.followInterval) Text('使用订阅建议的间隔；未提供建议时关闭自动更新。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          Text('自动更新间隔（分钟，0 为关闭）').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          TextInput({ text: this.interval }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Number).height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
            .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving && !this.followInterval).onChange((value: string) => this.interval = value);
          Text('User-Agent').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          TextInput({ text: this.userAgent, placeholder: 'clashos/1.0' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
            .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving).onChange((value: string) => this.userAgent = value);
          Text('服务商可能按 User-Agent 返回不同格式的配置。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          Text('下载超时（秒，1–120）').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          TextInput({ text: this.timeout }).type(InputType.Number).fontColor(this.theme.text).height(40).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
            .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving).onChange((value: string) => this.timeout = value);
          Text('订阅下载路径').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          Select([{ value: '跟随系统代理' }, { value: '直接连接' }, { value: '内置 HTTP 代理' }])
            .value(this.route === 'direct' ? '直接连接' : this.route === 'core' ? '内置 HTTP 代理' : '跟随系统代理')
            .font({ size: this.theme.font(13), family: this.theme.fontFamily }).width('100%').height(40).enabled(!this.saving)
            .backgroundColor(this.theme.field).onSelect((index: number) => this.route = ['system', 'direct', 'core'][index]);
        }.width('100%');
      }.width('100%').layoutWeight(1);
      if (this.error.length > 0) {
        Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
      }
      Row({ space: 10 }) {
        Blank();
        Button('取消', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary)
          .backgroundColor(this.theme.field).borderRadius(this.theme.radius(5)).enabled(!this.saving)
          .onClick(() => this.controller?.close());
        Button(this.saving ? '处理中…' : this.requireUrl ? '导入订阅' : '保存', { type: ButtonType.Normal })
          .height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).borderRadius(this.theme.radius(5))
          .enabled(!this.saving).onClick(() => this.save());
      }.width('100%').margin({ top: 8 });
    }.width('86%').height('88%').constraintSize({ maxWidth: 600, maxHeight: 900 }).padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
