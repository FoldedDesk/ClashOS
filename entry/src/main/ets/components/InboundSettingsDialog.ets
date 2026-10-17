import { VergePalette } from '../theme/VergeTheme';
import { ClashInboundSettings, ClashInboundChanges, ClashInboundAccount } from '../service/ClashApi';

@CustomDialog
export struct InboundSettingsDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  initial: ClashInboundSettings = { allowLan: false, bindAddress: '*', users: [], skipAuth: [],
    allowed: ['0.0.0.0/0', '::/0'], denied: [], localAddress: '127.0.0.1', overridden: false, profile: '', revision: 0 };
  onSave: (changes?: ClashInboundChanges) => Promise<void> = async (_changes?: ClashInboundChanges): Promise<void> => {};
  @State allowLan: boolean = false;
  @State address: string = '*';
  @State accounts: ClashInboundAccount[] = [];
  @State skip: string = '';
  @State allowed: string = '';
  @State denied: string = '';
  @State busy: boolean = false;
  @State error: string = '';

  aboutToAppear(): void {
    this.allowLan = this.initial.allowLan; this.address = this.initial.bindAddress;
    this.accounts = this.initial.users.map((name: string): ClashInboundAccount => ({ username: name }));
    this.skip = this.initial.skipAuth.join('\n'); this.allowed = this.initial.allowed.join('\n'); this.denied = this.initial.denied.join('\n');
  }

  private updateAccount(index: number, value: string, password: boolean): void {
    this.accounts = this.accounts.map((account: ClashInboundAccount, current: number): ClashInboundAccount =>
      current !== index ? account : password ? { username: account.username, password: value || undefined } : { username: value, password: account.password });
  }

  private addAccount(): void {
    if (this.accounts.length === 0 && this.initial.users.length === 0 && this.skip.trim().length === 0) this.skip = '127.0.0.0/8\n::1/128';
    this.accounts = this.accounts.concat([{ username: '', password: '' }]);
  }

  private prefixes(value: string): string[] { return value.split(/[\s,]+/).filter((item: string) => item.length > 0); }

  private async save(reset: boolean): Promise<void> {
    if (this.busy) return;
    this.error = '';
    try {
      if (!reset) {
        if (this.address.trim().length === 0) throw new Error('请输入监听地址，* 表示所有网卡');
        const names: string[] = [];
        this.accounts.forEach((account: ClashInboundAccount) => {
          if (!account.username || account.username.indexOf(':') >= 0 || names.indexOf(account.username) >= 0) throw new Error('账号名称不能为空、重复或包含冒号');
          if (!account.password && this.initial.users.indexOf(account.username) < 0) throw new Error('新账号必须填写密码');
          names.push(account.username);
        });
      }
      this.busy = true;
      await this.onSave(reset ? undefined : { allowLan: this.allowLan, bindAddress: this.address.trim(), users: this.accounts,
        skipAuth: this.prefixes(this.skip), allowed: this.prefixes(this.allowed), denied: this.prefixes(this.denied) });
      this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '共享设置未能保存'; }
    finally { this.busy = false; }
  }

  @Builder
  private prefixesField(label: string, text: string, changed: (value: string) => void) {
    Column({ space: 6 }) {
      Text(label).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      TextArea({ text, placeholder: '每行一个 IPv4 / IPv6 CIDR' }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text)
        .placeholderColor(this.theme.textMuted).backgroundColor(this.theme.field).height(58).borderRadius(this.theme.radius(5))
        .enabled(!this.busy).accessibilityText(label).onChange(changed);
    }.width('100%');
  }

  build() {
    Column({ space: 14 }) {
      Text('局域网共享代理').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).width('100%');
      Scroll() {
        Column({ space: 14 }) {
          Text('设置应用于所有保存的配置，订阅更新后仍保留。其他设备使用本机局域网 IP 和代理端口连接。')
            .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
          Row() {
            Text('允许局域网连接').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1);
            Toggle({ type: ToggleType.Switch, isOn: this.allowLan }).width(38).height(24).selectedColor(this.theme.primary)
              .enabled(!this.busy).accessibilityText('允许局域网连接').onChange((value: boolean) => this.allowLan = value);
          }.width('100%');
          TextInput({ text: this.address, placeholder: '*、IPv4 或 IPv6 地址' }).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text)
            .placeholderColor(this.theme.textMuted).backgroundColor(this.theme.field).height(38).borderRadius(this.theme.radius(5))
            .enabled(!this.busy && this.allowLan).accessibilityText('共享监听地址').onChange((value: string) => this.address = value);
          Text(this.allowLan ? '* 同时监听可用的 IPv4 / IPv6 网卡。控制器始终只允许本机访问。' : '共享关闭时仅监听 127.0.0.1。')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          Divider().color(this.theme.divider);
          Row() {
            Text('HTTP / SOCKS5 访问账号').fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1);
            Button('添加账号', { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).borderRadius(this.theme.radius(5))
              .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.busy && this.accounts.length < 128)
              .onClick(() => this.addAccount());
          }.width('100%');
          Text(this.accounts.length === 0 ? '未设置账号，允许匿名连接。' : '已有账号的密码留空表示保留。账号认证也适用于本机，除非来源属于免认证网段。')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
          ForEach(this.accounts, (account: ClashInboundAccount, index: number) => {
            Row({ space: 8 }) {
              TextInput({ text: account.username, placeholder: '用户名' }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text)
                .backgroundColor(this.theme.field).height(36).borderRadius(this.theme.radius(5)).layoutWeight(1).enabled(!this.busy)
                .accessibilityText(`代理账号 ${index + 1}`).onChange((value: string) => this.updateAccount(index, value, false));
              TextInput({ text: account.password ?? '', placeholder: this.initial.users.indexOf(account.username) >= 0 ? '留空保留密码' : '密码' })
                .type(InputType.Password).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).backgroundColor(this.theme.field).height(36).borderRadius(this.theme.radius(5))
                .layoutWeight(1).enabled(!this.busy).accessibilityText(`代理密码 ${index + 1}`).onChange((value: string) => this.updateAccount(index, value, true));
              Button('删除', { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(30).fontColor(this.theme.danger)
                .backgroundColor(Color.Transparent).enabled(!this.busy).onClick(() => this.accounts = this.accounts.filter((_account: ClashInboundAccount, current: number) => current !== index));
            }.width('100%');
          }, (_account: ClashInboundAccount, index: number) => `${index}`);
          this.prefixesField('免认证网段', this.skip, (value: string) => this.skip = value);
          this.prefixesField('允许访问的网段', this.allowed, (value: string) => this.allowed = value);
          this.prefixesField('禁止访问的网段', this.denied, (value: string) => this.denied = value);
          Text('禁止规则优先于允许规则；允许列表为空时，开启共享会拒绝所有来源。网段限制仅在共享开启时生效。')
            .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
        }.width('100%');
      }.width('100%').constraintSize({ maxHeight: 490 }).scrollBar(BarState.Auto);
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
      Row({ space: 8 }) {
        Button('恢复配置设置', { type: ButtonType.Normal }).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).height(36).fontColor(this.theme.primary)
          .backgroundColor(Color.Transparent).enabled(!this.busy && this.initial.overridden).onClick(() => this.save(true));
        Blank();
        Button('取消', { type: ButtonType.Normal }).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(36).borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary)
          .backgroundColor(this.theme.field).enabled(!this.busy).onClick(() => this.controller?.close());
        Button(this.busy ? '保存中…' : '保存并应用', { type: ButtonType.Normal }).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(36).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.busy).onClick(() => this.save(false));
      }.width('100%');
    }.width('88%').constraintSize({ maxWidth: 660 }).padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
