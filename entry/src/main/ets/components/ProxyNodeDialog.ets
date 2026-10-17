import { VergePalette } from '../theme/VergeTheme';
import { ProfileStore } from '../service/ProfileStore';
import { ProxyNodeForm, EditorObjectView, defaultProxyNodeForm } from '../service/ObjectEditsTypes';

interface WsHeadersPatch { Host: string | null; }
interface WsNodePatch { path: string; headers: WsHeadersPatch; }
interface NodeFormPatch {
  name: string; type: string; udp: boolean;
  server?: string; port?: number; password?: string; uuid?: string; cipher?: string; alterId?: number;
  tls?: boolean; 'skip-cert-verify'?: boolean; servername?: string | null; sni?: string | null; network?: string; 'ws-opts'?: WsNodePatch;
}
const NODE_TYPES: string[] = ['ss', 'vmess', 'vless', 'trojan', 'direct', 'reject'];
const SS_CIPHERS: string[] = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'chacha20-poly1305', 'aead_aes_128_gcm', 'aead_aes_256_gcm', 'aead_chacha20_poly1305'];
const VMESS_CIPHERS: string[] = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'];
export const NEW_NODE_CONTENT: string = '{"name":"","type":"ss","server":"","port":443,"cipher":"aes-128-gcm","password":"","udp":true}';

@CustomDialog
export struct ProxyNodeDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  store?: ProfileStore;
  title: string = '新建节点';
  initialContent: string = NEW_NODE_CONTENT;
  lockName: boolean = false;
  onSave: (item: EditorObjectView) => void = (_item: EditorObjectView): void => {};
  @State form: ProxyNodeForm = defaultProxyNodeForm();
  @State advanced: boolean = false;
  @State raw: string = '';
  @State error: string = '';
  @State changedProtocol: boolean = false;
  @State saving: boolean = false;
  @State dialogWidth: number = 840;
  private base: string = '';
  private identity: string = '';

  aboutToAppear(): void {
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const draft = this.store.nodeDraft(this.initialContent, '', false);
      this.base = draft.item.content; this.identity = draft.item.name;
      this.loadForm(draft.form);
    } catch (error) { this.error = (error as Error).message; }
  }

  private loadForm(form: ProxyNodeForm): void {
    form.type = form.type.toLowerCase(); form.network = form.network.toLowerCase(); form.alterId = form.alterId || '0';
    if (form.type === 'vmess') form.cipher = form.cipher || 'auto';
    this.form = form;
  }

  private integer(text: string, maximum: number, minimum: number = 0): number {
    if (!/^\d{1,5}$/.test(text.trim()) || Number(text) < minimum || Number(text) > maximum) throw new Error(`请输入 ${minimum} 至 ${maximum} 的整数`);
    return Number(text);
  }
  private patch(): string {
    const transport: boolean = this.form.type === 'vmess' || this.form.type === 'vless' || this.form.type === 'trojan';
    const patch: NodeFormPatch = { name: this.lockName ? this.identity : this.form.name.trim(), type: this.form.type, udp: this.form.udp,
      'skip-cert-verify': transport ? this.form.skipCertVerify : undefined,
      'ws-opts': transport && this.form.network === 'ws' ? { path: this.form.wsPath || '/', headers: { Host: this.form.wsHost.trim() || null } } : undefined };
    if (this.form.type !== 'direct' && this.form.type !== 'reject') {
      patch.server = this.form.server.trim(); patch.port = this.integer(this.form.port, 65535, 1);
      if (this.form.type === 'ss' || this.form.type === 'trojan') patch.password = this.form.password;
      if (this.form.type === 'ss' || this.form.type === 'vmess') patch.cipher = this.form.cipher;
      if (this.form.type === 'vmess' || this.form.type === 'vless') patch.uuid = this.form.uuid.trim();
      if (this.form.type === 'vmess') { patch.alterId = this.integer(this.form.alterId || '0', 65535); }
      if (this.form.type === 'vmess' || this.form.type === 'vless' || this.form.type === 'trojan') {
        patch.tls = this.form.type === 'trojan' || this.form.tls;
        patch.servername = this.form.type !== 'trojan' ? this.form.serverName.trim() : null;
        patch.sni = this.form.type === 'trojan' ? this.form.serverName.trim() : null; patch.network = this.form.network;
      }
    }
    return JSON.stringify(patch);
  }
  private mode(): void {
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const draft = this.advanced ? this.store.nodeDraft(this.raw, '', false) : this.store.nodeDraft(this.base, this.patch(), false);
      this.base = draft.item.content; this.raw = draft.item.content;
      if (this.advanced) this.loadForm(draft.form);
      this.advanced = !this.advanced; this.error = '';
    } catch (error) { this.error = (error as Error).message; }
  }
  private protocol(index: number): void {
    const type: string = NODE_TYPES[index]; if (type === this.form.type) return;
    const discarded: boolean = this.identity.length > 0 || this.form.password.length > 0 || this.form.uuid.length > 0;
    const next = defaultProxyNodeForm();
    next.name = this.form.name; next.type = type; next.server = this.form.server; next.port = this.form.port || '443';
    next.cipher = type === 'vmess' ? 'auto' : 'aes-128-gcm'; next.tls = type === 'trojan'; this.form = next;
    this.base = '{}'; this.changedProtocol = this.changedProtocol || discarded;
  }
  private save(): void {
    if (this.saving) return;
    this.saving = true; this.error = '';
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const result = this.advanced ? this.store.nodeDraft(this.raw) : this.store.nodeDraft(this.base, this.patch());
      if (this.lockName && result.item.name !== this.identity) throw new Error('编辑现有节点时请保留名称；需要改名可创建副本');
      this.onSave(result.item); this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '节点未能完成编辑'; }
    finally { this.saving = false; }
  }
  @Builder
  private label(text: string) { Text(text).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%').margin({ bottom: 6 }); }

  build() {
    Column({ space: 12 }) {
      Row() {
        Text(this.title).fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button(this.advanced ? '表单编辑' : '高级配置', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving).onClick(() => this.mode());
      }.width('100%');
      Text('完成编辑后返回列表；点击“保存并应用”才会写入配置。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      if (this.advanced) {
        TextArea({ text: this.raw, placeholder: '单个节点的 YAML / JSON 映射' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontFamily('monospace')
          .backgroundColor(this.theme.field).borderRadius(this.theme.radius(6)).width('100%').layoutWeight(1).enabled(!this.saving).onChange((value: string) => this.raw = value);
      } else {
        Scroll() {
          Column({ space: 14 }) {
            GridRow({ columns: this.dialogWidth < 640 ? 1 : 2, gutter: 12 }) {
              GridCol() { Column() { this.label('节点名称'); TextInput({ text: this.form.name, placeholder: '输入名称' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
                .backgroundColor(this.theme.field).enabled(!this.lockName && !this.saving).onChange((value: string) => this.form.name = value); }.width('100%'); }
              GridCol() { Column() { this.label('协议'); Select(NODE_TYPES.map((value: string): SelectOption => ({ value }))).value(this.form.type).selected(NODE_TYPES.indexOf(this.form.type))
                .height(38).width('100%').font({ size: this.theme.font(13), family: this.theme.fontFamily }).enabled(!this.saving).onSelect((index: number) => this.protocol(index)); }.width('100%'); }
            }.width('100%');
            if (this.lockName) Text('名称用于配置引用；需要改名可创建副本，再更新代理组或规则。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
            if (this.changedProtocol) Text('已清除原协议的其他选项；取消编辑可保留原配置。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning).width('100%');
            if (this.form.type !== 'direct' && this.form.type !== 'reject') {
              GridRow({ columns: this.dialogWidth < 640 ? 1 : 2, gutter: 12 }) {
                GridCol() { Column() { this.label('服务器'); TextInput({ text: this.form.server, placeholder: '域名或 IP，不含协议和路径' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
                  .backgroundColor(this.theme.field).onChange((value: string) => this.form.server = value); }.width('100%'); }
                GridCol() { Column() { this.label('端口'); TextInput({ text: this.form.port, placeholder: '1 至 65535' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).type(InputType.Number)
                  .backgroundColor(this.theme.field).onChange((value: string) => this.form.port = value); }.width('100%'); }
              }.width('100%');
              if (this.form.type === 'ss' || this.form.type === 'trojan') {
                Column() { this.label('密码'); TextInput({ text: this.form.password, placeholder: '节点密码' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).type(InputType.Password).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
                  .backgroundColor(this.theme.field).onChange((value: string) => this.form.password = value); }.width('100%');
              }
              if (this.form.type === 'ss' || this.form.type === 'vmess') {
                Column() { this.label('加密方式'); Select((this.form.type === 'ss' ? SS_CIPHERS : VMESS_CIPHERS).map((value: string): SelectOption => ({ value })))
                  .value(this.form.cipher).selected((this.form.type === 'ss' ? SS_CIPHERS : VMESS_CIPHERS).indexOf(this.form.cipher)).height(38).width('100%').font({ size: this.theme.font(13), family: this.theme.fontFamily })
                  .onSelect((index: number) => this.form.cipher = (this.form.type === 'ss' ? SS_CIPHERS : VMESS_CIPHERS)[index]); }.width('100%');
              }
              if (this.form.type === 'vmess' || this.form.type === 'vless') {
                Column() { this.label('UUID'); TextInput({ text: this.form.uuid, placeholder: '节点 UUID' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
                  .onChange((value: string) => this.form.uuid = value); }.width('100%');
              }
              if (this.form.type === 'vmess') {
                Column() { this.label('alterId（0 为 AEAD）'); TextInput({ text: this.form.alterId }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).type(InputType.Number).backgroundColor(this.theme.field)
                  .onChange((value: string) => this.form.alterId = value); }.width('100%');
              }
              if (this.form.type === 'vmess' || this.form.type === 'vless' || this.form.type === 'trojan') {
                Column() { this.label('传输方式'); Select([{ value: 'tcp' }, { value: 'ws' }]).value(this.form.network).selected(this.form.network === 'ws' ? 1 : 0)
                  .height(38).width('100%').font({ size: this.theme.font(13), family: this.theme.fontFamily }).onSelect((index: number) => this.form.network = index === 1 ? 'ws' : 'tcp'); }.width('100%');
                if (this.form.type === 'vmess' || this.form.type === 'vless') {
                  Row() { Text('TLS').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.tls }).selectedColor(this.theme.primary)
                    .onChange((value: boolean) => this.form.tls = value); }.width('100%');
                }
                if (this.form.tls || this.form.type === 'trojan') {
                  Column() { this.label('TLS 服务器名称（SNI，可选）'); TextInput({ text: this.form.serverName }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
                    .onChange((value: string) => this.form.serverName = value); }.width('100%');
                  Row() { Text('跳过证书校验').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.skipCertVerify }).selectedColor(this.theme.primary)
                    .onChange((value: boolean) => this.form.skipCertVerify = value); }.width('100%');
                }
                if (this.form.network === 'ws') {
                  Column() { this.label('WebSocket 路径'); TextInput({ text: this.form.wsPath }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
                    .onChange((value: string) => this.form.wsPath = value); }.width('100%');
                  Column() { this.label('WebSocket Host（可选）'); TextInput({ text: this.form.wsHost }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
                    .onChange((value: string) => this.form.wsHost = value); }.width('100%');
                }
              }
            }
            if (this.form.type === 'vless') Text('支持标准 VLESS TCP / TLS / WebSocket 和 UDP；Reality、Vision、XUDP 及额外加密尚不支持。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
            if (this.form.type !== 'reject') Row() {
              Text('UDP').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.udp }).selectedColor(this.theme.primary)
                .onChange((value: boolean) => this.form.udp = value);
            }.width('100%');
          }.width('100%');
        }.width('100%').layoutWeight(1).align(Alignment.Top);
      }
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').maxLines(3);
      Row({ space: 10 }) {
        Blank(); Button('取消', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary).backgroundColor(this.theme.field)
          .enabled(!this.saving).onClick(() => this.controller?.close());
        Button('完成节点编辑', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary)
          .enabled(!this.saving).onClick(() => this.save());
      }.width('100%');
    }.width('92%').height('88%').constraintSize({ maxWidth: 840 }).padding(22).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface)
      .onAreaChange((_old: Area, area: Area) => this.dialogWidth = Number(area.width));
  }
}
