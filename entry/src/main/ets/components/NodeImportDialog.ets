import { VergePalette } from '../theme/VergeTheme';
import { ClashNativeCore } from '../service/ClashNativeCore';
import { NodeLinkImport, emptyNodeLinkImport } from '../service/NodeLinkTypes';
import { EditorObjectView } from '../service/ObjectEditsTypes';

@CustomDialog
export struct NodeImportDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  initialContent: string = '';
  createProfile: boolean = true;
  targetName: string = '';
  occupiedNames: string[] = [];
  onImport: (result: NodeLinkImport, name: string) => Promise<void> = async (_result: NodeLinkImport, _name: string): Promise<void> => {};
  @State text: string = '';
  @State name: string = '节点链接配置';
  @State result: NodeLinkImport = emptyNodeLinkImport();
  @State error: string = '';
  @State saving: boolean = false;
  private native: ClashNativeCore = new ClashNativeCore();

  aboutToAppear(): void {
    this.text = this.initialContent;
    if (this.text.trim()) this.preview();
  }
  private preview(): void {
    this.result = emptyNodeLinkImport(); this.error = '';
    try { this.result = this.native.shareLinks(this.text, this.occupiedNames); }
    catch (error) { this.error = (error as Error).message; }
  }
  private async save(): Promise<void> {
    if (this.saving || !this.result.nodes.length) return;
    if (this.createProfile && !this.name.trim()) { this.error = '请输入配置名称'; return; }
    this.saving = true; this.error = '';
    try { await this.onImport(this.result, this.name.trim()); this.controller?.close(); }
    catch (error) { this.error = (error as Error).message || '节点未能导入，原配置已保留'; }
    finally { this.saving = false; }
  }
  build() {
    Column({ space: 14 }) {
      Row() {
        Text('导入节点链接').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Text('本地解析').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
      }.width('100%');
      Text(this.createProfile ? '粘贴 SS、VMess、VLESS、Trojan、HTTP 或 SOCKS5 链接，每行一个；也支持 Base64 节点列表。导入后创建独立配置并启用。' :
        `添加到「${this.targetName}」的节点草稿。添加后可在“代理组”中选择这些节点，最后点击“保存并应用”。重名自动添加序号。`)
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Scroll() {
        Column({ space: 12 }) {
          if (this.createProfile) {
            TextInput({ text: this.name, placeholder: '配置名称' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).accessibilityText('节点链接配置名称')
              .height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field).enabled(!this.saving)
              .onChange((value: string) => this.name = value);
          }
          TextArea({ text: this.text, placeholder: 'ss://…\nvmess://…\nvless://…\ntrojan://…\nhttps://…\nsocks5://…' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).accessibilityText('节点分享链接')
            .height(190).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontFamily('monospace').borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field).enabled(!this.saving)
            .onChange((value: string) => { if (value !== this.text) { this.text = value; this.result = emptyNodeLinkImport(); this.error = ''; } });
          Row() {
            Text(this.result.nodes.length ? `已解析 ${this.result.nodes.length} 个节点` : '预览仅显示名称和地址，密码不会列出。')
              .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.result.nodes.length ? this.theme.success : this.theme.textMuted).layoutWeight(1);
            Button('解析并预览', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
              .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving).onClick(() => this.preview());
          }.width('100%');
          ForEach(this.result.nodes.slice(0, 100), (item: EditorObjectView) => {
            Column({ space: 4 }) {
              Text(item.name).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis }).width('100%');
              Text(`${item.type.toUpperCase()} · ${item.server}:${item.port}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted)
                .maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis }).width('100%');
            }.padding(12).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field).width('100%');
          }, (item: EditorObjectView) => item.name);
          if (this.result.nodes.length > 100) Text(`仅预览前 100 个节点，将导入全部 ${this.result.nodes.length} 个。`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').maxLines(3);
      Row({ space: 10 }) {
        Blank();
        Button('取消', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary)
          .backgroundColor(this.theme.field).enabled(!this.saving).onClick(() => this.controller?.close());
        Button(this.saving ? '导入中…' : this.createProfile ? '创建并启用' : '添加到节点列表', { type: ButtonType.Normal })
          .height(36).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary)
          .enabled(!this.saving && this.result.nodes.length > 0).onClick(() => this.save());
      }.width('100%');
    }.width('92%').constraintSize({ maxWidth: 820 }).height('84%').padding(24).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface);
  }
}
