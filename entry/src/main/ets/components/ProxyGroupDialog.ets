import { VergePalette } from '../theme/VergeTheme';
import { ProfileStore } from '../service/ProfileStore';
import { ProxyGroupForm, EditorObjectView, defaultProxyGroupForm } from '../service/ObjectEditsTypes';

interface GroupFormPatch {
  name: string; type: string; proxies: string[]; use: string[]; 'include-all': null; 'include-all-proxies': boolean; 'include-all-providers': boolean;
  'disable-udp': boolean; lazy: boolean; filter: string | null; 'exclude-filter': string | null; 'default-selected': string | null;
  url?: string; interval?: number; timeout?: number; tolerance?: number; 'expected-status'?: string; strategy?: string;
}
const GROUP_TYPES: string[] = ['select', 'url-test', 'fallback', 'load-balance'];
const GROUP_STRATEGIES: string[] = ['consistent-hashing', 'round-robin', 'sticky-sessions'];
export const NEW_GROUP_CONTENT: string = '{"name":"","type":"select","proxies":["DIRECT"]}';

@CustomDialog
export struct ProxyGroupDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  store?: ProfileStore;
  title: string = '新建代理组';
  initialContent: string = NEW_GROUP_CONTENT;
  lockName: boolean = false;
  choices: string[] = ['DIRECT', 'REJECT'];
  providerChoices: string[] = [];
  onSave: (item: EditorObjectView) => void = (_item: EditorObjectView): void => {};
  onCopy: (text: string) => void = (_text: string): void => {};
  @State form: ProxyGroupForm = defaultProxyGroupForm();
  @State advanced: boolean = false;
  @State raw: string = '';
  @State error: string = '';
  @State memberIndex: number = 0;
  @State providerIndex: number = 0;
  @State saving: boolean = false;
  @State dialogWidth: number = 920;
  private base: string = '';
  private identity: string = '';

  private normalized(form: ProxyGroupForm): ProxyGroupForm {
    let type: string = form.type.toLowerCase();
    if (type === 'selector') type = 'select'; else if (type === 'urltest') type = 'url-test'; else if (type === 'loadbalance') type = 'load-balance';
    form.type = type; return form;
  }
  aboutToAppear(): void {
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const draft = this.store.groupDraft(this.initialContent, '', false);
      this.base = draft.item.content; this.identity = draft.item.name; this.form = this.normalized(draft.form);
    } catch (error) { this.error = (error as Error).message; }
  }
  private memberChoices(): string[] { return this.choices.filter((name: string) => name !== this.form.name && this.form.members.indexOf(name) < 0); }
  private remainingProviders(): string[] { return this.providerChoices.filter((name: string) => this.form.providers.indexOf(name) < 0); }
  private addMember(): void {
    const name: string | undefined = this.memberChoices()[this.memberIndex];
    if (name) { this.form.members = [...this.form.members, name]; this.memberIndex = 0; }
  }
  private addProvider(): void {
    const name: string | undefined = this.remainingProviders()[this.providerIndex];
    if (name) { this.form.providers = [...this.form.providers, name]; this.providerIndex = 0; }
  }
  private move(index: number, destination: number): void {
    const members: string[] = [...this.form.members]; const item: string | undefined = members[index]; if (item === undefined) return;
    members.splice(index, 1); members.splice(Math.max(0, Math.min(members.length, destination)), 0, item); this.form.members = members;
  }
  private remove(index: number): void { this.form.members = this.form.members.filter((_name: string, current: number) => current !== index); this.memberIndex = 0; }
  private integer(text: string, minimum: number, maximum: number): number {
    if (!/^\d{1,7}$/.test(text.trim()) || Number(text) < minimum || Number(text) > maximum) throw new Error(`请输入 ${minimum} 至 ${maximum} 的整数`);
    return Number(text);
  }
  private patch(): string {
    const patch: GroupFormPatch = { name: this.lockName ? this.identity : this.form.name.trim(), type: this.form.type, proxies: this.form.members, use: this.form.providers,
      'include-all': null, 'include-all-proxies': this.form.includeAllProxies, 'include-all-providers': this.form.includeAllProviders,
      'disable-udp': this.form.disableUdp, lazy: this.form.lazy, filter: this.form.filter || null, 'exclude-filter': this.form.excludeFilter || null,
      'default-selected': this.form.type === 'load-balance' ? null : this.form.defaultSelected || null,
      'expected-status': this.form.type === 'select' ? undefined : this.form.expectedStatus.trim() || '*' };
    if (this.form.type !== 'select') {
      patch.url = this.form.url.trim(); patch.interval = this.integer(this.form.interval, 0, 604800); patch.timeout = this.integer(this.form.timeout, 100, 60000);
      patch.tolerance = this.integer(this.form.tolerance, 0, 60000);
    }
    if (this.form.type === 'load-balance') patch.strategy = this.form.strategy;
    return JSON.stringify(patch);
  }
  private mode(): void {
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const draft = this.advanced ? this.store.groupDraft(this.raw, '', false) : this.store.groupDraft(this.base, this.patch(), false);
      this.base = draft.item.content; this.raw = draft.item.content;
      if (this.advanced) this.form = this.normalized(draft.form);
      this.advanced = !this.advanced; this.error = '';
    } catch (error) { this.error = (error as Error).message; }
  }
  private save(): void {
    if (this.saving) return;
    this.saving = true; this.error = '';
    try {
      if (!this.store) throw new Error('配置目录不可用');
      const result = this.advanced ? this.store.groupDraft(this.raw) : this.store.groupDraft(this.base, this.patch());
      if (this.lockName && result.item.name !== this.identity) throw new Error('编辑现有代理组时请保留名称；需要改名可创建副本');
      this.onSave(result.item); this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '代理组未能完成编辑'; }
    finally { this.saving = false; }
  }
  @Builder
  private label(text: string) { Text(text).fontSize(11).fontColor(this.theme.textSecondary).width('100%').margin({ bottom: 6 }); }
  @Builder
  private memberMenu(name: string, index: number) {
    Menu() {
      MenuItem({ content: '复制成员名称' }).onClick(() => this.onCopy(name));
      MenuItem({ content: '上移' }).enabled(index > 0).onClick(() => this.move(index, index - 1));
      MenuItem({ content: '下移' }).enabled(index + 1 < this.form.members.length).onClick(() => this.move(index, index + 1));
      MenuItem({ content: '移到顶部' }).onClick(() => this.move(index, 0));
      MenuItem({ content: '移到底部' }).onClick(() => this.move(index, this.form.members.length - 1));
      MenuItem({ content: '移除成员' }).contentFontColor(this.theme.danger).onClick(() => this.remove(index));
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE)
  }
  build() {
    Column({ space: 12 }) {
      Row() {
        Text(this.title).fontSize(20).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button(this.advanced ? '表单编辑' : '高级配置', { type: ButtonType.Normal }).height(32).fontSize(12).borderRadius(5)
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving).onClick(() => this.mode());
      }.width('100%');
      Text('完成编辑后返回列表；成员、规则引用和循环依赖在“保存并应用”时统一校验。').fontSize(11).fontColor(this.theme.textMuted).width('100%');
      if (this.advanced) {
        TextArea({ text: this.raw, placeholder: '单个代理组的 YAML / JSON 映射' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(12).fontFamily('monospace').backgroundColor(this.theme.field)
          .borderRadius(6).width('100%').layoutWeight(1).onChange((value: string) => this.raw = value);
      } else {
        Scroll() {
          Column({ space: 14 }) {
            GridRow({ columns: this.dialogWidth < 640 ? 1 : 2, gutter: 12 }) {
              GridCol() { Column() { this.label('代理组名称'); TextInput({ text: this.form.name, placeholder: '输入名称' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13)
                .backgroundColor(this.theme.field).enabled(!this.lockName).onChange((value: string) => this.form.name = value); }.width('100%'); }
              GridCol() { Column() { this.label('类型'); Select(GROUP_TYPES.map((value: string): SelectOption => ({ value }))).value(this.form.type).selected(GROUP_TYPES.indexOf(this.form.type))
                .height(38).width('100%').font({ size: 13 }).onSelect((index: number) => this.form.type = GROUP_TYPES[index]); }.width('100%'); }
            }.width('100%');
            if (this.lockName) Text('名称用于规则引用；需要改名可创建副本，再更新引用。').fontSize(11).fontColor(this.theme.textMuted).width('100%');
            Column({ space: 8 }) {
              Text(`成员 ${this.form.members.length} · 按列表顺序使用`).fontSize(13).fontColor(this.theme.text).width('100%');
              if (this.memberChoices().length > 0) Row({ space: 10 }) {
                Select(this.memberChoices().map((value: string): SelectOption => ({ value }))).value(this.memberChoices()[this.memberIndex] || '').selected(this.memberIndex)
                  .height(36).font({ size: 12 }).layoutWeight(1).onSelect((index: number) => this.memberIndex = index);
                Button('添加成员', { type: ButtonType.Normal }).height(32).fontSize(12).borderRadius(5).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.addMember());
              }.width('100%');
              ForEach(this.form.members, (name: string, index: number) => {
                Row({ space: 8 }) {
                  Text(`${index + 1}`).fontSize(11).fontColor(this.theme.textMuted).width(26);
                  Text(name).fontSize(12).fontColor(this.theme.text).layoutWeight(1).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                  Button('↑', { type: ButtonType.Normal }).width(30).height(28).fontSize(13).fontColor(this.theme.textSecondary).backgroundColor(Color.Transparent).enabled(index > 0).onClick(() => this.move(index, index - 1));
                  Button('↓', { type: ButtonType.Normal }).width(30).height(28).fontSize(13).fontColor(this.theme.textSecondary).backgroundColor(Color.Transparent).enabled(index + 1 < this.form.members.length).onClick(() => this.move(index, index + 1));
                  Button('移除', { type: ButtonType.Normal }).height(28).fontSize(11).fontColor(this.theme.danger).backgroundColor(Color.Transparent).onClick(() => this.remove(index));
                }.width('100%').padding(8).backgroundColor(this.theme.field).borderRadius(5).bindContextMenu(this.memberMenu(name, index), ResponseType.RightClick);
              }, (name: string, index: number) => `${index}/${name}`);
            }.width('100%');
            Column({ space: 8 }) {
              Text(`代理集合 ${this.form.providers.length}`).fontSize(13).fontColor(this.theme.text).width('100%');
              if (this.remainingProviders().length > 0) Row({ space: 10 }) {
                Select(this.remainingProviders().map((value: string): SelectOption => ({ value }))).value(this.remainingProviders()[this.providerIndex] || '').selected(this.providerIndex)
                  .height(36).font({ size: 12 }).layoutWeight(1).onSelect((index: number) => this.providerIndex = index);
                Button('添加集合', { type: ButtonType.Normal }).height(32).fontSize(12).borderRadius(5).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.addProvider());
              }.width('100%');
              ForEach(this.form.providers, (name: string) => {
                Row() { Text(name).fontSize(12).fontColor(this.theme.text).layoutWeight(1); Button('移除集合', { type: ButtonType.Normal }).height(28).fontSize(11)
                  .fontColor(this.theme.danger).backgroundColor(Color.Transparent).onClick(() => { this.form.providers = this.form.providers.filter((current: string) => current !== name); this.providerIndex = 0; });
                }.width('100%').padding(8).backgroundColor(this.theme.field).borderRadius(5);
              }, (name: string) => name);
              if (!this.providerChoices.length) Text('当前配置未定义代理集合').fontSize(11).fontColor(this.theme.textMuted).width('100%');
            }.width('100%');
            Row() { Text('包含全部配置节点').fontSize(13).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.includeAllProxies }).selectedColor(this.theme.primary)
              .onChange((value: boolean) => this.form.includeAllProxies = value); }.width('100%');
            Row() { Text('包含全部代理集合').fontSize(13).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.includeAllProviders }).selectedColor(this.theme.primary)
              .onChange((value: boolean) => this.form.includeAllProviders = value); }.width('100%');
            GridRow({ columns: this.dialogWidth < 640 ? 1 : 2, gutter: 12 }) {
              GridCol() { Column() { this.label('名称筛选表达式（可选）'); TextInput({ text: this.form.filter }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).backgroundColor(this.theme.field)
                .onChange((value: string) => this.form.filter = value); }.width('100%'); }
              GridCol() { Column() { this.label('名称排除表达式（可选）'); TextInput({ text: this.form.excludeFilter }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).backgroundColor(this.theme.field)
                .onChange((value: string) => this.form.excludeFilter = value); }.width('100%'); }
            }.width('100%');
            if (this.form.type !== 'select') {
              Column() { this.label('健康检查地址'); TextInput({ text: this.form.url }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).backgroundColor(this.theme.field)
                .onChange((value: string) => this.form.url = value); }.width('100%');
              GridRow({ columns: this.dialogWidth < 640 ? 1 : 3, gutter: 12 }) {
                GridCol() { Column() { this.label('检查间隔（秒，0 关闭）'); TextInput({ text: this.form.interval }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).type(InputType.Number).backgroundColor(this.theme.field)
                  .onChange((value: string) => this.form.interval = value); }.width('100%'); }
                GridCol() { Column() { this.label('超时（毫秒）'); TextInput({ text: this.form.timeout }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).type(InputType.Number).backgroundColor(this.theme.field)
                  .onChange((value: string) => this.form.timeout = value); }.width('100%'); }
                GridCol() { Column() { this.label('延迟容差（毫秒）'); TextInput({ text: this.form.tolerance }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).type(InputType.Number).backgroundColor(this.theme.field)
                  .onChange((value: string) => this.form.tolerance = value); }.width('100%'); }
              }.width('100%');
              Column() { this.label('预期状态码'); TextInput({ text: this.form.expectedStatus, placeholder: '* 或 204/200-299' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).backgroundColor(this.theme.field)
                .onChange((value: string) => this.form.expectedStatus = value); }.width('100%');
              Row() { Text('仅在使用时检查（lazy）').fontSize(13).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.lazy }).selectedColor(this.theme.primary)
                .onChange((value: boolean) => this.form.lazy = value); }.width('100%');
            }
            if (this.form.type === 'load-balance') {
              Column() { this.label('分配策略'); Select(GROUP_STRATEGIES.map((value: string): SelectOption => ({ value }))).value(this.form.strategy).selected(GROUP_STRATEGIES.indexOf(this.form.strategy))
                .height(38).width('100%').font({ size: 13 }).onSelect((index: number) => this.form.strategy = GROUP_STRATEGIES[index]); }.width('100%');
            } else {
              Column() { this.label('默认选择（可选，无已保存选择时生效）'); TextInput({ text: this.form.defaultSelected }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(38).fontSize(13).backgroundColor(this.theme.field)
                .onChange((value: string) => this.form.defaultSelected = value); }.width('100%');
            }
            Row() { Text('禁用此组的 UDP').fontSize(13).fontColor(this.theme.text).layoutWeight(1); Toggle({ type: ToggleType.Switch, isOn: this.form.disableUdp }).selectedColor(this.theme.primary)
              .onChange((value: boolean) => this.form.disableUdp = value); }.width('100%');
          }.width('100%');
        }.width('100%').layoutWeight(1).align(Alignment.Top);
      }
      if (this.error) Text(this.error).fontSize(12).fontColor(this.theme.danger).width('100%').maxLines(3);
      Row({ space: 10 }) {
        Blank(); Button('取消', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5).fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).onClick(() => this.controller?.close());
        Button('完成代理组编辑', { type: ButtonType.Normal }).height(34).fontSize(12).borderRadius(5).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.saving).onClick(() => this.save());
      }.width('100%');
    }.width('92%').height('90%').constraintSize({ maxWidth: 920 }).padding(22).borderRadius(10).backgroundColor(this.theme.surface)
      .onAreaChange((_old: Area, area: Area) => this.dialogWidth = Number(area.width));
  }
}
