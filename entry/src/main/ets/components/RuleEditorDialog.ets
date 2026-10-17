import { VergePalette } from '../theme/VergeTheme';
import { RuleEdits, RuleEditorSnapshot } from '../service/RuleEditsTypes';

interface EditorRuleRow { index: number; text: string; removed: boolean; }
const RULE_TYPES: string[] = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD', 'DOMAIN-REGEX',
  'IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'GEOIP', 'SRC-GEOIP', 'GEOSITE', 'IP-ASN', 'SRC-IP-ASN', 'DST-PORT', 'NETWORK', 'RULE-SET', 'MATCH'];

@CustomDialog
export struct RuleEditorDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  profileName: string = '';
  initial: RuleEdits = { version: 1, prepend: [], append: [], remove: [] };
  snapshot: RuleEditorSnapshot = { error: '', rules: [], effective: [], policies: ['DIRECT', 'REJECT'], providers: [] };
  onValidate: (edits: RuleEdits) => void = (_edits: RuleEdits): void => {};
  onSave: (edits: RuleEdits) => Promise<void> = async (_edits: RuleEdits): Promise<void> => {};
  onCopy: (text: string) => void = (_text: string): void => {};
  @State prepend: string[] = [];
  @State append: string[] = [];
  @State excluded: string[] = [];
  @State lane: number = 0;
  @State query: string = '';
  @State maximum: number = 100;
  @State kind: string = 'DOMAIN-SUFFIX';
  @State payload: string = '';
  @State target: string = 'DIRECT';
  @State noResolve: boolean = false;
  @State rawMode: boolean = false;
  @State raw: string = '';
  @State editing: number = -1;
  @State editingLane: number = 0;
  @State replacedOriginal: string = '';
  @State error: string = '';
  @State saving: boolean = false;
  @State dialogWidth: number = 900;

  aboutToAppear(): void { this.prepend = [...this.initial.prepend]; this.append = [...this.initial.append]; this.excluded = [...this.initial.remove]; }
  private edits(): RuleEdits { return { version: 1, prepend: [...this.prepend], append: [...this.append], remove: [...this.excluded] }; }
  private commit(edits: RuleEdits): boolean {
    try {
      this.onValidate(edits); this.prepend = edits.prepend; this.append = edits.append; this.excluded = edits.remove; this.error = ''; return true;
    } catch (error) { this.error = (error as Error).message; return false; }
  }
  private rows(): EditorRuleRow[] {
    const source: string[] = this.lane === 0 ? this.prepend : this.lane === 1 ? this.snapshot.rules : this.lane === 2 ? this.append : this.excluded;
    const query: string = this.query.trim().toLowerCase();
    return source.map((text: string, index: number): EditorRuleRow => ({ index, text, removed: this.lane === 3 || (this.lane === 1 && this.excluded.indexOf(text) >= 0) }))
      .filter((row: EditorRuleRow) => row.text.toLowerCase().indexOf(query) >= 0);
  }
  private cancelEdit(): void { this.editing = -1; this.raw = ''; this.payload = ''; this.replacedOriginal = ''; this.rawMode = false; }
  private edit(row: EditorRuleRow, original: boolean = false): void {
    this.editing = original ? -1 : row.index; this.editingLane = this.lane;
    this.rawMode = true; this.raw = row.text; this.replacedOriginal = original ? row.text : '';
    if (original) this.lane = 0;
  }
  private add(): void {
    const raw: string = this.rawMode ? this.raw.trim() : `${this.kind},${this.kind === 'MATCH' ? '' : `${this.payload.trim()},`}${this.target}${this.noResolve && this.kind !== 'MATCH' ? ',no-resolve' : ''}`;
    if (!raw || (!this.rawMode && this.kind !== 'MATCH' && !this.payload.trim())) { this.error = '请输入匹配内容或完整规则'; return; }
    const edits: RuleEdits = this.edits();
    const lane: number = this.editing >= 0 ? this.editingLane : this.lane === 2 ? 2 : 0;
    const list: string[] = lane === 0 ? edits.prepend : edits.append;
    if (this.editing >= 0) list[this.editing] = raw; else list.push(raw);
    if (this.replacedOriginal && edits.remove.indexOf(this.replacedOriginal) < 0) edits.remove.push(this.replacedOriginal);
    if (this.commit(edits)) { this.lane = lane; this.cancelEdit(); }
  }
  private action(row: EditorRuleRow, command: string): void {
    if (command === 'copy') { this.onCopy(row.text); return; }
    if (command === 'edit') { this.edit(row, this.lane === 1); return; }
    const edits: RuleEdits = this.edits();
    if (this.lane === 1 || this.lane === 3) {
      edits.remove = row.removed ? edits.remove.filter((text: string) => text !== row.text) : [...edits.remove, row.text];
    } else {
      const list: string[] = this.lane === 0 ? edits.prepend : edits.append;
      list.splice(row.index, 1);
      if (command === 'other') (this.lane === 0 ? edits.append : edits.prepend).push(row.text);
      else if (command !== 'delete') {
        const position: number = command === 'top' ? 0 : command === 'bottom' ? list.length : command === 'up' ? Math.max(0, row.index - 1) : Math.min(list.length, row.index + 1);
        list.splice(position, 0, row.text);
      }
    }
    if (this.commit(edits)) this.cancelEdit();
  }
  private async save(): Promise<void> {
    if (this.saving) return;
    this.saving = true; this.error = '';
    try {
      if (this.editing >= 0 || this.raw.trim() || this.payload.trim()) throw new Error('请先添加或确认正在编辑的规则');
      await this.onSave(this.edits()); this.controller?.close();
    } catch (error) { this.error = (error as Error).message || '规则未能保存'; }
    finally { this.saving = false; }
  }

  @Builder
  private button(label: string, callback: () => void, primary: boolean = false) {
    Button(label, { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).enabled(!this.saving)
      .fontColor(primary ? this.theme.onPrimary : this.theme.primary).backgroundColor(primary ? this.theme.primary : this.theme.primarySoft).onClick(callback);
  }
  @Builder
  private rowMenu(row: EditorRuleRow) {
    Menu() {
      if (this.lane !== 3) MenuItem({ content: this.lane === 1 ? '前置覆写此规则' : '编辑规则' }).onClick(() => this.action(row, 'edit'));
      MenuItem({ content: '复制规则' }).onClick(() => this.action(row, 'copy'));
      if (this.lane === 1 || this.lane === 3) {
        MenuItem({ content: row.removed ? '恢复原始规则' : '排除此原始规则' }).onClick(() => this.action(row, 'exclude'));
      } else {
        MenuItem({ content: '上移' }).enabled(row.index > 0).onClick(() => this.action(row, 'up'));
        MenuItem({ content: '下移' }).enabled(row.index + 1 < (this.lane === 0 ? this.prepend.length : this.append.length)).onClick(() => this.action(row, 'down'));
        MenuItem({ content: '移到顶部' }).onClick(() => this.action(row, 'top'));
        MenuItem({ content: '移到底部' }).onClick(() => this.action(row, 'bottom'));
        MenuItem({ content: this.lane === 0 ? '移到后置规则' : '移到前置规则' }).onClick(() => this.action(row, 'other'));
        MenuItem({ content: '删除规则' }).contentFontColor(this.theme.danger).onClick(() => this.action(row, 'delete'));
      }
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE).enabled(!this.saving);
  }
  @Builder
  private form() {
    Column({ space: 10 }) {
      Row() {
        Text(this.editing >= 0 ? '编辑自定义规则' : this.replacedOriginal ? '覆写原始规则' : '添加自定义规则').fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).layoutWeight(1);
        Button(this.rawMode ? '使用表单' : '使用完整规则', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .enabled(!this.saving).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
          .onClick(() => { this.rawMode = !this.rawMode; this.raw = ''; });
      }.width('100%');
      if (this.rawMode) {
        TextInput({ text: this.raw, placeholder: '例如 DOMAIN-SUFFIX,example.com,DIRECT' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38)
          .backgroundColor(this.theme.surface).enabled(!this.saving).onChange((value: string) => this.raw = value);
      } else {
        GridRow({ columns: this.dialogWidth < 640 ? 1 : 6, gutter: 10 }) {
          GridCol({ span: this.dialogWidth < 640 ? 1 : 2 }) {
          Select(RULE_TYPES.map((text: string): SelectOption => ({ value: text }))).value(this.kind).selected(RULE_TYPES.indexOf(this.kind))
            .height(38).font({ size: this.theme.font(12), family: this.theme.fontFamily }).width('100%').enabled(!this.saving)
            .onSelect((index: number) => { this.kind = RULE_TYPES[index]; this.noResolve = false; });
          }
          if (this.kind !== 'MATCH') {
            GridCol({ span: this.dialogWidth < 640 ? 1 : 2 }) {
              TextInput({ text: this.payload, placeholder: this.kind === 'RULE-SET' ? '规则集合名称' : '匹配内容' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).height(38).width('100%')
                .backgroundColor(this.theme.surface).enabled(!this.saving).onChange((value: string) => this.payload = value);
            }
          }
          GridCol({ span: this.dialogWidth < 640 ? 1 : this.kind === 'MATCH' ? 4 : 2 }) {
          Select(this.snapshot.policies.map((text: string): SelectOption => ({ value: text }))).value(this.target).selected(this.snapshot.policies.indexOf(this.target))
            .height(38).font({ size: this.theme.font(12), family: this.theme.fontFamily }).width('100%').enabled(!this.saving)
            .onSelect((index: number) => this.target = this.snapshot.policies[index]);
          }
        }.width('100%');
        if (['IP-CIDR', 'IP-CIDR6', 'SRC-IP-CIDR', 'SRC-IP-CIDR6', 'GEOIP', 'SRC-GEOIP', 'IP-ASN', 'SRC-IP-ASN', 'RULE-SET'].indexOf(this.kind) >= 0) {
          Row({ space: 8 }) {
            Checkbox().select(this.noResolve).selectedColor(this.theme.primary).enabled(!this.saving).onChange((value: boolean) => this.noResolve = value);
            Text('no-resolve · 不为此规则触发域名解析').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
          }.width('100%');
        }
      }
      Row({ space: 10 }) {
        Text(this.lane === 2 ? '添加到后置规则' : '添加到前置规则').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).layoutWeight(1);
        if (this.editing >= 0 || this.replacedOriginal) this.button('取消编辑', () => this.cancelEdit());
        Button(this.editing >= 0 ? '确认修改' : '添加规则', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .enabled(!this.saving).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).onClick(() => this.add());
      }.width('100%');
    }.padding(12).borderRadius(this.theme.radius(6)).backgroundColor(this.theme.field).width('100%');
  }
  build() {
    Column({ space: 12 }) {
      Row() {
        Text('编辑规则').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        this.button('取消', (): void => { this.controller?.close(); });
      }.width('100%');
      Text(`${this.profileName} · 自定义规则在订阅更新后保留；使用中的配置保存后立即应用。`).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Row({ space: 8 }) {
        ForEach([0, 1, 2, 3], (value: number) => {
          Button(value === 0 ? `前置规则 ${this.prepend.length}` : value === 1 ? `原始规则 ${this.snapshot.rules.length}` : value === 2 ? `后置规则 ${this.append.length}` : `排除项 ${this.excluded.length}`,
            { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).enabled(!this.saving)
            .fontColor(this.lane === value ? this.theme.onPrimary : this.theme.primary).backgroundColor(this.lane === value ? this.theme.primary : this.theme.primarySoft)
            .onClick(() => { this.lane = value; this.maximum = 100; this.query = ''; });
        }, (value: number) => `${value}`);
      }.width('100%');
      Text(this.lane === 0 ? '前置规则优先于订阅规则，按从上到下的顺序匹配。' : this.lane === 1 ? `已排除 ${this.excluded.length} 种原始规则；排除项按完整文本匹配，原文件保持不变。` :
        this.lane === 2 ? '后置规则在订阅规则之后匹配；前面已有 MATCH 时，后置规则不会被命中。' :
        '按完整文本排除原始规则；订阅更新后暂未出现的排除项也可在此恢复。').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      if (this.lane === 0 || this.lane === 2 || this.editing >= 0 || this.replacedOriginal) this.form();
      TextInput({ text: this.query, placeholder: '搜索规则、匹配内容或策略' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
        .onChange((value: string) => { this.query = value; this.maximum = 100; });
      Scroll() {
        Column({ space: 6 }) {
          ForEach(this.rows().slice(0, this.maximum), (row: EditorRuleRow) => {
            Row({ space: 10 }) {
              Text(`${row.index + 1}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width(30);
              Text(row.text).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(row.removed ? this.theme.textMuted : this.theme.text).layoutWeight(1)
                .maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
              if (row.removed) Text('已排除').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning);
              Button('•••', { type: ButtonType.Normal }).width(30).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).backgroundColor(Color.Transparent)
                .fontColor(this.theme.textSecondary)
                .enabled(!this.saving).accessibilityText(`规则 ${row.index + 1} 操作`).bindMenu(this.rowMenu(row));
            }.width('100%').padding(10).borderRadius(this.theme.radius(5)).backgroundColor(this.theme.field)
              .bindContextMenu(this.rowMenu(row), ResponseType.RightClick);
          }, (row: EditorRuleRow) => `${this.lane}/${row.index}/${row.text}/${row.removed}`);
          if (this.rows().length === 0) Text('暂无匹配规则').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).padding(20);
          if (this.rows().length > this.maximum) Button(`显示更多（${this.maximum} / ${this.rows().length}）`, { type: ButtonType.Normal })
            .height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.maximum += 100);
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').maxLines(3);
      Row({ space: 10 }) {
        this.button('清空自定义规则', () => { this.commit({ version: 1, prepend: [], append: [], remove: [] }); this.cancelEdit(); });
        Blank();
        Button(this.saving ? '保存中…' : '保存规则', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .enabled(!this.saving).fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).onClick(() => this.save());
      }.width('100%');
    }.width('92%').height('88%').constraintSize({ maxWidth: 1080 }).padding(22).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface)
      .onAreaChange((_old: Area, area: Area) => this.dialogWidth = Number(area.width));
  }
}
