import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
import { ProfileStore } from '../service/ProfileStore';
import { ObjectEdits, ObjectSequenceEdits, ObjectSnapshotSection, ObjectEditorSnapshot, EditorObjectView, ObjectEditItem, emptyObjectEdits, emptyObjectSnapshot } from '../service/ObjectEditsTypes';
import { ProxyNodeDialog, NEW_NODE_CONTENT } from './ProxyNodeDialog';
import { ProxyGroupDialog, NEW_GROUP_CONTENT } from './ProxyGroupDialog';
import { NodeImportDialog } from './NodeImportDialog';
import { NodeLinkImport } from '../service/NodeLinkTypes';

interface ObjectEditorRow { item: EditorObjectView; index: number; removed: boolean; }

@CustomDialog
export struct ObjectEditorDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  store?: ProfileStore;
  profileName: string = '';
  sourceContent: string = '';
  ruleSettings: string = '';
  mergeSettings: string = '';
  providerContext: string = '';
  initial: ObjectEdits = emptyObjectEdits();
  initialKind: number = 0;
  focusName: string = '';
  onSave: (edits: ObjectEdits) => Promise<void> = async (_edits: ObjectEdits): Promise<void> => {};
  onCopy: (text: string, label: string) => void = (_text: string, _label: string): void => {};
  @State edits: ObjectEdits = emptyObjectEdits();
  @State snapshot: ObjectEditorSnapshot = emptyObjectSnapshot();
  @State kind: number = 0;
  @State lane: number = 1;
  @State query: string = '';
  @State maximum: number = 100;
  @State revision: number = 0;
  @State error: string = '';
  @State saving: boolean = false;
  @State dialogWidth: number = 1080;
  private child: CustomDialogController | null = null;
  private alive: boolean = true;

  private clone(edits: ObjectEdits): ObjectEdits {
    return { version: 1, proxies: { prepend: [...edits.proxies.prepend], append: [...edits.proxies.append], remove: [...edits.proxies.remove] },
      groups: { prepend: [...edits.groups.prepend], append: [...edits.groups.append], remove: [...edits.groups.remove] } };
  }
  private model(edits: ObjectEdits = this.edits, kind: number = this.kind): ObjectSequenceEdits { return kind === 0 ? edits.proxies : edits.groups; }
  private section(snapshot: ObjectEditorSnapshot = this.snapshot, kind: number = this.kind): ObjectSnapshotSection { return kind === 0 ? snapshot.proxies : snapshot.groups; }
  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter();
    this.kind = this.initialKind; this.edits = this.clone(this.initial);
    try {
      if (!this.store) throw new Error('配置目录不可用');
      this.snapshot = this.store.previewObjects(this.sourceContent, this.edits, this.ruleSettings, false, this.mergeSettings, this.providerContext);
      if (this.focusName) {
        const section = this.section(); this.query = this.focusName;
        this.lane = section.prepend.some((item: EditorObjectView) => item.name === this.focusName) ? 0 : section.append.some((item: EditorObjectView) => item.name === this.focusName) ? 2 : 1;
        if (![...section.original, ...section.prepend, ...section.append].some((item: EditorObjectView) => item.name === this.focusName)) this.error = this.kind === 0 ?
          '该节点可能来自代理集合；集合节点由集合源管理，可在此新增配置节点' : '该代理组未在当前配置中声明，可在此新建代理组';
      }
    } catch (error) { this.error = (error as Error).message; }
  }
  aboutToDisappear(): void { this.alive = false; this.child?.close(); dialogActivity.leave(this.dialogActivityId); }
  private count(kind: number): number {
    const section = this.section(this.snapshot, kind), model = this.model(this.edits, kind);
    return section.prepend.length + section.append.length + section.original.filter((item: EditorObjectView) => model.remove.indexOf(item.name) < 0).length;
  }
  private rows(): ObjectEditorRow[] {
    const section = this.section(), model = this.model();
    const items: EditorObjectView[] = this.lane === 0 ? section.prepend : this.lane === 1 ? section.original : this.lane === 2 ? section.append :
      model.remove.map((name: string): EditorObjectView => section.original.find((item: EditorObjectView) => item.name === name) ?? { name, type: '', server: '', port: '', content: '' });
    const query: string = this.query.trim().toLowerCase();
    return items.map((item: EditorObjectView, index: number): ObjectEditorRow => ({ item, index, removed: this.lane === 3 || (this.lane === 1 && model.remove.indexOf(item.name) >= 0) }))
      .filter((row: ObjectEditorRow) => `${row.item.name} ${row.item.type} ${row.item.server} ${row.item.port}`.toLowerCase().indexOf(query) >= 0);
  }
  private update(edits: ObjectEdits): void {
    if (!this.alive || !this.store) throw new Error('编辑窗口已关闭');
    const snapshot = this.store.previewObjects(this.sourceContent, edits, this.ruleSettings, false, this.mergeSettings, this.providerContext);
    const names: Set<string> = new Set();
    [0, 1].forEach((kind: number) => {
      const section = this.section(snapshot, kind), model = this.model(edits, kind);
      [...section.prepend, ...section.original.filter((item: EditorObjectView) => model.remove.indexOf(item.name) < 0), ...section.append].forEach((item: EditorObjectView) => {
        if (names.has(item.name)) throw new Error(`名称「${item.name}」已存在，请编辑原条目或使用其他名称`);
        names.add(item.name);
      });
    });
    this.edits = edits; this.snapshot = snapshot; this.revision++; this.error = '';
  }
  private finish(item: EditorObjectView, kind: number, lane: number, row?: ObjectEditorRow): void {
    const edits = this.clone(this.edits), model = this.model(edits, kind);
    const saved: ObjectEditItem = { name: item.name, content: item.content };
    let destination: number = lane === 2 ? 2 : 0;
    if (row && lane === 1) {
      if (model.remove.indexOf(row.item.name) < 0) model.remove.push(row.item.name);
      model.prepend = model.prepend.filter((current: ObjectEditItem) => current.name !== item.name);
      model.append = model.append.filter((current: ObjectEditItem) => current.name !== item.name); model.prepend.push(saved); destination = 0;
    } else if (row) (lane === 0 ? model.prepend : model.append)[row.index] = saved;
    else (destination === 0 ? model.prepend : model.append).push(saved);
    this.update(edits); this.kind = kind; this.lane = destination; this.query = ''; this.maximum = 100;
  }
  private open(row?: ObjectEditorRow, copy: boolean = false): void {
    if (this.saving || !this.store || (row && !row.item.content)) return;
    const kind: number = this.kind, lane: number = row && !copy ? this.lane : this.lane === 2 ? 2 : 0;
    let content: string = row?.item.content ?? (kind === 0 ? NEW_NODE_CONTENT : NEW_GROUP_CONTENT);
    if (copy && row) {
      let name: string = `${row.item.name} 副本`, counter: number = 2;
      while (this.snapshot.choices.indexOf(name) >= 0) name = `${row.item.name} 副本 ${counter++}`;
      const patch: string = JSON.stringify({ name });
      content = kind === 0 ? this.store.nodeDraft(content, patch, false).item.content : this.store.groupDraft(content, patch, false).item.content;
    }
    this.child?.close();
    if (kind === 0) {
      this.child = new CustomDialogController({ builder: ProxyNodeDialog({ store: this.store,
        choices: this.snapshot.choices,
        title: copy ? '复制节点' : row ? '编辑节点' : '新建节点', initialContent: content, lockName: row !== undefined && !copy,
        onSave: (item: EditorObjectView): void => { this.finish(item, kind, lane, copy ? undefined : row); } }), autoCancel: false, customStyle: true });
    } else {
      this.child = new CustomDialogController({ builder: ProxyGroupDialog({ store: this.store,
        title: copy ? '复制代理组' : row ? '编辑代理组' : '新建代理组', initialContent: content, lockName: row !== undefined && !copy,
        choices: this.snapshot.choices, providerChoices: this.snapshot.providers, onCopy: (text: string): void => this.onCopy(text, '成员名称'),
        onSave: (item: EditorObjectView): void => { this.finish(item, kind, lane, copy ? undefined : row); } }), autoCancel: false, customStyle: true });
    }
    this.child.open();
  }
  private action(row: ObjectEditorRow, command: string): void {
    try {
      if (command === 'edit') { this.open(row); return; }
      if (command === 'copy') { this.onCopy(row.item.content, this.kind === 0 ? '节点配置' : '代理组配置'); return; }
      if (command === 'duplicate') { this.open(row, true); return; }
      const edits = this.clone(this.edits), model = this.model(edits);
      if (this.lane === 1 || this.lane === 3) {
        if (row.removed) {
          model.remove = model.remove.filter((name: string) => name !== row.item.name);
          if (this.section().original.some((item: EditorObjectView) => item.name === row.item.name)) {
            model.prepend = model.prepend.filter((item: ObjectEditItem) => item.name !== row.item.name);
            model.append = model.append.filter((item: ObjectEditItem) => item.name !== row.item.name);
          }
        } else model.remove.push(row.item.name);
      } else {
        const list: ObjectEditItem[] = this.lane === 0 ? model.prepend : model.append; const removed: ObjectEditItem | undefined = list.splice(row.index, 1)[0];
        if (!removed) return;
        if (command === 'other') (this.lane === 0 ? model.append : model.prepend).push(removed);
        else if (command !== 'delete') list.splice(command === 'top' ? 0 : command === 'bottom' ? list.length : command === 'up' ? Math.max(0, row.index - 1) : Math.min(list.length, row.index + 1), 0, removed);
      }
      this.update(edits);
    } catch (error) { this.error = (error as Error).message; }
  }
  private importLinks(): void {
    if (this.saving || !this.store) return;
    const lane: number = this.lane === 2 ? 2 : 0;
    this.child?.close();
    this.child = new CustomDialogController({ builder: NodeImportDialog({ createProfile: false, targetName: this.profileName,
      occupiedNames: this.snapshot.choices, onImport: async (result: NodeLinkImport, _name: string): Promise<void> => {
        const edits = this.clone(this.edits), list = lane === 2 ? edits.proxies.append : edits.proxies.prepend;
        result.nodes.forEach((item: EditorObjectView) => list.push({ name: item.name, content: item.content }));
        this.update(edits); this.kind = 0; this.lane = lane; this.query = ''; this.maximum = 100;
      } }), autoCancel: false, customStyle: true });
    this.child.open();
  }
  private async save(): Promise<void> {
    if (this.saving) return;
    this.saving = true; this.error = '';
    try { await this.onSave(this.clone(this.edits)); this.controller?.close(); }
    catch (error) { this.error = (error as Error).message || '节点和代理组未能保存'; }
    finally { this.saving = false; }
  }
  @Builder
  private rowMenu(row: ObjectEditorRow) {
    Menu() {
      if (this.lane !== 3) {
        MenuItem({ content: '编辑条目' }).onClick(() => this.action(row, 'edit'));
        MenuItem({ content: '创建条目副本' }).onClick(() => this.action(row, 'duplicate'));
        MenuItem({ content: '复制条目配置' }).onClick(() => this.action(row, 'copy'));
      }
      MenuItem({ content: '复制名称' }).onClick(() => this.onCopy(row.item.name, '名称'));
      if (this.lane === 1 || this.lane === 3) {
        MenuItem({ content: row.removed ? '恢复原始条目' : '排除此原始条目' }).onClick(() => this.action(row, 'exclude'));
      } else {
        MenuItem({ content: '上移' }).enabled(row.index > 0).onClick(() => this.action(row, 'up'));
        MenuItem({ content: '下移' }).enabled(row.index + 1 < (this.lane === 0 ? this.model().prepend.length : this.model().append.length)).onClick(() => this.action(row, 'down'));
        MenuItem({ content: '移到顶部' }).onClick(() => this.action(row, 'top'));
        MenuItem({ content: '移到底部' }).onClick(() => this.action(row, 'bottom'));
        MenuItem({ content: this.lane === 0 ? '移到后置' : '移到前置' }).onClick(() => this.action(row, 'other'));
        MenuItem({ content: '删除条目' }).contentFontColor(this.theme.danger).onClick(() => this.action(row, 'delete'));
      }
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE).enabled(!this.saving);
  }
  build() {
    Column({ space: 12 }) {
      Row() {
        Text('节点与代理组').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button('取消', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.textSecondary).backgroundColor(this.theme.field)
          .enabled(!this.saving).onClick(() => this.controller?.close());
      }.width('100%');
      Text(`${this.profileName} · 修改在订阅更新后保留；原始配置保持不变。代理集合中的节点由集合源管理。`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      Row({ space: 10 }) {
        Button(`节点 ${this.count(0)}`, { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.kind === 0 ? this.theme.onPrimary : this.theme.primary)
          .backgroundColor(this.kind === 0 ? this.theme.primary : this.theme.primarySoft).enabled(!this.saving).onClick(() => { this.kind = 0; this.lane = 1; this.query = ''; this.maximum = 100; });
        Button(`代理组 ${this.count(1)}`, { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.kind === 1 ? this.theme.onPrimary : this.theme.primary)
          .backgroundColor(this.kind === 1 ? this.theme.primary : this.theme.primarySoft).enabled(!this.saving).onClick(() => { this.kind = 1; this.lane = 1; this.query = ''; this.maximum = 100; });
        Blank();
        if (this.kind === 0) Button('导入链接', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.saving).onClick(() => this.importLinks());
        Button(this.kind === 0 ? '新建节点' : '新建代理组', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
          .enabled(!this.saving).onClick(() => this.open());
      }.width('100%');
      Row({ space: 8 }) {
        ForEach([0, 1, 2, 3], (lane: number) => {
          Button(lane === 0 ? `前置 ${this.model().prepend.length}` : lane === 1 ? `原始 ${this.section().original.length}` : lane === 2 ? `后置 ${this.model().append.length}` : `排除项 ${this.model().remove.length}`,
            { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.lane === lane ? this.theme.onPrimary : this.theme.primary)
            .backgroundColor(this.lane === lane ? this.theme.primary : this.theme.primarySoft).enabled(!this.saving).onClick(() => { this.lane = lane; this.query = ''; this.maximum = 100; });
        }, (lane: number) => `${lane}`);
      }.width('100%');
      TextInput({ text: this.query, placeholder: '搜索名称、协议或服务器' }).fontColor(this.theme.text).placeholderColor(this.theme.textMuted).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).backgroundColor(this.theme.field)
        .enabled(!this.saving).onChange((value: string) => { this.query = value; this.maximum = 100; });
      Scroll() {
        Column({ space: 7 }) {
          ForEach(this.rows().slice(0, this.maximum), (row: ObjectEditorRow) => {
            Row({ space: 10 }) {
              Column({ space: 5 }) {
                Text(row.item.name).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(row.removed ? this.theme.textMuted : this.theme.text).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
                Text(`${row.item.type.toUpperCase()}${row.item.server ? ` · ${row.item.server}:${row.item.port}` : ''}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).maxLines(1).textOverflow({ overflow: TextOverflow.Ellipsis });
              }.layoutWeight(1).alignItems(HorizontalAlign.Start);
              if (row.removed) Text('已排除').fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning);
              if (this.lane !== 3) Button('编辑', { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
                .enabled(!this.saving).onClick(() => this.open(row));
              Button('•••', { type: ButtonType.Normal }).width(30).height(30).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).backgroundColor(Color.Transparent)
                .enabled(!this.saving).accessibilityText(`${row.item.name} 的条目操作`).bindMenu(this.rowMenu(row));
            }.width('100%').padding(12).borderRadius(this.theme.radius(6)).backgroundColor(this.theme.field).bindContextMenu(this.rowMenu(row), ResponseType.RightClick);
          }, (row: ObjectEditorRow) => `${this.revision}/${this.kind}/${this.lane}/${row.index}/${row.item.name}`);
          if (!this.rows().length) Text('暂无匹配条目').fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).padding(24);
          if (this.rows().length > this.maximum) Button(`显示更多（${this.maximum} / ${this.rows().length}）`, { type: ButtonType.Normal }).height(30).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
            .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).onClick(() => this.maximum += 100);
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%').maxLines(3);
      Row({ space: 10 }) {
        Button('清空全部修改', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5)).fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft)
          .enabled(!this.saving).onClick(() => { try { this.update(emptyObjectEdits()); } catch (error) { this.error = (error as Error).message; } });
        Blank(); Button(this.saving ? '保存中…' : '保存并应用', { type: ButtonType.Normal }).height(34).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(!this.saving).onClick(() => this.save());
      }.width('100%');
    }.width('92%').height('88%').constraintSize({ maxWidth: 1080 }).padding(22).borderRadius(this.theme.radius(10)).backgroundColor(this.theme.surface)
      .onAreaChange((_old: Area, area: Area) => this.dialogWidth = Number(area.width));
  }
}
