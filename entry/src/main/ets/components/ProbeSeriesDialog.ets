import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
import { ProbeSample, ProbeSeries, ProbeSeriesController, emptyProbeSeries, probeStatistics, probeFailureText, probeReport } from '../service/ProbeSeriesController';

@CustomDialog
export struct ProbeSeriesDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  nodeName: string = '';
  initialUrl: string = '';
  probe: (name: string, url: string) => Promise<number> = async (): Promise<number> => { throw new Error('内核不可用'); };
  isCurrent: () => boolean = (): boolean => true;
  onCopy: (text: string) => void = (_text: string): void => {};
  onFinished: () => void = (): void => {};
  @State url: string = '';
  @State count: number = 5;
  @State result: ProbeSeries = emptyProbeSeries();
  @State error: string = '';
  private runner?: ProbeSeriesController;
  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); this.url = this.initialUrl; this.runner = new ProbeSeriesController(this.probe, this.isCurrent); }
  aboutToDisappear(): void { this.runner?.dispose(); dialogActivity.leave(this.dialogActivityId); }
  private async start(): Promise<void> {
    this.error = '';
    try {
      await this.runner?.run(this.nodeName, this.url.trim(), this.count, (state: ProbeSeries): void => { this.result = state; });
      if (this.result.state === 'complete' && this.isCurrent()) this.onFinished();
    } catch (error) { this.error = (error as Error).message; }
  }
  private status(): string {
    return this.result.state === 'running' ? (this.result.stopping ? '当前一次结束后停止' : '检测中…') :
      this.result.state === 'cancelled' ? '已停止' : this.result.state === 'complete' ? '检测完成' :
      this.result.state === 'stale' ? '配置或内核已变化，请重新打开检测' : '每次通过当前节点发起独立的 HTTP(S) 探测';
  }
  @Builder
  private actions() {
    Menu() {
      MenuItem({ content: '复制检测报告' }).enabled(this.result.samples.length > 0).onClick(() => this.onCopy(probeReport(this.result)));
      MenuItem({ content: '停止后续检测' }).enabled(this.result.state === 'running' && !this.result.stopping).onClick(() => this.runner?.cancel());
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE);
  }
  build() {
    Column({ space: 14 }) {
      Row() {
        Text('节点连续检测').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button('关闭', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).onClick(() => this.controller?.close());
      }.width('100%');
      Text(this.nodeName).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).width('100%').maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
      TextInput({ text: this.url, placeholder: 'HTTP(S) 检测地址' }).height(38).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
        .fontColor(this.theme.text).placeholderColor(this.theme.textMuted).backgroundColor(this.theme.field).width('100%')
        .enabled(this.result.state !== 'running').onChange((value: string) => this.url = value);
      Row({ space: 12 }) {
        Select([{ value: '3 次' }, { value: '5 次' }, { value: '10 次' }]).selected([3,5,10].indexOf(this.count)).value(`${this.count} 次`)
          .width(110).height(36).font({ size: this.theme.font(13), family: this.theme.fontFamily }).enabled(this.result.state !== 'running')
          .onSelect((index: number) => this.count = [3,5,10][index]);
        if (this.result.state === 'running') {
          Button(this.result.stopping ? '正在停止…' : '停止后续检测', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
            .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(!this.result.stopping).onClick(() => this.runner?.cancel());
        } else {
          Button('开始检测', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
            .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(this.result.state !== 'stale').onClick(() => this.start());
        }
        Blank();
        Button('复制报告', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(this.result.samples.length > 0).onClick(() => this.onCopy(probeReport(this.result)));
      }.width('100%');
      Text(this.status()).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
      if (this.result.samples.length > 0) {
        Text(`已完成 ${probeStatistics(this.result).completed}/${this.result.total} · 成功 ${probeStatistics(this.result).passed} · 失败 ${probeStatistics(this.result).failed}`)
          .fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).width('100%');
        Text(`中位延迟 ${probeStatistics(this.result).median || '—'} ms · 最低 ${probeStatistics(this.result).minimum || '—'} ms · 最高 ${probeStatistics(this.result).maximum || '—'} ms`)
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      }
      Scroll() {
        Column({ space: 10 }) {
          ForEach(this.result.samples, (sample: ProbeSample) => {
            Row({ space: 12 }) {
              Text(`${sample.index}`).width(24).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted);
              Text(sample.delay > 0 ? `${sample.delay} ms` : probeFailureText(sample.error)).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily)
                .fontColor(sample.delay > 0 ? this.theme.success : this.theme.danger).layoutWeight(1).maxLines(4).textOverflow({ overflow: TextOverflow.Ellipsis });
            }.width('100%').padding(12).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5));
          }, (sample: ProbeSample) => String(sample.index));
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
    }.width('86%').constraintSize({ maxWidth: 820 }).height('82%').padding(24).borderRadius(this.theme.radius(12)).backgroundColor(this.theme.surface)
      .bindContextMenu(this.actions(), ResponseType.RightClick);
  }
}
