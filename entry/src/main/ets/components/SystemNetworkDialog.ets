import { dialogActivity } from '../service/DialogActivity';
import { VergePalette } from '../theme/VergeTheme';
import { SystemNetworkCheck, NetworkCheck, NetworkSample, NetworkTarget, emptyNetworkCheck, networkTargets, networkProxyEnabled,
  networkProxyText, networkStateText, networkSampleText, networkPassed, networkStatistics, networkReport } from '../service/SystemNetworkCheck';

@CustomDialog
export struct SystemNetworkDialog {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  controller?: CustomDialogController;
  private dialogActivityId: number = 0;
  isCurrent: () => Promise<boolean> = async (): Promise<boolean> => true;
  onCopy: (text: string) => void = (_text: string): void => {};
  onSettings: () => void = (): void => {};
  onFinished: () => void = (): void => {};
  @State custom: string = '';
  @State result: NetworkCheck = emptyNetworkCheck();
  @State error: string = '';
  @State busy: boolean = false;
  private runner?: SystemNetworkCheck;
  private active: boolean = true;
  aboutToAppear(): void { this.dialogActivityId = dialogActivity.enter(); this.runner = new SystemNetworkCheck(this.isCurrent); }
  aboutToDisappear(): void { this.active = false; this.runner?.dispose(); dialogActivity.leave(this.dialogActivityId); }
  private async start(): Promise<void> {
    if (this.busy) return; this.busy = true; this.error = '';
    try { await this.runner?.run(this.custom, (state: NetworkCheck): void => { this.result = state; }); if (this.active) this.onFinished(); }
    catch (error) { if (this.active) this.error = (error as Error).message; }
    finally { if (this.active) this.busy = false; }
  }
  @Builder
  private actions() {
    Menu() {
      MenuItem({ content: '复制联网检测报告' }).enabled(this.result.samples.length > 0).onClick(() => this.onCopy(networkReport(this.result)));
      MenuItem({ content: '停止联网检测' }).enabled(this.busy && this.result.state === 'running').onClick(() => this.runner?.cancel());
      MenuItem({ content: '打开系统代理设置' }).enabled(!this.busy).onClick(() => { this.controller?.close(); this.onSettings(); });
    }.backgroundColor(this.theme.surface).backgroundBlurStyle(BlurStyle.NONE);
  }
  build() {
    Column({ space: 14 }) {
      Row() {
        Text('系统代理联网检测').fontSize(this.theme.font(20)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Bold).fontColor(this.theme.text).layoutWeight(1);
        Button('关闭', { type: ButtonType.Normal }).height(32).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).onClick(() => this.controller?.close());
      }.width('100%');
      Text('使用鸿蒙系统 HTTP 客户端和当前系统代理规则访问网站，不指定节点或绕过排除项。')
        .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      TextInput({ text: this.custom, placeholder: '自定义 HTTP(S) 地址（留空检测 Google、Gstatic、GitHub API）' })
        .height(40).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).placeholderColor(this.theme.textMuted)
        .backgroundColor(this.theme.field).width('100%').enabled(!this.busy).onChange((value: string) => this.custom = value);
      Text(this.custom.trim() ? '自定义地址期望 HTTP 200–399；响应超过 256 KB 会结束检测。' : 'Google / Gstatic 期望 HTTP 204，GitHub API 期望 HTTP 200。')
        .fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
      Row({ space: 10 }) {
        if (this.busy) {
          Button(this.result.state === 'cancelled' ? '正在停止…' : '停止检测', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
            .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(this.result.state === 'running').onClick(() => this.runner?.cancel());
        } else {
          Button('开始联网检测', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).borderRadius(this.theme.radius(5))
            .fontColor(this.theme.onPrimary).backgroundColor(this.theme.primary).enabled(this.result.state !== 'stale').onClick(() => this.start());
        }
        Blank();
        Button('代理设置', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
          .fontColor(this.theme.textSecondary).backgroundColor(this.theme.field).enabled(!this.busy).onClick(() => { this.controller?.close(); this.onSettings(); });
        Button('复制报告', { type: ButtonType.Normal }).height(36).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
          .fontColor(this.theme.primary).backgroundColor(this.theme.primarySoft).enabled(this.result.samples.length > 0).onClick(() => this.onCopy(networkReport(this.result)));
      }.width('100%');
      Text(networkStateText(this.result.state)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textSecondary).width('100%');
      if (this.result.proxy) {
        Text(networkProxyText(this.result.proxy)).fontSize(this.theme.font(13)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).width('100%');
        Text(`排除项：${this.result.proxy.exclusions.join(', ') || '无'}`).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%').maxLines(3);
        if (!networkProxyEnabled(this.result.proxy)) Text('系统代理未开启；网站访问成功也不表示流量经过 ClashOS。')
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.warning).width('100%');
      }
      if (this.error) Text(this.error).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.danger).width('100%');
      if (this.result.samples.length > 0) {
        Text(`已完成 ${this.result.samples.length}/${this.result.total} · 网站响应成功 ${networkStatistics(this.result).passed} · HTTP 状态异常 ${networkStatistics(this.result).httpErrors} · 网络请求失败 ${networkStatistics(this.result).networkErrors}`)
          .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.text).width('100%');
      }
      Scroll() {
        Column({ space: 10 }) {
          ForEach(this.result.samples, (sample: NetworkSample) => {
            Column({ space: 6 }) {
              Text(sample.name).fontSize(this.theme.font(14)).fontFamily(this.theme.fontFamily).fontWeight(FontWeight.Medium).fontColor(this.theme.text).width('100%');
              Text(sample.url).fontSize(this.theme.font(11)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%').maxLines(2).textOverflow({ overflow: TextOverflow.Ellipsis });
              Text(networkSampleText(sample)).fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily)
                .fontColor(networkPassed(sample) ? this.theme.success : sample.status ? this.theme.warning : this.theme.danger).width('100%');
            }.width('100%').padding(12).backgroundColor(this.theme.field).borderRadius(this.theme.radius(5));
          }, (sample: NetworkSample) => JSON.stringify(sample));
          if (this.result.state === 'idle') Text(networkTargets().map((target: NetworkTarget) => target.url).join('\n'))
            .fontSize(this.theme.font(12)).fontFamily(this.theme.fontFamily).fontColor(this.theme.textMuted).width('100%');
        }.width('100%');
      }.width('100%').layoutWeight(1).align(Alignment.Top);
    }.width('88%').constraintSize({ maxWidth: 820 }).height('84%').padding(24).borderRadius(this.theme.radius(12)).backgroundColor(this.theme.surface)
      .bindContextMenu(this.actions(), ResponseType.RightClick);
  }
}
