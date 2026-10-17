import { VergePalette } from '../theme/VergeTheme';

@Component
export struct ProxyGroupIcon {
  @StorageLink('clashosTheme') theme: VergePalette = new VergePalette();
  @Prop @Watch('reset') source: string = '';
  @Prop @Watch('reset') revision: number = 0;
  @Prop iconSize: number = 32;
  @Prop emoji: string = '';
  @Prop fallback: Resource = $r('app.media.verge_selector');
  @Prop color: string = '';
  onFailure: (failed: boolean) => void = (_failed: boolean): void => {};
  @State failed: boolean = false;
  private reset(): void { this.failed = false; this.onFailure(false); }
  private preset(): Resource {
    switch (this.source.slice(8)) {
      case 'speed': return $r('app.media.verge_speed');
      case 'fallback': return $r('app.media.verge_fallback');
      case 'balance': return $r('app.media.verge_balance');
      case 'proxies': return $r('app.media.verge_proxies');
      case 'server': return $r('app.media.verge_server');
      case 'shield': return $r('app.media.verge_shield');
      case 'home': return $r('app.media.verge_home');
      default: return $r('app.media.verge_selector');
    }
  }
  private tint(): string { return this.source.startsWith('builtin:') ? this.theme.primary : this.color || this.theme.primary; }
  private filled(source: Resource): boolean { return source.id === $r('app.media.verge_fallback').id || source.id === $r('app.media.verge_home').id; }
  private filter(): ColorFilter {
    const color: string = this.tint();
    return new ColorFilter([0, 0, 0, parseInt(color.slice(1, 3), 16) / 255, 0,
      0, 0, 0, parseInt(color.slice(3, 5), 16) / 255, 0,
      0, 0, 0, parseInt(color.slice(5, 7), 16) / 255, 0, 0, 0, 0, 1, 0]);
  }
  build() {
    Stack() {
      if (this.source.startsWith('builtin:')) {
        Image(this.preset()).width(this.iconSize).height(this.iconSize)
          .fillColor(this.filled(this.preset()) ? this.tint() : Color.Transparent).colorFilter(this.filter()).draggable(false);
      } else if (this.source && !this.failed) {
        Image(this.source).width(this.iconSize).height(this.iconSize).objectFit(ImageFit.Contain).draggable(false)
          .onError(() => { this.failed = true; this.onFailure(true); });
      } else if (this.emoji) {
        Text(this.emoji).fontSize(this.iconSize * 0.94).textAlign(TextAlign.Center);
      } else {
        Image(this.fallback).width(this.iconSize).height(this.iconSize)
          .fillColor(this.filled(this.fallback) ? this.tint() : Color.Transparent).colorFilter(this.filter()).draggable(false);
      }
    }.width(this.iconSize).height(this.iconSize).accessibilityText(this.source && !this.failed ? '自定义代理组图标' : '默认代理组图标');
  }
}
