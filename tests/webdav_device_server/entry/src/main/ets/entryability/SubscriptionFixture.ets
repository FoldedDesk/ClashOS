// Public subscription responses in the independent, removable device fixture.
export class SubscriptionFixture {
  mode: string = 'ready';
  requests: number = 0;
  rejected: number = 0;
  homeRequests: number = 0;
  customAgent: boolean = false;
  encodedQueryRequests: number = 0;
  readonly source: string = "port: 18890\nsocks-port: 0\nmode: direct\nauthentication: ['subscription-fixture:public-proxy-password']\nskip-auth-prefixes: []\nhosts: {subscription.device.test: 127.0.0.1}\ndns: {enable: false, use-hosts: true}\nproxies: []\nproxy-groups: []\nrules: ['MATCH,DIRECT']\n";
  accept(agent: string, path: string): boolean {
    this.requests++; this.customAgent = agent === 'clash-public-fixture/2';
    if (path === '/public-subscription.yaml?token=PUBLIC%2Bvalue%26tail&flag=meta') this.encodedQueryRequests++;
    const valid: boolean = this.mode === 'custom' ? agent === 'clash-public-fixture/2' : ['clashos/1.0', 'clash-public-fixture/2'].includes(agent);
    if (!valid) this.rejected++; return valid;
  }
  headers(): string {
    if (this.mode === 'no-metadata') return '';
    return "Content-Type: application/yaml\r\nContent-Disposition: attachment; filename=public.yaml; filename*=UTF-8''%E5%85%AC%E5%BC%80%E8%AE%A2%E9%98%85%20%F0%9F%98%80.yaml\r\n" +
      `Subscription-Userinfo: upload=1024; download=3072; total=${this.mode === 'custom' ? 16384 : 8192}; expire=2000000000\r\nProfile-Update-Interval: ${this.mode === 'custom' ? 4 : 2}\r\n` +
      'Profile-Web-Page-Url: http://127.0.0.1:18088/public-home\r\n';
  }
  installPage(): string {
    const target: string = 'http://127.0.0.1:18088/public-subscription.yaml?token=PUBLIC%2Bvalue%26tail&flag=meta';
    return '<html><title>ClashOS public install fixture</title><body><h1>ClashOS public install links</h1>' +
      ['clash', 'clashos', 'clash-verge'].map((scheme: string): string => '<p><a style="font-size:32px" href="' + scheme +
        '://install-config?url=' + encodeURIComponent(target) + '&amp;name=' + encodeURIComponent('公开链接 😀') + '">Install ' + scheme + '</a></p>').join('') + '</body></html>';
  }
  state(): string { return JSON.stringify({ mode: this.mode, requests: this.requests, rejected: this.rejected, homeRequests: this.homeRequests, customAgent: this.customAgent, encodedQueryRequests: this.encodedQueryRequests }); }
}
