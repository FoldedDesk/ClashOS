import { common } from '@kit.AbilityKit';
import { fileIo } from '@kit.CoreFileKit';

export interface AppSettings {
  activeProfileId: string;
  endpoint: string;
  secret: string;
  mode: string;
  testUrl: string;
}

export class SettingsStore {
  private path: string;

  constructor(context: common.UIAbilityContext) {
    this.path = `${context.filesDir}/settings.json`;
  }

  load(): AppSettings {
    const defaults: AppSettings = {
      activeProfileId: '', endpoint: 'http://127.0.0.1:9090', secret: '', mode: '',
      testUrl: 'https://www.gstatic.com/generate_204'
    };
    if (!fileIo.accessSync(this.path)) return defaults;
    const parsed: AppSettings = JSON.parse(fileIo.readTextSync(this.path)) as AppSettings;
    return {
      activeProfileId: typeof parsed.activeProfileId === 'string' ? parsed.activeProfileId : '',
      endpoint: typeof parsed.endpoint === 'string' ? parsed.endpoint : defaults.endpoint,
      secret: typeof parsed.secret === 'string' ? parsed.secret : '',
      mode: ['Rule', 'Global', 'Direct'].indexOf(parsed.mode) >= 0 ? parsed.mode : '',
      testUrl: typeof parsed.testUrl === 'string' && /^https?:\/\//.test(parsed.testUrl) ? parsed.testUrl : defaults.testUrl
    };
  }

  save(settings: AppSettings): void {
    const file = fileIo.openSync(`${this.path}.tmp`, fileIo.OpenMode.CREATE | fileIo.OpenMode.READ_WRITE | fileIo.OpenMode.TRUNC);
    try {
      fileIo.writeSync(file.fd, JSON.stringify(settings));
      fileIo.fsyncSync(file.fd);
    } finally {
      fileIo.closeSync(file);
    }
    fileIo.renameSync(`${this.path}.tmp`, this.path);
  }
}
