import { ProfileStore, ClashProfile } from './ProfileStore';
import { AppearanceController } from './AppearanceController';
import { AppearanceSettings } from '../theme/AppearanceTypes';
import { BackupGlobals, BackupRestoreSelection, BackupRestoreResult } from './BackupTypes';
import { GroupIconStore } from './GroupIconStore';

export interface BackupRuntime {
  validate: (globals: BackupGlobals) => void;
  reload: () => Promise<void>;
}

export class BackupRestoreCoordinator {
  private profiles: ProfileStore;
  private appearance?: AppearanceController;
  private active?: ClashProfile;
  private icons?: GroupIconStore;
  constructor(profiles: ProfileStore, appearance?: AppearanceController, active?: ClashProfile, icons?: GroupIconStore) {
    this.profiles = profiles; this.appearance = appearance; this.active = active; this.icons = icons;
  }
  private sameGlobals(a: BackupGlobals, b: BackupGlobals): boolean { return a.merge === b.merge && a.script === b.script; }
  private sameAppearance(a: AppearanceSettings, b: AppearanceSettings): boolean { return a.mode === b.mode && a.accent === b.accent; }

  async restore(text: string, selection: BackupRestoreSelection, runtime?: BackupRuntime): Promise<BackupRestoreResult> {
    const preview = this.profiles.inspectBackup(text, selection.globals);
    if (!selection.profiles.length && !selection.globals && !selection.appearance) throw new Error('请选择配置或需要恢复的设置');
    if (selection.profiles.some((i: number) => !Number.isInteger(i) || i < 0 || i >= preview.rows.length || !preview.rows[i].valid) ||
      new Set(selection.profiles).size !== selection.profiles.length) throw new Error('请选择可以加载的配置');
    if (selection.appearance && (!preview.archive.appearance || !this.appearance)) throw new Error('此备份不包含外观，或当前外观服务不可用');
    const restoreIcons: boolean = selection.appearance && preview.archive.groupIcons !== undefined;
    if (restoreIcons && !this.icons) throw new Error('当前图标服务不可用，无法恢复备份中的代理组图标');
    const previousIcons: string = restoreIcons ? this.icons!.revision() : '';
    if (restoreIcons && selection.expectedGroupIcons !== undefined && previousIcons !== selection.expectedGroupIcons) throw new Error('图标设置已变化，请重新预览备份');
    if (selection.expectedGlobals && !this.sameGlobals(selection.expectedGlobals, preview.currentGlobals)) throw new Error('全局扩展已变化，请重新预览备份');
    if (selection.expectedNames !== undefined && selection.expectedNames !== preview.namesSnapshot) throw new Error('配置列表已变化，请重新预览备份');
    const previousGlobals: BackupGlobals = preview.currentGlobals;
    const previousAppearance: AppearanceSettings | undefined = selection.appearance ? this.appearance?.savedSettings() : undefined;
    if (selection.appearance && selection.expectedAppearance && previousAppearance && !this.sameAppearance(selection.expectedAppearance, previousAppearance))
      throw new Error('外观设置已变化，请重新预览备份');
    if (selection.globals) {
      const globals: BackupGlobals = preview.archive.globals as BackupGlobals;
      if (runtime) runtime.validate(globals);
      // Selected profiles are checked in their future restore context. Settings-only
      // restores still need a native validation context on a fresh installation.
      else if (this.active || selection.profiles.length === 0) this.profiles.validateBackupGlobals(this.active, globals);
    }
    let created: ClashProfile[] = [], globalsChanged: boolean = false, runtimeAttempted: boolean = false, appearanceAttempted: boolean = false;
    try {
      if (selection.profiles.length) created = this.profiles.restoreBackup(text, selection.profiles, selection.globals);
      if (selection.globals) {
        this.profiles.replaceBackupGlobals(previousGlobals, preview.archive.globals as BackupGlobals); globalsChanged = true;
        if (runtime) { runtimeAttempted = true; await runtime.reload(); }
        if (!this.sameGlobals(this.profiles.backupGlobals(), preview.archive.globals as BackupGlobals)) throw new Error('全局扩展在恢复期间已变化，无法提交本次恢复');
      }
      if (selection.appearance && this.appearance && preview.archive.appearance) {
        // Native API calls above may yield; do not overwrite a newer preference.
        if (previousAppearance && !this.sameAppearance(previousAppearance, this.appearance.savedSettings())) throw new Error('外观设置已变化，请重新预览备份');
        appearanceAttempted = true;
        this.appearance.save(preview.archive.appearance.mode, preview.archive.appearance.accent);
      }
      // Last synchronous commit: a failed icon import leaves the old index/images
      // intact, so earlier profile/global/appearance steps can still be rolled back.
      if (restoreIcons) this.icons!.restoreBackup(preview.archive.groupIcons!, previousIcons);
      return { count: created.length, globals: selection.globals, appearance: selection.appearance, reloaded: runtimeAttempted };
    } catch (error) {
      const problems: string[] = [];
      if (appearanceAttempted && previousAppearance && this.appearance) {
        try {
          if (!this.sameAppearance(previousAppearance, this.appearance.savedSettings())) this.appearance.save(previousAppearance.mode, previousAppearance.accent);
        } catch (_) { problems.push('外观未能撤回'); }
      }
      if (globalsChanged) {
        try { this.profiles.replaceBackupGlobals(preview.archive.globals as BackupGlobals, previousGlobals); }
        catch (_) { problems.push('全局扩展未能撤回'); }
      }
      try { if (!this.sameGlobals(this.profiles.backupGlobals(), previousGlobals)) problems.push('全局扩展与恢复前不一致'); }
      catch (_) { problems.push('无法确认全局扩展'); }
      if (runtimeAttempted && problems.length === 0 && runtime) {
        try { await runtime.reload(); } catch (_) { problems.push('内核状态未能确认，请重新加载原配置'); }
      }
      created.forEach((profile: ClashProfile) => { try { this.profiles.remove(profile); } catch (_) { problems.push('新增副本未能删除'); } });
      if (this.profiles.backupNamesSnapshot() !== preview.namesSnapshot) problems.push('配置列表已变化或有新增文件未能清理');
      throw new Error(`${(error as Error).message || '恢复失败'}；${problems.length ? problems.join('；') : '本次恢复已撤回，原设置已保留'}`);
    }
  }
}
