import { AppearanceSettings } from '../theme/AppearanceTypes';
import { GroupIconBackup } from './GroupIconBackup';
import { NetworkBackup } from './NetworkBackupTypes';
import { SubscriptionData } from './SubscriptionTypes';
import { DesktopPreferences } from './DesktopController';

export const BACKUP_LIMIT: number = 32 * 1024 * 1024;

export interface BackupGlobals { merge: string; script: string; }
export interface BackupCreateOptions { profileIds: string[]; includeGlobals: boolean; includeAppearance: boolean; includeNetwork?: boolean; includeDesktop?: boolean; }
export interface BackupRestoreSelection {
  profiles: number[];
  globals: boolean;
  appearance: boolean;
  network?: boolean;
  desktop?: boolean;
  expectedDesktop?: DesktopPreferences;
  expectedNetwork?: string;
  expectedGlobals?: BackupGlobals;
  expectedAppearance?: AppearanceSettings;
  expectedGroupIcons?: string;
  expectedNames?: string;
}
export interface BackupRestoreResult { count: number; globals: boolean; appearance: boolean; reloaded: boolean; network?: boolean; networkApplied?: boolean; desktop?: boolean; }

export interface BackupResource {
  suffix: string;
  data: string;
}

export interface BackupProfile {
  subscription?: SubscriptionData;
  sequence?: string;
  script?: string;
  merge?: string;
  objectEdits?: string;
  ruleEdits?: string;
  name: string;
  content: string;
  sourceUrl: string;
  updateInterval: number;
  pinned: boolean;
  selections: string;
  resources: BackupResource[];
}

export interface ProfileBackup {
  migrationNotes?: string[];
  format: string;
  version: number;
  createdAt: string;
  profiles: BackupProfile[];
  globals?: BackupGlobals;
  appearance?: AppearanceSettings;
  groupIcons?: GroupIconBackup;
  network?: NetworkBackup;
  desktop?: DesktopPreferences;
}

export interface BackupPreviewRow {
  index: number;
  name: string;
  valid: boolean;
  resources: number;
  restoreName: string;
  error: string;
}

export interface BackupPreview {
  archive: ProfileBackup;
  rows: BackupPreviewRow[];
  currentGlobals: BackupGlobals;
  namesSnapshot: string;
}

export interface BackupEntry {
  name: string;
  bytes: number;
  updatedAt: string;
  remote: boolean;
  etag: string;
}

export interface WebDavSettings {
  url: string;
  username: string;
  password: string;
}

export const BACKUP_FILE_PATTERN: RegExp = /^clashos-backup-\d{13}-[0-9a-f]{32}\.json$/;
export const BACKUP_RESOURCE_PATTERN: RegExp = /^\.(?:provider|rule-provider)-[0-9a-f]{16}\.cache$/;
