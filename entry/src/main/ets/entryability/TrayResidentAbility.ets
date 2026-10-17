import { UIAbility } from '@kit.AbilityKit';
import { attachDesktopResident, detachDesktopResident } from '../service/DesktopSession';

// ATTACH_TO_STATUS_BAR_ITEM keeps the existing process and its native core;
// no second core, invisible web page, timer or synthetic background task.
export default class TrayResidentAbility extends UIAbility {
  onCreate(): void { attachDesktopResident(this.context); }
  onDestroy(): void { detachDesktopResident(this.context); }
}
