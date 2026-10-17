// Component lifecycle tracking also works on API 12, where the controller's
// onDidDisappear callback is unavailable. A closing older dialog cannot release
// a newer one; nested dialogs retain their own leases.
export class DialogActivity {
  private nextId: number = 0;
  private openDialogs: Set<number> = new Set();
  onIdle?: () => void;

  enter(): number { const id: number = ++this.nextId; this.openDialogs.add(id); return id; }
  leave(id: number): void {
    if (this.openDialogs.delete(id) && this.openDialogs.size === 0) this.onIdle?.();
  }
  busy(): boolean { return this.openDialogs.size > 0; }
}

export const dialogActivity: DialogActivity = new DialogActivity();
