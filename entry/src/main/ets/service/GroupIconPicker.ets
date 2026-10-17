import { common } from '@kit.AbilityKit';
import { fileIo, fileUri, picker } from '@kit.CoreFileKit';
import { image } from '@kit.ImageKit';
import { GroupIconStore } from './GroupIconStore';

export async function pickGroupIcon(context: common.UIAbilityContext, store: GroupIconStore): Promise<string | undefined> {
  const options = new picker.DocumentSelectOptions(); options.maxSelectNumber = 1;
  options.fileSuffixFilters = ['图片|.png,.jpg,.jpeg,.webp,.gif,.bmp'];
  const paths: string[] = await new picker.DocumentViewPicker(context).select(options);
  if (!paths.length) return undefined;
  let file: fileIo.File;
  try { file = fileIo.openSync(paths[0], fileIo.OpenMode.READ_ONLY); }
  catch (_) { file = fileIo.openSync(new fileUri.FileUri(paths[0]).path, fileIo.OpenMode.READ_ONLY); }
  let bytes: ArrayBuffer;
  try {
    const size: number = fileIo.statSync(file.fd).size;
    if (size <= 0 || size > 2 * 1024 * 1024) throw new Error('请选择 2 MB 以内的图片');
    const data: Uint8Array = new Uint8Array(size); let used: number = 0;
    while (used < size) {
      const buffer: ArrayBuffer = new ArrayBuffer(Math.min(size - used, 65536));
      const count: number = fileIo.readSync(file.fd, buffer);
      if (count <= 0 || count > buffer.byteLength) throw new Error('图片未能完整读取');
      data.set(new Uint8Array(buffer, 0, count), used); used += count;
    }
    bytes = data.buffer as ArrayBuffer;
  } finally { fileIo.closeSync(file); }
  const source = image.createImageSource(bytes);
  try {
    const info: image.ImageInfo = await source.getImageInfo();
    if (info.size.width < 1 || info.size.height < 1 || info.size.width > 4096 || info.size.height > 4096) throw new Error('图片尺寸不能超过 4096 × 4096');
    const factor: number = Math.min(1, 256 / Math.max(info.size.width, info.size.height));
    const pixel = await source.createPixelMap({ desiredSize: { width: Math.max(1, Math.round(info.size.width * factor)), height: Math.max(1, Math.round(info.size.height * factor)) } });
    try {
      const packer = image.createImagePacker();
      try { return store.stageImage(await packer.packing(pixel, { format: 'image/png', quality: 100 })); }
      finally { await packer.release(); }
    } finally { await pixel.release(); }
  } finally { await source.release(); }
}
