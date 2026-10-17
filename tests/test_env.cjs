// The host service tests use standard TypeScript transpilation, not an ArkUI runtime.
const path = require('node:path');
module.exports = function loadTypeScript() {
  const explicit = process.env.CLAHSOS_TYPESCRIPT;
  if (explicit) return require(explicit);
  const candidates = ['typescript'];
  if (process.env.DEVECO_SDK_HOME) candidates.push(path.resolve(process.env.DEVECO_SDK_HOME, '..', 'tools/ohpm/node_modules/typescript'));
  if (process.env.DEVECO_STUDIO_HOME) candidates.push(path.resolve(process.env.DEVECO_STUDIO_HOME, 'tools/ohpm/node_modules/typescript'));
  candidates.push('/Applications/DevEco-Studio.app/Contents/tools/ohpm/node_modules/typescript');
  for (const candidate of candidates) {
    let resolved;
    try { resolved = require.resolve(candidate); }
    catch (error) { if (error.code === 'MODULE_NOT_FOUND') continue; throw error; }
    return require(resolved);
  }
  throw new Error('TypeScript is required. Set CLAHSOS_TYPESCRIPT to its installed module path, or use the TypeScript bundled with DevEco Studio.');
};
