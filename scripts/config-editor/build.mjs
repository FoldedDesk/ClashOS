import {build} from 'esbuild';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const out=path.resolve(root,'../../entry/src/main/resources/rawfile/config-editor');
fs.mkdirSync(out,{recursive:true});
await build({entryPoints:[path.join(root,'editor.mjs')],outfile:path.join(out,'editor.js'),bundle:true,minify:true,format:'iife',target:'chrome100',legalComments:'eof'});
fs.copyFileSync(path.join(root,'index.html'),path.join(out,'index.html'));
let notices='ClashOS offline configuration editor\nThird-party dependency notices\n\n';
for(const folder of fs.readdirSync(path.join(root,'node_modules'))){
 const folders=folder.startsWith('@')?fs.readdirSync(path.join(root,'node_modules',folder)).map(x=>folder+'/'+x):[folder];
 for(const name of folders){if(name==='esbuild'||name.startsWith('@esbuild')||name.startsWith('.'))continue;
  const base=path.join(root,'node_modules',name),pkg=path.join(base,'package.json');if(!fs.existsSync(pkg))continue;
  const meta=JSON.parse(fs.readFileSync(pkg,'utf8'));let license='';
  for(const file of ['LICENSE','LICENSE.txt','LICENSE.md'])if(fs.existsSync(path.join(base,file))){license=fs.readFileSync(path.join(base,file),'utf8');break;}
  if(!license)throw Error('Dependency license missing: '+name);
  notices+=name+' '+meta.version+' ('+meta.license+')\n'+license+'\n\n';
 }
}
fs.writeFileSync(path.join(out,'THIRD-PARTY-NOTICES.txt'),notices);
console.log('Bundled offline editor:',fs.statSync(path.join(out,'editor.js')).size,'bytes; dependency notices included');
