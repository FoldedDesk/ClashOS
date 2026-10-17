const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const ts=require('./test_env.cjs')();
const filename=path.join(__dirname,'../entry/src/main/ets/service/ConfigEditorController.ets'),m={exports:{}};
vm.runInNewContext(ts.transpileModule(fs.readFileSync(filename,'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020}}).outputText,{module:m,exports:m.exports});
let checks=0;const check=(value,message)=>{assert(value,message);checks++;};
(async()=>{
 const controller=new m.exports.ConfigEditorController();await assert.rejects(()=>controller.text(),/尚未就绪/);checks++;
 let current='port: 7890\r\n# PUBLIC 😀\r\n',resolve,commands=[];
 const port={read:async()=>JSON.stringify({text:current,revision:0,composing:false}),command:async(name,value)=>commands.push([name,value]),markError:async message=>commands.push(['mark',message])};
 const binding=controller.bind(port);check(await controller.text()===current,'Read preserves exact text');
 check(!controller.changedSinceRead(0),'A delayed status for the just-read document cannot clear its validation result');
 check(controller.changedSinceRead(1),'A later document revision invalidates the previous validation result');
 current+='mode: rule\r\n';check(await controller.text()===current,'Save reads the latest document, not a delayed status callback');
 port.read=async()=>JSON.stringify(JSON.stringify({text:current,revision:5,composing:false}));check(await controller.text()===current,'ArkWeb JSON-wrapped string transport is accepted');
 for(const value of [null,{},[],{text:4,revision:0,composing:false},{text:'x',revision:-1,composing:false},{text:'x',revision:0.5,composing:false},{text:'x',revision:0},{text:'x',revision:0,composing:true}]){
  port.read=async()=>JSON.stringify(value);await assert.rejects(()=>controller.text());checks++;
 }
 port.read=()=>new Promise(r=>resolve=r);const pending=controller.text();controller.unbind(binding);resolve(JSON.stringify({text:'old',revision:1,composing:false}));await assert.rejects(()=>pending,/已关闭/);checks++;
 port.read=async()=>JSON.stringify({text:'new',revision:0,composing:false});const next=controller.bind(port);controller.unbind(binding);check(await controller.text()==='new','Old dialog cleanup cannot unbind a newer editor');
 await controller.command('complete');await controller.command('goto',8);await controller.command('raw-js;alert(1)');await controller.command('goto',Infinity);await controller.markError('PUBLIC error line 3');
 check(commands.length===3&&commands[0][0]==='complete'&&commands[1][1]===8,'Only supported finite-value commands reach the local editor');
 await controller.command('clear');check(commands.at(-1)[0]==='clear','Clear uses the bound editor instead of replacing a stale initial document');
 await assert.rejects(()=>controller.replace('template'),/尚未就绪/);checks++;
 port.replace=async text=>{current=text;};port.read=async()=>JSON.stringify({text:current,revision:6,composing:false});
 await controller.replace('# PUBLIC 😀\n</script>');check(await controller.text()===current&&current.includes('</script>'),'Native template replacement passes exact literal document data');
 let expectedValue;port.replace=async(text,expected)=>{expectedValue=expected;if(expected!==current)throw Error('stale');current=text;};
 const expectedCurrent=current;await controller.replace('fontFamily: monospace',expectedCurrent);
 check(expectedValue===expectedCurrent&&current==='fontFamily: monospace','Conditional replacement transports exact source bytes to the production editor guard');
 await assert.rejects(()=>controller.replace('lost update',expectedCurrent),/stale/);checks++;
 check(current==='fontFamily: monospace','Rejected derived edits preserve newer editor content');
 port.replace=()=>new Promise(r=>resolve=r);const replacing=controller.replace('old');controller.unbind(next);controller.bind(port);resolve();
 await assert.rejects(()=>replacing,/已关闭/);checks++;
 const final=controller.bind(port);controller.unbind(final);await assert.rejects(()=>controller.text());checks++;
 console.log(`Config editor controller scenarios passed: ${checks} (production ArkTS controller; transport callbacks modeled)`);
})().catch(error=>{console.error(error);process.exitCode=1;});
