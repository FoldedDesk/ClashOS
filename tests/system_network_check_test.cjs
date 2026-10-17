const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const ts=require('./test_env.cjs')();
const source=fs.readFileSync(path.join(__dirname,'../entry/src/main/ets/service/SystemNetworkCheck.ets'),'utf8');
const compiled=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2020}}).outputText;
const plain=x=>JSON.parse(JSON.stringify(x));
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
let checks=0;const check=(value,message)=>{assert(value,message);checks++;};
function environment(outcomes=[],read){
  const state={proxy:{host:'127.0.0.1',port:7890,exclusionList:['localhost','127.0.0.1'],username:'private-user',password:'secret-credential'},calls:[],destroyed:0,reads:0};
  const kit={connection:{getDefaultHttpProxy:async()=>{state.reads++;return read?read(state):state.proxy;}},http:{RequestMethod:{GET:'GET'},HttpProtocol:{HTTP1_1:1},createHttp(){
    let destroyed=false,abort;
    return {request(target,options){state.calls.push({target,options});const outcome=outcomes.shift();abort=outcome?.reject;
      if(outcome?.promise)return outcome.promise;
      if(outcome instanceof Error)return Promise.reject(outcome);
      return Promise.resolve({responseCode:outcome??204,result:'private-response-body',header:{'Set-Cookie':'private-header'}});},
      destroy(){if(destroyed)throw Error('Double destroy');destroyed=true;state.destroyed++;abort?.(Object.assign(Error('destroyed'),{code:2300999}));}};
  }}};
  const m={exports:{}};vm.runInNewContext(compiled,{module:m,exports:m.exports,require(name){if(name==='@kit.NetworkKit')return kit;if(name==='@ohos.url')return{default:{URL}};throw Error(name);}});
  return{...m.exports,state};
}
async function settleUntil(test){for(let n=0;n<100&&!test();n++)await new Promise(r=>setImmediate(r));assert(test(),'Expected asynchronous checkpoint was not reached');}
(async()=>{
  let env=environment([204,403,Object.assign(Error('must-not-export'),{code:2300999})]),states=[];
  let runner=new env.SystemNetworkCheck();await runner.run('',s=>states.push(s));
  const result=states.at(-1);
  check(result.state==='complete'&&result.samples.length===3,'A failed site does not prevent the remaining fixed checks');
  assert.deepEqual(plain(env.networkStatistics(result)),{responses:2,passed:1,httpErrors:1,networkErrors:1});checks++;
  check(env.networkSampleText(result.samples[1]).includes('已收到 HTTP 403')&&!env.networkSampleText(result.samples[1]).includes('网络请求失败'),'A real HTTP error is distinguished from a transport failure');
  check(env.networkSampleText(result.samples[2]).includes('2300999')&&!env.networkSampleText(result.samples[2]).includes('证书'),'Unknown OS errors preserve their code without inventing a certificate diagnosis');
  check(states[0].samples.length===0&&states[2].samples.length===1,'Published progress snapshots are immutable');
  states[1].proxy.exclusions.push('edited-by-view');check(!result.proxy.exclusions.includes('edited-by-view'),'Published exclusion lists cannot mutate controller state');
  const report=env.networkReport(result),snapshots=JSON.stringify(states);
  check(![report,snapshots].some(x=>/secret-credential|private-user|private-response-body|private-header|must-not-export/.test(x)),'Reports and snapshots exclude credentials, bodies, headers and untrusted error messages');
  check(report.includes('HTTP 状态异常 1')&&report.includes('网络请求失败 1')&&report.includes('系统代理：127.0.0.1:7890'),'Report retains route policy and separate result categories');
  check(env.state.destroyed===3,'Every completed/failed HTTP object is destroyed exactly once');
  for(const call of env.state.calls){check(call.options.usingProxy===true&&call.options.usingCache===false&&call.options.usingProtocol===1&&call.options.maxLimit===262144,'Requests use the actual system proxy and bounded uncached HTTP/1.1');check(!('caPath' in call.options)&&!('clientCert' in call.options)&&!('serverTrust' in call.options),'System TLS trust is not overridden');}
  check(env.networkTargets().length===3&&env.networkTargets()[0].expected===204,'Default targets have independent expected statuses');
  for(const value of ['file:///tmp/private','https://user:secret@example.com','https://example.com/ bad','https://example.com/\npart','x'.repeat(4097),'https://']){
    assert.throws(()=>env.networkTargets(value));checks++;
  }
  check(env.networkTargets(' https://example.com/check ')[0].expected===0,'Custom targets use 200–399 and accept surrounding spaces');
  check(env.networkErrorText(2300060).includes('证书')&&env.networkErrorText(2300028).includes('超时')&&env.networkErrorText(2300006).includes('域名'),'Known OS error codes have precise categories');
  check(env.networkProxyText({host:'::1',port:7890,exclusions:[]}).includes('[::1]:7890'),'IPv6 proxy addresses are unambiguous');

  env=environment([302]);env.state.proxy={host:'',port:0,exclusionList:[]};states=[];runner=new env.SystemNetworkCheck();
  await runner.run('https://example.com/check',s=>states.push(s));
  check(!env.networkProxyEnabled(states.at(-1).proxy)&&env.networkProxyText(states.at(-1).proxy).includes('未开启')&&env.networkPassed(states.at(-1).samples[0]),'Direct system policy remains visible and custom redirects are accepted');

  const gate=deferred();env=environment([gate]);states=[];runner=new env.SystemNetworkCheck();
  const running=runner.run('',s=>states.push(s));await settleUntil(()=>env.state.calls.length===1);
  await assert.rejects(()=>runner.run('',()=>{}));checks++;
  runner.cancel();runner.cancel();await running;
  check(env.state.calls.length===1&&env.state.destroyed===1&&states.at(-1).state==='cancelled'&&states.at(-1).samples.length===0,'Stop aborts the active request and starts no later targets');
  await runner.run('https://example.com/',s=>states.push(s));check(env.state.calls.length===2&&states.at(-1).state==='complete','An explicitly restarted stopped check uses a fresh request');

  const closed=deferred();env=environment([closed]);states=[];runner=new env.SystemNetworkCheck();
  const closing=runner.run('',s=>states.push(s));await settleUntil(()=>env.state.calls.length===1);runner.dispose();const before=states.length;await closing;
  check(states.length===before&&env.state.destroyed===1,'Disposal aborts network work and silences late UI updates');
  await assert.rejects(()=>runner.run('',()=>{}));checks++;

  for(const key of ['host','port','exclusionList','password']){
    const pending=deferred();env=environment([pending]);states=[];runner=new env.SystemNetworkCheck();
    const changing=runner.run('',s=>states.push(s));await settleUntil(()=>env.state.calls.length===1);
    env.state.proxy={...env.state.proxy,[key]:key==='port'?7899:key==='exclusionList'?['*']:key==='host'?'192.0.2.1':'changed-secret'};
    pending.resolve({responseCode:204});await changing;
    check(states.at(-1).state==='stale'&&states.at(-1).samples.length===0&&env.state.calls.length===1,`Changed ${key} invalidates a pending sample and stops the run`);
    check(!JSON.stringify(states).includes('changed-secret'),'Private comparison signatures never reach snapshots');
  }
  env=environment([204],s=>{if(s.reads>1)s.proxy.exclusionList.reverse();return s.proxy;});states=[];runner=new env.SystemNetworkCheck();await runner.run('',s=>states.push(s));
  check(states.at(-1).state==='complete','Exclusion-list order alone does not invalidate equivalent policy');

  const stale=deferred();let current=true;env=environment([stale]);states=[];runner=new env.SystemNetworkCheck(async()=>current);
  const changed=runner.run('',s=>states.push(s));await settleUntil(()=>env.state.calls.length===1);current=false;stale.resolve({responseCode:204});await changed;
  check(states.at(-1).state==='stale'&&states.at(-1).samples.length===0,'Changed core/runtime guard cannot publish mixed-route samples');
  env=environment();states=[];runner=new env.SystemNetworkCheck(async()=>{throw Error('unavailable');});await runner.run('',s=>states.push(s));
  check(states.at(-1).state==='stale'&&env.state.calls.length===0,'An unverifiable runtime prevents requests');
  env=environment([],()=>{throw Error('private read failure');});states=[];runner=new env.SystemNetworkCheck();await runner.run('',s=>states.push(s));
  check(states.at(-1).state==='error'&&env.state.calls.length===0&&!JSON.stringify(states).includes('private read failure'),'Unreadable proxy settings are reported without silently choosing a route');
  env=environment();states=[];runner=new env.SystemNetworkCheck();await runner.run('',s=>{states.push(s);if(s.state==='running')runner.cancel();});
  check(env.state.calls.length===0&&states.at(-1).state==='cancelled','Immediate cancellation sends no traffic');
  console.log(`System network checks passed: ${checks} (system policy, HTTP outcomes, trust, secrets, cancellation and stale state)`);
})().catch(error=>{console.error(error);process.exitCode=1;});
