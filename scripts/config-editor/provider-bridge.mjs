// One native read plus the latest queued query. Aborted documents never borrow
// another request's data, and closing the editor resolves every pending lookup.
export class ProviderCompletionClient {
  constructor(send,isCurrent=()=>true,timeout=4000){this.send=send;this.isCurrent=isCurrent;this.timeout=timeout;this.sequence=0;this.running=null;this.queued=null;this.closed=false;}
  resolve(record,value){if(!record.resolved){record.resolved=true;record.resolve(value);}}
  request(query,context,revision){
    if(this.closed||context.aborted||typeof query!=='string'||query.length>256*1024)return Promise.resolve(null);
    return new Promise(resolve=>{
      const record={id:++this.sequence,query,context,revision,resolve,resolved:false,aborted:false};
      context.addEventListener?.('abort',()=>{record.aborted=true;this.resolve(record,null);if(this.queued===record)this.queued=null;},{onDocChange:true});
      if(this.running){if(this.queued)this.resolve(this.queued,null);this.queued=record;}
      else this.start(record);
    });
  }
  start(record){
    if(this.closed||record.aborted||record.context.aborted||!this.isCurrent(record.context,record.revision)){this.resolve(record,null);return;}
    this.running=record;
    record.timer=setTimeout(()=>this.finish(record,null),this.timeout);
    try{this.send(JSON.stringify({id:record.id,revision:record.revision,query:record.query}));}
    catch{this.finish(record,null);}
  }
  finish(record,value){
    if(this.running!==record)return;
    clearTimeout(record.timer);this.running=null;
    this.resolve(record,!this.closed&&!record.aborted&&!record.context.aborted&&this.isCurrent(record.context,record.revision)?value:null);
    const queued=this.queued;this.queued=null;if(queued)this.start(queued);
  }
  receive(id,revision,value){
    const record=this.running;if(!record||record.id!==id||record.revision!==revision)return false;
    this.finish(record,value);return true;
  }
  dispose(){
    this.closed=true;
    if(this.running){clearTimeout(this.running.timer);this.resolve(this.running,null);}
    if(this.queued)this.resolve(this.queued,null);
    this.running=this.queued=null;
  }
}
