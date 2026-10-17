import {basicSetup} from 'codemirror';
import {EditorState,Compartment} from '@codemirror/state';
import {EditorView,keymap} from '@codemirror/view';
import {yaml} from '@codemirror/lang-yaml';
import {json,jsonParseLinter} from '@codemirror/lang-json';
import {javascript,javascriptLanguage} from '@codemirror/lang-javascript';
import {syntaxHighlighting,HighlightStyle,syntaxTree} from '@codemirror/language';
import {tags} from '@lezer/highlight';
import {autocompletion,startCompletion} from '@codemirror/autocomplete';
import {indentWithTab,undo,redo} from '@codemirror/commands';
import {openSearchPanel} from '@codemirror/search';
import {linter,setDiagnostics} from '@codemirror/lint';
import {clashCompletions} from './completion.mjs';
import {serializeDocument,replaceDocument} from './document.mjs';
import {scriptCompletions} from './script-completion.mjs';
import {detectLanguage,nativeErrorLocation} from './language.mjs';

let view,revision=0,currentLanguage='yaml',initialText='',initialDoc,lastStatus='',statusTimer,mode='auto',scriptScope='';
const themeSlot=new Compartment(),languageSlot=new Compartment(),wrapSlot=new Compartment(),readOnlySlot=new Compartment();
function diagnostics(view){
  if(currentLanguage==='json')return jsonParseLinter()(view);
  const results=[];
  syntaxTree(view.state).iterate({enter(node){if(node.type.isError&&results.length<50)results.push({from:node.from,to:node.to,severity:'error',message:currentLanguage==='javascript'?'JavaScript 语法不完整，请试运行以查看原生结果':'YAML 语法不完整，请校验配置以查看原生解析结果'});}});
  return results;
}
function grammar(name){
  currentLanguage=name;
  if(name==='javascript')return [javascript(),javascriptLanguage.data.of({autocomplete:scriptCompletions}),autocompletion({icons:false}),linter(diagnostics,{delay:600})];
  return [name==='json'?json():yaml(),autocompletion({override:[clashCompletions(name)],icons:false}),linter(diagnostics,{delay:600})];
}
function palette(p){
  return [EditorView.theme({
    '&':{color:p.text,backgroundColor:p.field},'.cm-content':{caretColor:p.primary},'.cm-cursor,.cm-dropCursor':{borderLeftColor:p.primary},
    '.cm-gutters':{backgroundColor:p.surface,color:p.textMuted,borderRightColor:p.border},'.cm-activeLineGutter,.cm-activeLine':{backgroundColor:p.primarySoft},
    '.cm-selectionBackground,.cm-content ::selection':{background:p.primaryBorder+'88'},'&.cm-focused .cm-selectionBackground':{background:p.primaryBorder+'88'},
    '.cm-tooltip':{backgroundColor:p.surface,color:p.text,borderColor:p.border},'.cm-tooltip-autocomplete > ul > li[aria-selected]':{backgroundColor:p.primary,color:p.onPrimary},
    '.cm-panels':{backgroundColor:p.surface,color:p.text,borderColor:p.border},'.cm-search input':{backgroundColor:p.field,color:p.text,border:'1px solid '+p.border},
    '.cm-search button':{background:p.field,color:p.text,border:'1px solid '+p.border},'.cm-foldPlaceholder':{background:p.surface,color:p.textMuted,borderColor:p.border}
  },{dark:p.dark}),syntaxHighlighting(HighlightStyle.define([
    {tag:[tags.propertyName,tags.definition(tags.propertyName)],color:p.primary},
    {tag:[tags.string,tags.special(tags.string)],color:p.success},
    {tag:[tags.number,tags.bool,tags.null,tags.keyword],color:p.purple},
    {tag:tags.comment,color:p.textMuted,fontStyle:'italic'},
    {tag:[tags.punctuation,tags.separator],color:p.textSecondary},
    {tag:[tags.meta,tags.labelName],color:p.warning}
  ]))];
}
function status(){
  if(!view)return;
  const pos=view.state.selection.main.head,line=view.state.doc.lineAt(pos);
  const data=JSON.stringify({line:line.number,column:pos-line.from+1,lines:view.state.doc.lines,language:currentLanguage,dirty:!view.state.doc.eq(initialDoc),revision});
  if(data!==lastStatus){lastStatus=data;try{window.clashosEditorBridge?.status(data);}catch(_){}}
}
function mount(options){
  if(view)return false;
  initialText=options.text;
  mode=options.language==='javascript'?'javascript':'auto';scriptScope=options.scriptScope||'';
  // Preserve the document's original line separator when serializing. CM's
  // internal line tree uses LF, including for CRLF input and native edits.
  view=new EditorView({parent:document.getElementById('editor'),state:EditorState.create({doc:initialText,extensions:[
    basicSetup,keymap.of([indentWithTab]),EditorState.phrases.of({'Find':'查找','Replace':'替换','next':'下一个','previous':'上一个','all':'全部','match case':'区分大小写','regexp':'正则','by word':'整词','replace':'替换','replace all':'全部替换','close':'关闭'}),EditorView.contentAttributes.of({'aria-label':options.label||'Clash YAML / JSON 配置编辑区',spellcheck:'false',autocapitalize:'off',autocomplete:'off'}),
    languageSlot.of(grammar(detectLanguage(initialText,mode))),themeSlot.of(palette(options.theme)),wrapSlot.of(EditorView.lineWrapping),readOnlySlot.of([]),
    EditorView.updateListener.of(update=>{
      if(update.docChanged){revision++;const next=detectLanguage(update.state.doc.sliceString(0,Math.min(256,update.state.doc.length)),mode);if(next!==currentLanguage)queueMicrotask(()=>view.dispatch({effects:languageSlot.reconfigure(grammar(next))}));}
      if(update.docChanged||update.selectionSet){clearTimeout(statusTimer);statusTimer=setTimeout(status,60);}
    })
  ]})});initialDoc=view.state.doc;status();return true;
}
function snapshot(){
  if(!view)throw Error('Editor not initialized');
  return {text:serializeDocument(view.state.doc,initialDoc,initialText),revision,composing:view.composing};
}
function command(name,value){
  if(!view)return false;
  switch(name){
    case 'complete':view.focus();return startCompletion(view);
    case 'search':return openSearchPanel(view);
    case 'undo':return undo(view);
    case 'redo':return redo(view);
    case 'clear':if(view.state.readOnly)return false;view.dispatch({changes:{from:0,to:view.state.doc.length,insert:''},selection:{anchor:0},userEvent:'input.delete'});view.focus();return true;
    case 'wrap':view.dispatch({effects:wrapSlot.reconfigure(value?EditorView.lineWrapping:[])});return true;
    case 'readonly':view.dispatch({effects:readOnlySlot.reconfigure([EditorState.readOnly.of(!!value),EditorView.editable.of(!value)])});return true;
    case 'goto':{
      const line=view.state.doc.line(Math.min(view.state.doc.lines,Math.max(1,Math.floor(value))));
      view.dispatch({selection:{anchor:line.from},scrollIntoView:true});view.focus();return true;
    }
  }
  return false;
}
function markError(message){
  if(!view)return;
  const position=nativeErrorLocation(message,currentLanguage,scriptScope);
  if(!position)return;
  const line=view.state.doc.line(Math.max(1,Math.min(position.line,view.state.doc.lines)));
  const from=Math.min(line.to,line.from+Math.max(0,position.column-1));
  view.dispatch(setDiagnostics(view.state,[{from,to:Math.min(line.to,from+1),severity:'error',message}]));command('goto',line.number);
}
function replace(text){
  return replaceDocument(view,text);
}
window.ClashOSEditor=Object.freeze({mount,snapshot,command,replace,markError,setTheme(theme){if(view)view.dispatch({effects:themeSlot.reconfigure(palette(theme))});}});
