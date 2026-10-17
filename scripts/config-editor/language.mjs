export function detectLanguage(text,mode='auto') {
  if(mode==='javascript')return 'javascript';
  return /^[\s\uFEFF]*[\[{]/.test(text)?'json':'yaml';
}

export function nativeErrorLocation(message,language,scope='') {
  if(language==='javascript'){
    // Only a stack frame from the edited extension can identify its source
    // location. A failure in the other extension or generated YAML cannot.
    const frames=[...message.matchAll(/\b(global|profile)-script\.js:(\d+)(?::(\d+))?/g)];
    const frame=frames.find(x=>!scope||x[1]===scope);
    return frame?{line:Number(frame[2]),column:Number(frame[3]||1)}:null;
  }
  const match=/line\s+(\d+)(?:\s*[,，:]?\s*column\s+(\d+))?/i.exec(message)||/第?\s*(\d+)\s*行/.exec(message);
  return match?{line:Number(match[1]),column:Number(match[2]||1)}:null;
}
