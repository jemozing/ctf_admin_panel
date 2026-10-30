import type {LogRecord} from './api'

// Identity includes the actual container, timestamp and stream. Repeated WS
// windows and reconnects must never append a second copy of an observed record.
export function mergeLogRecords(previous:LogRecord[],incoming:LogRecord[],limit=2000,byteLimit=512*1024){
  const unique=new Map(previous.map(record=>[record.id,record]))
  for(const record of incoming)unique.set(record.id,record)
  const sorted=[...unique.values()].sort((a,b)=>((Date.parse(a.at||'')||0)-(Date.parse(b.at||'')||0))||(a.at||'').localeCompare(b.at||'')||a.id.localeCompare(b.id))
  let bytes=0,start=sorted.length
  while(start>0&&sorted.length-start<limit){const size=new TextEncoder().encode(sorted[start-1].text).length;if(bytes+size>byteLimit)break;bytes+=size;start--}
  return {records:sorted.slice(start),omitted:start>0}
}

export function highlightParts(text:string,search:string):{text:string;match:boolean}[]{
  if(!search)return [{text,match:false}]
  const lower=text.toLocaleLowerCase(),needle=search.toLocaleLowerCase(),result:{text:string;match:boolean}[]=[]
  let cursor=0,index=lower.indexOf(needle)
  while(index>=0){if(index>cursor)result.push({text:text.slice(cursor,index),match:false});result.push({text:text.slice(index,index+search.length),match:true});cursor=index+search.length;index=lower.indexOf(needle,cursor)}
  if(cursor<text.length)result.push({text:text.slice(cursor),match:false})
  return result
}
