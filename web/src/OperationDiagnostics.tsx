import {useEffect,useRef,useState} from 'react'
import {api,bytes,label,time} from './api'
import type {DiagnosticChunk,DiagnosticLog} from './api'
import {Badge,Notice} from './ui'
export default function OperationDiagnostics({operationID}:{operationID:string}){
 const[chunks,setChunks]=useState<DiagnosticChunk[]>([]),[error,setError]=useState(''),[dropped,setDropped]=useState(0),[clientLimited,setClientLimited]=useState(false)
 const buffer=useRef<DiagnosticChunk[]>([])
 useEffect(()=>{
  let active=true,cursor=0,timer:ReturnType<typeof setTimeout>|undefined;const controller=new AbortController();buffer.current=[];setChunks([]);setDropped(0);setError('');setClientLimited(false)
  const refresh=async()=>{let more=false;try{const result=await api<DiagnosticLog>(`/api/operations/${operationID}/diagnostics?after=${cursor}`,{signal:controller.signal});if(!active)return;setDropped(result.dropped_bytes);setError('');cursor=result.next_sequence;more=result.has_more;const values=[...new Map([...buffer.current,...result.chunks].map(chunk=>[chunk.sequence,chunk])).values()];let size=0,start=values.length;while(start>0&&size+new TextEncoder().encode(values[start-1].content).length<=512*1024){size+=new TextEncoder().encode(values[start-1].content).length;start--}if(start>0)setClientLimited(true);buffer.current=values.slice(start);setChunks(buffer.current)}catch(error){if(active)setError(error instanceof Error?error.message:'Вывод недоступен')}finally{if(active)timer=setTimeout(()=>void refresh(),more?100:2000)}}
  void refresh();return()=>{active=false;controller.abort();clearTimeout(timer)}
 },[operationID])
 return <section className="operation-diagnostics"><h3>Вывод сборки и переключения</h3>{error&&<Notice variant="error">{error}</Notice>}{dropped>0&&<Notice variant="warning">По политике хранения удалено {bytes(dropped)} диагностического вывода. Критический журнал операции сохранён.</Notice>}{clientLimited&&<Notice variant="warning">Во вкладке оставлены последние 512 KiB вывода.</Notice>}<div className="diagnostic-output">{chunks.length?chunks.map(chunk=><div key={chunk.sequence}><div><time title={chunk.at}>{time(chunk.at)}</time> <Badge>{label(chunk.stage)}</Badge></div><pre>{chunk.content}</pre></div>):<p className="muted">Диагностический вывод пока отсутствует.</p>}</div></section>
}
