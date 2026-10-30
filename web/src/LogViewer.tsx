import {useEffect,useMemo,useRef,useState} from 'react'
import type {FormEvent} from 'react'
import {Pause,Play,RefreshCw,Terminal} from 'lucide-react'
import {api,short,time} from './api'
import type {Details,LogPage,LogRecord} from './api'
import {mergeLogRecords,highlightParts} from './logHistory'
import {Badge,Button,Empty,Notice} from './ui'

const emptyFilters={component:'*',search:'',include:'',exclude:'',since:'',until:'',tail:200}
export default function LogViewer({details,sensitiveAccess}:{details:Details;sensitiveAccess:boolean}){
 const [draft,setDraft]=useState(emptyFilters),[filters,setFilters]=useState(emptyFilters),[paused,setPaused]=useState(false),[live,setLive]=useState(false),[loading,setLoading]=useState(false)
 const [records,setRecords]=useState<LogRecord[]>([]),[page,setPage]=useState<LogPage|null>(null),[error,setError]=useState(''),[omitted,setOmitted]=useState(false),[revision,setRevision]=useState(0)
 const buffer=useRef<LogRecord[]>([])
 const query=useMemo(()=>{const v=new URLSearchParams({component:filters.component,tail:String(filters.tail)});for(const key of ['search','include','exclude','since','until'] as const){const value=filters[key];if(value)v.set(key,key==='since'||key==='until'?new Date(value).toISOString():value)};return v.toString()},[filters])
 useEffect(()=>{buffer.current=[];setRecords([]);setOmitted(false);setPage(null)},[details.service.id,query,revision])
 useEffect(()=>{
  if(!sensitiveAccess||paused)return
  let closed=false,socket:WebSocket|undefined,retry:ReturnType<typeof setTimeout>|undefined
  const controller=new AbortController()
  const accept=(value:LogPage)=>{if(closed)return;setPage(value);setError('');const merged=mergeLogRecords(buffer.current,value.records||[]);buffer.current=merged.records;setRecords(merged.records);if(merged.omitted)setOmitted(true)}
  setLoading(true)
  api<LogPage>(`/api/services/${details.service.id}/log-records?${query}`,{signal:controller.signal}).then(accept).catch(error=>{if(!closed)setError(error instanceof Error?error.message:'Логи недоступны')}).finally(()=>{if(!closed)setLoading(false)})
  const connect=()=>{
   const v=new URLSearchParams(query);v.set('service_id',details.service.id);v.set('format','records')
   socket=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/api/stream?${v}`)
   socket.onopen=()=>setLive(true)
   socket.onmessage=event=>{try{const value=JSON.parse(event.data) as {log_records?:LogPage;logs_error?:string;truncated?:boolean};if(value.log_records)accept(value.log_records);if(value.logs_error)setError(value.logs_error);if(value.truncated){setOmitted(true);setError('Поток превысил размер сообщения. Уменьшите число строк или выберите компонент.')}}catch{setError('Некорректный ответ потока')}}
   socket.onclose=()=>{setLive(false);if(!closed)retry=setTimeout(connect,5000)}
  };connect()
  return()=>{closed=true;controller.abort();clearTimeout(retry);socket?.close();setLive(false)}
 },[details.service.id,query,paused,sensitiveAccess,revision])
 const submit=(event:FormEvent)=>{event.preventDefault();setFilters({...draft});setRevision(value=>value+1)}
 if(!sensitiveAccess)return <Empty icon={<Terminal/>}>Доступ к логам выдаёт администратор команды.</Empty>
 return <div className="panel"><div className="panel-heading"><div><h2><Terminal size={17}/>Логи сервиса</h2><p>Текущие контейнеры · stdout/stderr · порядок по времени Docker, без гарантии общего порядка событий.</p></div><div className="page-actions"><Badge tone={paused?'warn':live?'good':'neutral'}>{paused?'Пауза':live?'Live':'Переподключение'}</Badge><Button variant="outline" onClick={()=>setPaused(value=>!value)}>{paused?<Play size={14}/>:<Pause size={14}/>} {paused?'Продолжить':'Пауза'}</Button><Button variant="ghost" aria-label="Обновить логи" onClick={()=>setRevision(value=>value+1)}><RefreshCw size={14}/></Button></div></div>
 <form className="log-filters" onSubmit={submit}><label>Компонент<select value={draft.component} onChange={event=>setDraft({...draft,component:event.target.value})}><option value="*">Все компоненты</option>{details.service.containers.map(value=><option key={value.component}>{value.component}</option>)}</select></label><label>Текстовый поиск<input maxLength={256} value={draft.search} onChange={event=>setDraft({...draft,search:event.target.value})}/></label><label>Include · RE2<input maxLength={256} value={draft.include} onChange={event=>setDraft({...draft,include:event.target.value})} placeholder="error|warning"/></label><label>Exclude · RE2<input maxLength={256} value={draft.exclude} onChange={event=>setDraft({...draft,exclude:event.target.value})}/></label><label>С момента<input type="datetime-local" value={draft.since} onChange={event=>setDraft({...draft,since:event.target.value})}/></label><label>До момента<input type="datetime-local" value={draft.until} onChange={event=>setDraft({...draft,until:event.target.value})}/></label><label>Строк на компонент<select value={draft.tail} onChange={event=>setDraft({...draft,tail:Number(event.target.value)})}><option value={100}>100</option><option value={200}>200</option><option value={500}>500 · предыдущие строки</option></select></label><Button type="submit" busy={loading}>Применить фильтры</Button></form>
 {error&&<Notice variant="error">{error}</Notice>}{paused&&<Notice>Отображение приостановлено. После продолжения будет запрошен текущий ограниченный хвост; полный архив за время паузы не гарантируется.</Notice>}
 {(page?.truncated||omitted)&&<Notice variant="warning">Вывод неполный: достигнут лимит чтения, строки или буфера. Используйте фильтр времени и отдельный компонент.</Notice>}
 {!!page?.sources.length&&<div className="log-sources">{page.sources.map(source=><div key={`${source.component}:${source.container_id}`}><Badge>{source.component} · {source.driver||'driver неизвестен'}{source.tty?' · TTY combined':''}</Badge><code>{short(source.container_id)}</code>{source.error&&<span className="text-warning">{source.error}</span>}</div>)}</div>}
 <div className="structured-logs" role="log" aria-label="Записи логов">{records.length?records.map(record=><div className="structured-log-row" key={record.id}><time title={record.at||'Docker не предоставил время'}>{record.at?time(record.at):'Без времени'}</time><span className="log-source" title={record.container_id}>{record.component} · {record.stream}<small>{short(record.container_id)}</small></span><pre>{highlightParts(record.text,filters.search).map((part,index)=>part.match?<mark key={index}>{part.text}</mark>:part.text)}{record.truncated&&<span className="text-warning"> … [строка усечена]</span>}</pre></div>):<Empty>{loading?'Загрузка логов…':'Записей для выбранного фильтра нет.'}</Empty>}</div>
 <p className="muted section-note">Храним в этой вкладке до 2 000 записей / 512 KiB; один ответ — до 500 записей. Старые контейнеры и logging driver могут не предоставлять прошлый вывод. Пересоздание обнаруживается по новому container ID.</p>
 </div>
}
