import {lazy,Suspense,useEffect,useMemo,useRef,useState} from 'react'
import type {FormEvent} from 'react'
import {ArrowLeft,ArrowRight,Network,Pause,Play,RefreshCw,Search} from 'lucide-react'
import {api,bytes,time,getDisplayTimeZone} from './api'
import type {Service,User} from './api'
import {Badge,Button,Empty,Modal,Notice} from './ui'
import {trafficBytes,trafficHex,trafficQuery,wafLabel,wafReasonLabel,captureReasonLabel} from './proxyTypes'
import type {TrafficBody,TrafficExchange,TrafficFilters,TrafficPage} from './proxyTypes'
const Packets=lazy(()=>import('./Packets'))
const Flows=lazy(()=>import('./Flows'))
const ProtocolDecoder=lazy(()=>import('./Flows').then(module=>({default:module.ProtocolDecoder})))

const initialFilters:TrafficFilters={services:[],route:'',from:'',until:'',ip:'',method:'',status:'',url:'',waf:''}
const errorText=(error:unknown)=>error instanceof Error?error.message:'Не удалось получить трафик'
const decisionTone=(value:string):'neutral'|'good'|'warn'|'bad'=>['banned','deny','blocked','rate_limited','state_full'].includes(value)?'bad':['observe','would_block','degraded'].includes(value)?'warn':['allow','allowed','exempt','exception'].includes(value)?'good':'neutral'

export default function Traffic({services,user,initialServiceID}:{services:Service[];user:User;initialServiceID?:string}){
  const [tab,setTab]=useState<'http'|'packets'|'flows'>('http')
  const tabs=[{id:'http',label:'HTTP'},{id:'packets',label:'Пакеты TCP / UDP'},{id:'flows',label:'TCP-потоки / gRPC'}] as const
  if(initialServiceID)return <HTTPTraffic services={services} user={user} initialServiceID={initialServiceID}/>
  return <><div className="tabs traffic-tabs" role="tablist" aria-label="Вид сетевого трафика">{tabs.map(item=><button key={item.id} id={`traffic-${item.id}-tab`} role="tab" type="button" aria-selected={tab===item.id} aria-controls={`traffic-${item.id}-panel`} className={tab===item.id?'tab-active':''} onClick={()=>setTab(item.id)}>{item.label}</button>)}</div><div role="tabpanel" id={`traffic-${tab}-panel`} aria-labelledby={`traffic-${tab}-tab`}>{tab==='http'?<HTTPTraffic services={services} user={user}/>:<Suspense fallback={<Empty>Загружаем просмотр трафика…</Empty>}>{tab==='packets'?<Packets services={services} user={user}/>:<Flows services={services} user={user}/>}</Suspense>}</div></>
}

function HTTPTraffic({services,user,initialServiceID}:{services:Service[];user:User;initialServiceID?:string}){
  const defaultFilters=initialServiceID?{...initialFilters,services:[initialServiceID]}:initialFilters
  const [draft,setDraft]=useState<TrafficFilters>(defaultFilters),[filters,setFilters]=useState<TrafficFilters>(defaultFilters)
  const [cursor,setCursor]=useState<string|undefined>(),[previous,setPrevious]=useState<(string|undefined)[]>([])
  const [live,setLive]=useState(true),[refresh,setRefresh]=useState(0),[busy,setBusy]=useState(false)
  const [page,setPage]=useState<TrafficPage|null>(null),[error,setError]=useState(''),[selected,setSelected]=useState<TrafficExchange|null>(null)
  const lastRequest=useRef('')
  const zone=getDisplayTimeZone()
  const query=useMemo(()=>trafficQuery(filters,cursor,zone),[filters,cursor,zone])
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const requestKey=query+'\0'+refresh
    const unchanged=lastRequest.current===requestKey
    lastRequest.current=requestKey
    if(!live&&unchanged){setBusy(false);return}
    const load=async()=>{
      setBusy(true)
      try{const value=await api<TrafficPage>('/api/traffic?'+query,{signal:controller.signal});if(active){setPage(value);setError('')}}catch(error){if(active)setError(errorText(error))}
      finally{if(active){setBusy(false);if(live&&!cursor)timer=setTimeout(()=>void load(),2000)}}
    }
    void load()
    return()=>{active=false;clearTimeout(timer);controller.abort()}
  },[query,refresh,live,cursor])
  const apply=(event:FormEvent)=>{event.preventDefault();setFilters({...draft,services:[...draft.services]});setCursor(undefined);setPrevious([]);setPage(null);setSelected(null);setRefresh(value=>value+1)}
  const change=<K extends keyof TrafficFilters>(key:K,value:TrafficFilters[K])=>setDraft(current=>({...current,[key]:value}))
  const records=page?.records||[]
  const serviceName=(id:string)=>services.find(service=>service.id===id)?.name||id
  return <div className="traffic-view">
    <div className="page-title"><div><h1>{initialServiceID?'HTTP-трафик':'Трафик'}</h1><p>HTTP-запросы и ответы, прошедшие через подключённые маршруты.</p></div><div className="page-actions"><Button variant="outline" onClick={()=>{setLive(value=>!value);if(cursor){setCursor(undefined);setPrevious([])}}}>{live?<Pause size={15}/>:<Play size={15}/>} {live?'Пауза':'Включить live'}</Button><Button variant="outline" busy={busy} onClick={()=>setRefresh(value=>value+1)}><RefreshCw size={15}/>Обновить</Button></div></div>
    <section className="panel traffic-filters"><form onSubmit={apply}>
      <div className="traffic-filter-top"><label>Сервисы<select multiple aria-label="Сервисы в журнале трафика" value={draft.services} onChange={event=>change('services',Array.from(event.target.selectedOptions,option=>option.value))}>{services.map(service=><option value={service.id} key={service.id}>{service.name}</option>)}</select><small>Без выбора — все сервисы. Несколько: Ctrl / ⌘.</small></label><div className="traffic-filter-dates"><label>От<input type="datetime-local" value={draft.from} onChange={event=>change('from',event.target.value)}/></label><label>До<input type="datetime-local" value={draft.until} onChange={event=>change('until',event.target.value)}/></label><small>{zone==='UTC'?'Ввод времени UTC.':'Часовой пояс браузера.'}</small></div><label>IP / CIDR<input value={draft.ip} onChange={event=>change('ip',event.target.value)} placeholder="192.0.2.0/24" maxLength={64}/><small>Эффективный адрес клиента.</small></label></div>
      <div className="traffic-filter-bottom"><label>Метод<select value={draft.method} onChange={event=>change('method',event.target.value)}><option value="">Все методы</option>{['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT','TRACE'].map(method=><option key={method}>{method}</option>)}</select></label><label>HTTP status<input value={draft.status} onChange={event=>change('status',event.target.value)} placeholder="200 или 4xx" maxLength={3}/></label><label>Решение WAF<select value={draft.waf} onChange={event=>change('waf',event.target.value)}><option value="">Все решения</option>{['allowed','would_block','blocked','exception','off','not_evaluated'].map(value=><option value={value} key={value}>{wafLabel(value)}</option>)}</select></label><label>Маршрут<input value={draft.route} onChange={event=>change('route',event.target.value)} placeholder="ID маршрута" maxLength={128}/></label><label className="traffic-url-filter">URL содержит<input value={draft.url} onChange={event=>change('url',event.target.value)} placeholder="/api/" maxLength={256}/></label><Button type="submit" variant="outline"><Search size={15}/>Применить</Button><Button type="button" variant="ghost" onClick={()=>{setDraft(defaultFilters);setFilters(defaultFilters);setCursor(undefined);setPrevious([]);setPage(null);setRefresh(value=>value+1)}}>Сбросить</Button></div>
    </form></section>
    {error&&<Notice variant="error">{error}{page&&' Показаны последние полученные записи.'}</Notice>}
    {page?.counters.last_error&&<Notice variant="warning">{page.counters.last_error}</Notice>}
    {page?.counters.previous_epoch_counters_unknown&&<Notice>Счётчики относятся к текущей эпохе recorder. Значения до его последнего запуска неизвестны.</Notice>}
    {page?.gap&&<Notice variant="warning">Часть записей уже удалена ротацией. В журнале есть пропуск; показаны доступные данные.</Notice>}

    <div className="traffic-status"><div><span className={`service-dot ${live&&!cursor&&!error?'dot-live':''}`}/><strong>{error?'Связь с журналом нарушена':live&&!cursor?'Live · каждые 2 с':'Просмотр приостановлен'}</strong><span>{filters.services.length?`${filters.services.length} сервис(а)`:'Все сервисы'}</span></div><span>{page?.counters.retention_seconds?`Хранение до ${Math.round(page.counters.retention_seconds/60)} мин`:'Ограниченное окно хранения'}{page?.epoch&&` · epoch ${page.epoch.slice(0,12)}`}</span></div>
    {!!page?.counters&&<div className="traffic-counters">{Object.entries(page.counters.counters).map(([name,value])=><span key={name}>{({ingested:'Получено',updated:'Обновлений',rejected:'Не принято',write_errors:'Ошибки записи',rotated:'Удалено ротацией',completed:'Завершено',aborted:'Прервано',waf_denied:'Отклонено WAF',upstream_errors:'Ошибки upstream'} as Record<string,string>)[name]||name}: <strong>{name.endsWith('_bytes')?bytes(value):value.toLocaleString('ru-RU')}</strong></span>)}</div>}
    {page&&<p className="traffic-retention-facts">В хранилище: {page.counters.stored_records.toLocaleString('ru-RU')} записей · данные {bytes(page.counters.stored_bytes)} / {bytes(page.counters.payload_budget_bytes)} · диск {bytes(page.counters.disk_bytes)} / {bytes(page.counters.quota_bytes)} на диске.</p>}
    <section className="panel traffic-table"><div className="table-wrap"><table><thead><tr><th>Время / запрос</th><th>Сервис / маршрут</th><th>Клиент</th><th>HTTP / URL</th><th>Ответ</th><th>Время / объём</th><th>WAF</th><th/></tr></thead><tbody>{records.map(record=><tr key={record.request_id} onClick={()=>setSelected(record)}><td title={record.at}>{time(record.at)}<small className="mono">{record.request_id.slice(0,12)}</small></td><td>{serviceName(record.service_id)}<small className="mono">{record.route_id}</small></td><td className="mono">{record.client_ip||'—'}</td><td><strong>{record.method}</strong><small className="traffic-url" title={record.url}>{record.url}</small></td><td><Badge tone={record.status>=500?'bad':record.status>=400?'warn':'neutral'}>{record.status||'…'}</Badge><small>{record.state==='in_progress'?'Передаётся':record.state==='aborted'?'Прерван':record.response_source==='proxy'?'Ответ proxy':'Ответ upstream'}{record.truncated?' · усечено':''}{record.dropped?' · пропуск записи':''}{record.recorder_unavailable?' · recorder недоступен':''}</small></td><td>{Number.isFinite(record.duration_ms)?`${record.duration_ms.toFixed(1)} мс`:'—'}<small>↑ {bytes(record.request_bytes||0)} · ↓ {bytes(record.response_bytes||0)}</small></td><td><Badge tone={decisionTone(record.waf_decision)}>{wafLabel(record.waf_decision)}</Badge></td><td><Button variant="ghost" aria-label={`Открыть обмен ${record.request_id}`} onClick={event=>{event.stopPropagation();setSelected(record)}}><ArrowRight size={14}/></Button></td></tr>)}</tbody></table></div>{!records.length&&<Empty icon={<Network size={27}/>}><strong>{busy?'Получаем трафик…':error?'Журнал недоступен':'Сохранённых обменов по этим фильтрам нет'}</strong><span>Записи относятся к подключённым HTTP-маршрутам и доступному окну хранения.</span></Empty>}</section>
    <div className="traffic-pagination"><Button variant="outline" disabled={busy||!previous.length} onClick={()=>{setLive(false);setCursor(previous[previous.length-1]);setPrevious(value=>value.slice(0,-1));setPage(null)}}><ArrowLeft size={14}/>Новее</Button><span>{records.length} записей · страница {previous.length+1}</span><Button variant="outline" disabled={busy||!page?.next_cursor} onClick={()=>{if(!page?.next_cursor)return;setLive(false);setPrevious(value=>[...value,cursor]);setCursor(page.next_cursor);setPage(null)}}>Старее<ArrowRight size={14}/></Button></div>
    {selected&&<TrafficDetail metadata={selected} user={user} serviceName={serviceName} onClose={()=>setSelected(null)}/>}
  </div>
}

function TrafficDetail({metadata,user,serviceName,onClose}:{metadata:TrafficExchange;user:User;serviceName:(id:string)=>string;onClose:()=>void}){
  const id=metadata.request_id
  const [value,setValue]=useState<TrafficExchange|null>(null),[error,setError]=useState('')
  useEffect(()=>{
    if(!user.sensitive_access){setValue(metadata);setError('');return}
    setValue(null)
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const refresh=async()=>{try{const result=await api<TrafficExchange>('/api/traffic/'+encodeURIComponent(id),{signal:controller.signal});if(active){setValue(result);setError('')}}catch(error){if(active){setValue(null);setError(errorText(error))}}finally{if(active)timer=setTimeout(()=>void refresh(),2000)}}
    void refresh();return()=>{active=false;clearTimeout(timer);controller.abort()}
  },[id,user.sensitive_access,metadata])
  return <Modal open onClose={onClose} title="HTTP-обмен" description="Сохранённые данные запроса и ответа." wide><div className="dialog-body traffic-detail">{error&&<Notice variant="error">{error}</Notice>}{!value&&!error&&<Empty>Получаем обмен…</Empty>}{value&&<>
    <div className="traffic-detail-heading"><code>{value.method} {value.url}</code><Badge tone={decisionTone(value.waf_decision)}>{wafLabel(value.waf_decision)}</Badge></div>
    <div className="facts-grid"><DetailFact label="Сервис / маршрут" value={`${serviceName(value.service_id)} · ${value.route_id}`}/><DetailFact label="Запрос" value={value.request_id}/><DetailFact label="Время" value={time(value.at)}/><DetailFact label="Состояние / ответ" value={`${value.state} · ${value.status||'ожидание'} · ${value.response_source||'—'}`}/><DetailFact label="Клиент / источник IP" value={`${value.client_ip} · ${value.client_ip_source||'TCP peer'}`}/><DetailFact label="TCP peer" value={value.peer_ip||'—'}/><DetailFact label="Длительность" value={`${value.duration_ms.toFixed(1)} мс`}/><DetailFact label="Ревизия политики" value={String(value.policy_revision??'—')}/></div>
    {value.waf_reason&&<Notice>{wafReasonLabel(value.waf_reason)}</Notice>}{value.error&&<Notice variant="warning">{value.error}</Notice>}{value.recorder_unavailable&&<Notice variant="warning">Recorder был недоступен; часть данных обмена не сохранена.</Notice>}
    {user.sensitive_access&&value.http_protocol==='h2'&&<Suspense fallback={<p>Загружаем разбор gRPC…</p>}><ProtocolDecoder endpoint={'/api/traffic/'+encodeURIComponent(id)+'/decode'} request={{}} user={user}/></Suspense>}
    {user.sensitive_access?<div className="traffic-payload-grid"><section><h3>Запрос · {bytes(value.request_bytes)}</h3><Headers headers={value.request_headers}/><Body body={value.request_body}/><Headers headers={value.request_trailers}/></section><section><h3>Ответ · {bytes(value.response_bytes)}</h3><Headers headers={value.response_headers}/><Body body={value.response_body}/><Headers headers={value.response_trailers}/></section></div>:<Notice>Для заголовков и тел обмена нужен доступ к чувствительным данным. Отредактированные метаданные доступны вашей роли.</Notice>}
  </>}</div></Modal>
}

function DetailFact({label,value}:{label:string;value:string}){return <div className="fact"><span>{label}</span><code>{value}</code></div>}
function Headers({headers}:{headers?:Record<string,string[]>}){return <details className="traffic-headers"><summary>Заголовки</summary>{headers&&Object.keys(headers).length?<pre>{Object.entries(headers).map(([key,values])=>values.map(value=>`${key}: ${value}`).join('\n')).join('\n')}</pre>:<p className="muted">Заголовки не сохранены.</p>}</details>}
function Body({body}:{body?:TrafficBody}){
  const [mode,setMode]=useState<'text'|'hex'>('text')
  const raw=useMemo(()=>body?trafficBytes(body):new Uint8Array(),[body])
  if(!body)return <p className="muted">Тело не захвачено.</p>
  return <div className="traffic-body"><div className="traffic-body-heading"><span>{body.content_type||'Тип не указан'}</span><div><Button variant={mode==='text'?'outline':'ghost'} onClick={()=>setMode('text')}>Текст</Button><Button variant={mode==='hex'?'outline':'ghost'} onClick={()=>setMode('hex')}>Hex</Button></div></div>{body.sensitive_raw&&<Notice variant="warning">Сохранены неотредактированные байты gRPC. Они могут содержать игровые секреты.</Notice>}<p className="muted">Наблюдалось {bytes(body.observed_bytes)} · сохранено {bytes(body.captured_bytes)}{body.content_encoding&&` · ${body.content_encoding}`}{body.truncated&&' · усечено'}</p>{body.not_captured_reason&&<Notice>{captureReasonLabel(body.not_captured_reason)}</Notice>}{raw.length>0?<pre>{mode==='hex'?trafficHex(raw):new TextDecoder('utf-8',{fatal:false}).decode(raw)}</pre>:<p className="muted">Сохранённых байтов нет.</p>}</div>
}
