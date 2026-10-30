import {useEffect,useMemo,useRef,useState} from 'react'
import type {FormEvent} from 'react'
import {ArrowLeft,ArrowRight,Download,Network,Pause,Play,RefreshCw,Search,Settings} from 'lucide-react'
import {api,bytes,getDisplayTimeZone,postBlob,time} from './api'
import type {Service,User} from './api'
import {Badge,Button,Empty,Modal,Notice} from './ui'
import {initialPacketFilters,localPacketTime,maxPCAPBytes,packetAddress,packetBytes,packetCaptureSelection,packetCaptureState,packetDirection,packetExportRequest,packetFilterQuery,packetFlags,packetHex,packetQueryString,packetReason} from './packetTypes'
import type {PacketCapturePreview,PacketCaptureTargets,PacketFilters,PacketMetadata,PacketPage,PacketPolicyView,PacketRecord,PacketStatus} from './packetTypes'

const errorText=(error:unknown)=>error instanceof Error?error.message:'Не удалось получить пакеты'

export default function Packets({services,user}:{services:Service[];user:User}){
  const [draft,setDraft]=useState<PacketFilters>(initialPacketFilters),[filters,setFilters]=useState<PacketFilters>(initialPacketFilters)
  const [cursor,setCursor]=useState<string|undefined>(),[previous,setPrevious]=useState<(string|undefined)[]>([])
  const [live,setLive]=useState(true),[refresh,setRefresh]=useState(0),[busy,setBusy]=useState(false)
  const [page,setPage]=useState<PacketPage|null>(null),[error,setError]=useState(''),[selected,setSelected]=useState<PacketMetadata|null>(null)
  const [exportOpen,setExportOpen]=useState(false),[configOpen,setConfigOpen]=useState(false)
  const [status,setStatus]=useState<PacketStatus|null>(null),[statusError,setStatusError]=useState('')
  const lastRequest=useRef(''),zone=getDisplayTimeZone()
  const query=useMemo(()=>packetQueryString(packetFilterQuery(filters,cursor,zone)),[filters,cursor,zone])
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController(),key=query+'\0'+refresh
    const unchanged=lastRequest.current===key;lastRequest.current=key
    if(!live&&unchanged){setBusy(false);return}
    const load=async()=>{
      setBusy(true)
      try{const result=await api<PacketPage>('/api/packets?'+query,{signal:controller.signal});if(active){setPage(result);setError('')}}catch(error){if(active){setError(errorText(error));setSelected(null)}}
      finally{if(active){setBusy(false);if(live&&!cursor)timer=setTimeout(()=>void load(),2000)}}
    }
    void load();return()=>{active=false;controller.abort();clearTimeout(timer)}
  },[query,refresh,live,cursor])
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const load=async()=>{try{const result=await api<PacketStatus>('/api/packets/status',{signal:controller.signal});if(active){setStatus(result);setStatusError('')}}catch(error){if(active)setStatusError(errorText(error))}finally{if(active)timer=setTimeout(()=>void load(),5000)}}
    void load();return()=>{active=false;controller.abort();clearTimeout(timer)}
  },[refresh])
  const change=<K extends keyof PacketFilters>(key:K,value:PacketFilters[K])=>setDraft(current=>({...current,[key]:value}))
  const apply=(event:FormEvent)=>{event.preventDefault();try{packetFilterQuery(draft,undefined,zone);setFilters({...draft,services:[...draft.services]});setError('');setCursor(undefined);setPrevious([]);setSelected(null);setPage(null);setRefresh(value=>value+1)}catch(error){setError(errorText(error))}}
  const reset=()=>{setDraft(initialPacketFilters);setFilters(initialPacketFilters);setCursor(undefined);setPrevious([]);setSelected(null);setPage(null);setError('');setRefresh(value=>value+1)}
  const serviceName=(id:string)=>services.find(service=>service.id===id)?.name||id
  const records=page?.records||[],components=[...new Set(services.filter(service=>!draft.services.length||draft.services.includes(service.id)).flatMap(service=>service.containers.map(container=>container.component)))].sort()
  return <div className="traffic-view packet-view">
    <div className="page-title"><div><h1>Пакеты TCP / UDP</h1><p>Пассивное наблюдение только за выбранными портами зарегистрированных сервисов.</p></div><div className="page-actions"><Button variant="outline" onClick={()=>{setLive(value=>!value);if(cursor){setCursor(undefined);setPrevious([])}}}>{live?<Pause size={15}/>:<Play size={15}/>} {live?'Пауза':'Включить live'}</Button><Button variant="outline" busy={busy} onClick={()=>setRefresh(value=>value+1)}><RefreshCw size={15}/>Обновить</Button>{user.sensitive_access&&<Button variant="outline" onClick={()=>setExportOpen(true)}><Download size={15}/>PCAP</Button>}{user.role==='admin'&&<Button variant="outline" onClick={()=>setConfigOpen(true)}><Settings size={15}/>Захват</Button>}</div></div>
    <Notice>Это отдельные наблюдения сетевых пакетов; возможны повторные передачи, потери и усечение. Для сборки TCP-потоков и разбора gRPC откройте вкладку «TCP-потоки / gRPC». TLS и другие зашифрованные данные не расшифровываются; WAF применяется только к HTTP-маршрутам. Если выбраны оба конца пакета, направление отмечается как неоднозначное; фильтры «к/от» включают только однозначное направление.</Notice>
    {(status||statusError)&&<section className="panel packet-status-panel"><h2>Состояние захвата</h2>{statusError?<Notice variant="error">{statusError}</Notice>:<><p>{status&&packetCaptureState(status)} {status?.capture&&<>Ревизия {status.capture.revision} · {status.capture.snaplen===0?'только метаданные':`до ${status.capture.snaplen} байт кадра`} · очередь {status.capture.queue_depth} / {status.capture.queue_capacity} · epoch {status.capture.epoch.slice(0,12)}.{status.capture.enabled&&status.capture.lease_until&&<> Подтверждение привязок до {time(status.capture.lease_until)}.</>}</>}</p>{(status?.error||status?.capture?.last_error)&&<Notice variant="warning">{status.error||status.capture?.last_error}</Notice>}{status?.capture&&<><div className="traffic-counters">{Object.entries(status.capture.counters).map(([key,value])=><span key={key}>{({observed:'Наблюдалось',matched:'Совпало',enqueued:'В очереди',stored:'Передано хранилищу',unmatched:'Вне выбранных целей',malformed:'Неразобранных',excluded:'Исключено',rate_dropped:'Потеря из-за PPS',queue_dropped:'Потеря очереди',sink_dropped:'Потеря доставки',duplicate_suppressed:'Подавлено дубликатов',source_errors:'Ошибки источника'} as Record<string,string>)[key]||key}: <strong>{value.toLocaleString('ru-RU')}</strong></span>)}</div><p>{!status.capture.kernel_drops_known&&'Потери в ядре неизвестны; нулевые счётчики не доказывают полноту захвата. '}{status.capture.previous_epoch_counters_unknown&&'Счётчики до последнего запуска collector неизвестны.'}</p></>}</>}</section>}
    <section className="panel traffic-filters packet-filters"><form onSubmit={apply}>
      <div className="traffic-filter-top"><label>Сервисы<select multiple aria-label="Сервисы в журнале пакетов" value={draft.services} onChange={event=>change('services',Array.from(event.target.selectedOptions,option=>option.value))}>{services.map(service=><option value={service.id} key={service.id}>{service.name}</option>)}</select><small>Без выбора — все сервисы. Несколько: Ctrl / ⌘.</small></label><div className="traffic-filter-dates"><label>От<input type="datetime-local" step="1" value={draft.from} onChange={event=>change('from',event.target.value)}/></label><label>До<input type="datetime-local" step="1" value={draft.until} onChange={event=>change('until',event.target.value)}/></label><small>{zone==='UTC'?'Ввод времени UTC.':'Часовой пояс браузера.'}</small></div><label>IP / CIDR<input value={draft.ip} onChange={event=>change('ip',event.target.value)} placeholder="192.0.2.0/24 или 2001:db8::/32" maxLength={64}/><small>Источник или назначение пакета.</small></label></div>
      <div className="traffic-filter-bottom"><label>Компонент<select value={draft.component} onChange={event=>change('component',event.target.value)}><option value="">Все компоненты</option>{components.map(component=><option key={component}>{component}</option>)}</select></label><label>Протокол<select value={draft.protocol} onChange={event=>change('protocol',event.target.value)}><option value="">TCP и UDP</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label><label>Направление<select value={draft.direction} onChange={event=>change('direction',event.target.value)}><option value="">Все направления</option><option value="ingress">К сервису</option><option value="egress">От сервиса</option><option value="ambiguous">Неоднозначно: оба конца выбраны</option></select></label><label>Порт источника<input type="number" min="1" max="65535" value={draft.sourcePort} onChange={event=>change('sourcePort',event.target.value)} placeholder="Любой"/></label><label>Порт назначения<input type="number" min="1" max="65535" value={draft.destinationPort} onChange={event=>change('destinationPort',event.target.value)} placeholder="Любой"/></label><Button type="submit" variant="outline"><Search size={15}/>Применить</Button><Button type="button" variant="ghost" onClick={reset}>Сбросить</Button></div>
    </form></section>
    {error&&<Notice variant="error">{error}{page&&' Показаны последние полученные метаданные.'}</Notice>}
    {page?.counters.last_error&&<Notice variant="warning">{page.counters.last_error}</Notice>}
    {page?.gap&&<Notice variant="warning">Курсор относится к удалённым данным или другой эпохе. Часть записей недоступна; показаны сохранившиеся пакеты.</Notice>}
    {page?.counters.previous_epoch_counters_unknown&&<Notice>Счётчики хранилища относятся к его текущей эпохе; значения до перезапуска неизвестны.</Notice>}
    <div className="traffic-status"><div><span className={`service-dot ${live&&!cursor&&!error?'dot-live':''}`}/><strong>{error?'Связь с журналом нарушена':live&&!cursor?'Live · каждые 2 с':'Просмотр приостановлен'}</strong><span>{filters.services.length?`${filters.services.length} сервис(а)`:'Все сервисы'}</span></div><span>{page?.counters.retention_seconds?`Хранение до ${Math.round(page.counters.retention_seconds/60)} мин`:'Ограниченное окно хранения'}{page?.epoch&&` · epoch ${page.epoch.slice(0,12)}`}</span></div>
    {page&&<><div className="traffic-counters">{Object.entries(page.counters.counters).map(([name,value])=><span key={name}>{({ingested:'Записано',rejected:'Не принято',write_errors:'Ошибки записи',rotated:'Удалено ротацией'} as Record<string,string>)[name]||name}: <strong>{value.toLocaleString('ru-RU')}</strong></span>)}</div><p className="traffic-retention-facts">В хранилище: {page.counters.stored_records.toLocaleString('ru-RU')} пакетов · данные {bytes(page.counters.stored_bytes)} / {bytes(page.counters.payload_budget_bytes)} · диск {bytes(page.counters.disk_bytes)} / {bytes(page.counters.quota_bytes)}.</p></>}
    <section className="panel traffic-table packet-table"><div className="table-wrap"><table><thead><tr><th>Время / пакет</th><th>Сервис / компонент</th><th>Интерфейс</th><th>Протокол</th><th>Источник → назначение</th><th>Размер</th><th/></tr></thead><tbody>{records.map(record=><tr key={record.packet_id} onClick={()=>setSelected(record)}><td title={record.at}>{time(record.at)}<small className="mono">{record.packet_id.slice(0,12)}</small></td><td><PacketAttribution packet={record} serviceName={serviceName}/></td><td className="mono">{record.interface}<small>{packetDirection(record.direction)}</small></td><td><Badge>{record.protocol.toUpperCase()}</Badge>{record.protocol==='tcp'&&<small>{packetFlags(record.tcp_flags)}</small>}</td><td className="mono packet-addresses"><span>{packetAddress(record.source_ip,record.source_port)}</span><small>→ {packetAddress(record.destination_ip,record.destination_port)}</small></td><td>{bytes(record.wire_length)}<small>Сохранено {bytes(record.captured_length)}{record.truncated?' · усечено':''}</small></td><td><Button variant="ghost" aria-label={`Открыть пакет ${record.packet_id}`} onClick={event=>{event.stopPropagation();setSelected(record)}}><ArrowRight size={14}/></Button></td></tr>)}</tbody></table></div>{!records.length&&<Empty icon={<Network size={27}/>}><strong>{busy?'Получаем пакеты…':error?'Журнал недоступен':'Сохранённых пакетов по этим фильтрам нет'}</strong><span>Захват должен быть включён Admin для выбранных портов и интерфейсов.</span></Empty>}</section>
    <div className="traffic-pagination"><Button variant="outline" disabled={busy||!previous.length} onClick={()=>{setLive(false);setCursor(previous[previous.length-1]);setPrevious(value=>value.slice(0,-1));setSelected(null);setPage(null)}}><ArrowLeft size={14}/>Новее</Button><span>{records.length} пакетов · страница {previous.length+1}</span><Button variant="outline" disabled={busy||!page?.next_cursor} onClick={()=>{if(!page?.next_cursor)return;setLive(false);setPrevious(value=>[...value,cursor]);setCursor(page.next_cursor);setSelected(null);setPage(null)}}>Старее<ArrowRight size={14}/></Button></div>
    {selected&&<PacketDetail key={selected.packet_id} metadata={selected} user={user} serviceName={serviceName} onClose={()=>setSelected(null)}/>}
    {exportOpen&&user.sensitive_access&&<PacketExport filters={filters} services={services} onClose={()=>setExportOpen(false)}/>}
    {configOpen&&user.role==='admin'&&<CaptureSettings onClose={()=>setConfigOpen(false)}/>}
  </div>
}

function PacketAttribution({packet,serviceName}:{packet:PacketMetadata;serviceName:(id:string)=>string}){
  if(packet.attribution==='ambiguous'||(packet.candidates?.length||0)>1)return <><Badge tone="warn">Неоднозначная привязка</Badge><small>{packet.candidates?.map(candidate=>`${serviceName(candidate.service_id)} / ${candidate.component}`).join('; ')||'Несколько совпадающих целей'}</small></>
  return <>{packet.service_id?serviceName(packet.service_id):'Не определён'}<small>{packet.component||'Компонент не определён'}</small></>
}
function Fact({label,value}:{label:string;value:string}){return <div className="fact"><span>{label}</span><code>{value}</code></div>}
function PacketDetail({metadata,user,serviceName,onClose}:{metadata:PacketMetadata;user:User;serviceName:(id:string)=>string;onClose:()=>void}){
  const [record,setRecord]=useState<PacketRecord|null>(null),[error,setError]=useState('')
  useEffect(()=>{
    setRecord(null);setError('')
    if(!user.sensitive_access)return
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const load=async()=>{try{const result=await api<PacketRecord>('/api/packets/'+encodeURIComponent(metadata.packet_id),{signal:controller.signal});if(active){setRecord(result);setError('')}}catch(error){if(active){setRecord(null);setError(errorText(error))}}finally{if(active)timer=setTimeout(()=>void load(),5000)}}
    void load();return()=>{active=false;controller.abort();clearTimeout(timer)}
  },[metadata.packet_id,user.id,user.role,user.sensitive_access])
  const raw=useMemo(()=>packetBytes(record?.data),[record?.data])
  return <Modal open onClose={onClose} title="Сетевой пакет" description="Метаданные и сохранённые байты одного наблюдения." wide><div className="dialog-body packet-detail">
    <div className="packet-detail-title"><Badge>{metadata.protocol.toUpperCase()}</Badge><PacketAttribution packet={metadata} serviceName={serviceName}/></div>
    <div className="facts-grid"><Fact label="Пакет" value={metadata.packet_id}/><Fact label="Время" value={time(metadata.at)}/><Fact label="Источник" value={packetAddress(metadata.source_ip,metadata.source_port)}/><Fact label="Назначение" value={packetAddress(metadata.destination_ip,metadata.destination_port)}/><Fact label="Интерфейс / направление" value={`${metadata.interface} (#${metadata.if_index}) · ${packetDirection(metadata.direction)}`}/><Fact label="На линии / сохранено" value={`${bytes(metadata.wire_length)} / ${bytes(metadata.captured_length)}${metadata.truncated?' · усечено':''}`}/><Fact label="Флаги TCP" value={metadata.protocol==='tcp'?packetFlags(metadata.tcp_flags):'Не применимо'}/><Fact label="Эпоха / ревизия политики" value={`${metadata.collector_epoch} / ${metadata.policy_revision}`}/></div>
    <Notice>Hex и ASCII показывают кадр Ethernet вместе с сетевыми заголовками. Управляющие и непечатные байты заменены точками. Шифрование TLS сохраняется; содержимое не исполняется и не интерпретируется как HTML.</Notice>
    {!user.sensitive_access?<Notice>Для просмотра байтов нужен доступ к чувствительным данным. В списке доступны только метаданные.</Notice>:<>{error&&<Notice variant="error">{error}</Notice>}{!record&&!error&&<p className="muted">Получаем сохранённые байты…</p>}{record&&(raw.length?<pre className="packet-hex" aria-label="Hex и ASCII пакета">{packetHex(raw)}</pre>:<Notice>{packetReason(record.not_captured_reason)}</Notice>)}</>}
  </div></Modal>
}

function PacketExport({filters,services,onClose}:{filters:PacketFilters;services:Service[];onClose:()=>void}){
  const zone=getDisplayTimeZone(),[scope,setScope]=useState<PacketFilters>(()=>{const now=new Date();return {...filters,services:[...filters.services],from:filters.from||localPacketTime(new Date(now.getTime()-5*60000),zone),until:filters.until||localPacketTime(now,zone)}})
  const [maxPackets,setMaxPackets]=useState(1000),[maxBytes,setMaxBytes]=useState(1024*1024),[ack,setAck]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[result,setResult]=useState<{count:string;truncated:boolean;gap:boolean}|null>(null)
  const alive=useRef(true),controller=useRef<AbortController|null>(null)
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;controller.current?.abort()}},[])
  const submit=async(event:FormEvent)=>{
    event.preventDefault();setError('');setResult(null)
    try{
      if(!ack)throw new Error('Подтвердите экспорт чувствительных сетевых данных.')
      const request=packetExportRequest(scope,maxPackets,maxBytes,zone)
      controller.current=new AbortController();setBusy(true)
      const {blob,headers}=await postBlob('/api/packets/export',request,{signal:controller.current.signal})
      if(!alive.current)return
      if(blob.size>maxBytes)throw new Error('Сервер вернул файл больше подтверждённого лимита; скачивание отменено.')
      const url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download='ctfm-packets-'+new Date().toISOString().replace(/[:.]/g,'-')+'.pcap';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setResult({count:headers.get('X-Packet-Count')||'—',truncated:headers.get('X-Packets-Truncated')==='true',gap:headers.get('X-Packets-Gap')==='true'});setAck(false)
    }catch(error){if(alive.current)setError(errorText(error))}finally{if(alive.current)setBusy(false)}
  }
  return <Modal open onClose={onClose} title="Экспорт PCAP" description="Экспорт только сохранённых байтов в выбранном интервале." wide><form onSubmit={event=>void submit(event)}><div className="dialog-body packet-export">
    {error&&<Notice variant="error">{error}</Notice>}{result&&<Notice variant={result.truncated||result.gap?'warning':'info'}>PCAP подготовлен: {result.count} пакетов.{result.truncated&&' Достигнут лимит; экспорт усечён.'}{result.gap&&' В выбранном интервале есть пропуски хранения.'}</Notice>}<Notice variant="warning">PCAP может содержать пароли, флаги и другие чувствительные данные. Автоматическое редактирование сырых байтов не выполняется. Экспорт проверяет текущие права и фиксируется в аудите.</Notice>
    <label>Сервисы<select multiple value={scope.services} onChange={event=>setScope(value=>({...value,services:Array.from(event.target.selectedOptions,option=>option.value)}))}>{services.map(service=><option key={service.id} value={service.id}>{service.name}</option>)}</select><small>{scope.services.length?'Выбрано сервисов: '+scope.services.length:'Будут включены все сервисы, доступные журналу.'}</small></label>
    <div className="packet-form-grid"><label>От<input required type="datetime-local" step="1" value={scope.from} onChange={event=>setScope(value=>({...value,from:event.target.value}))}/></label><label>До<input required type="datetime-local" step="1" value={scope.until} onChange={event=>setScope(value=>({...value,until:event.target.value}))}/></label><label>Не более пакетов<input required type="number" min="1" max="10000" value={maxPackets} onChange={event=>setMaxPackets(Number(event.target.value))}/></label><label>Не более байт PCAP<input required type="number" min="24" max={maxPCAPBytes} value={maxBytes} onChange={event=>setMaxBytes(Number(event.target.value))}/><small>До 8 MiB, включая заголовки PCAP.</small></label></div>
    <p className="section-note">Интервал до 60 минут; время {zone==='UTC'?'UTC':'браузера'}. Фильтры текущего списка сохраняются: {scope.component&&`компонент ${scope.component}; `}{scope.protocol||'TCP/UDP'}{scope.ip&&`; IP ${scope.ip}`}{scope.sourcePort&&`; src :${scope.sourcePort}`}{scope.destinationPort&&`; dst :${scope.destinationPort}`}{scope.direction&&`; ${packetDirection(scope.direction)}`}. При достижении лимита файл содержит только доступную часть интервала. Пакеты, удалённые ротацией, и отброшенные при захвате не восстанавливаются.</p>
    <label className="checkbox-label"><input type="checkbox" checked={ack} onChange={event=>setAck(event.target.checked)}/>Подтверждаю выбранные сервисы, интервал и экспорт неотредактированных сетевых байтов.</label>
  </div><div className="dialog-footer"><Button type="button" variant="ghost" onClick={onClose}>Отмена</Button><Button type="submit" busy={busy} disabled={!ack}><Download size={15}/>Скачать PCAP</Button></div></form></Modal>
}

function CaptureSettings({onClose}:{onClose:()=>void}){
  const [view,setView]=useState<PacketPolicyView|null>(null),[targets,setTargets]=useState<PacketCaptureTargets|null>(null),[selected,setSelected]=useState<string[]>([])
  const [enabled,setEnabled]=useState(false),[snaplen,setSnaplen]=useState(0),[pps,setPPS]=useState(1000),[ack,setAck]=useState(false)
  const [preview,setPreview]=useState<PacketCapturePreview|null>(null),[confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[reload,setReload]=useState(0)
  const alive=useRef(true),controller=useRef<AbortController|null>(null)
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;controller.current?.abort()}},[])
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const abort=new AbortController();setBusy(true);setPreview(null);setError('')
    const poll=async()=>{try{const result=await api<PacketPolicyView>('/api/capture/policy',{signal:abort.signal});if(active)setView(result)}catch(error){if(active)setError(errorText(error))}finally{if(active)timer=setTimeout(()=>void poll(),3000)}}
    const load=async()=>{try{const [policy,result]=await Promise.all([api<PacketPolicyView>('/api/capture/policy',{signal:abort.signal}),api<PacketCaptureTargets>('/api/capture/targets',{signal:abort.signal})]);if(active){setView(policy);setTargets(result);setSelected(policy.selected_target_ids||[]);setEnabled(policy.policy.enabled);setSnaplen(policy.policy.snaplen);setPPS(policy.policy.max_packets_per_second||1000);setAck(false);setConfirmed(false)}}catch(error){if(active){setTargets(null);setError(errorText(error))}}finally{if(active){setBusy(false);timer=setTimeout(()=>void poll(),3000)}}}
    void load();return()=>{active=false;abort.abort();clearTimeout(timer)}
  },[reload])
  const changed=()=>{setPreview(null);setConfirmed(false);setError('')}
  const buildPreview=async(event:FormEvent)=>{
    event.preventDefault();setError('');setConfirmed(false)
    try{
      if(!view||!targets)throw new Error('Сначала получите доступные цели захвата.')
      if(enabled){packetCaptureSelection(targets,selected);if(!selected.length)throw new Error('Выберите хотя бы один порт зарегистрированного сервиса.')}
      if(snaplen!==0&&(!Number.isInteger(snaplen)||snaplen<64||snaplen>65535))throw new Error('Лимит кадра: 0 для метаданных или от 64 до 65 535 байт.')
      if(!Number.isInteger(pps)||pps<1||pps>100000)throw new Error('Лимит наблюдений должен быть от 1 до 100 000 пакетов в секунду.')
      if(enabled&&snaplen>0&&!ack)throw new Error('Подтвердите сохранение неотредактированных сетевых байтов.')
      setBusy(true);controller.current=new AbortController()
      const result=await api<PacketCapturePreview>('/api/capture/preview',{method:'POST',body:JSON.stringify({expected_revision:view.desired_revision,enabled,target_ids:enabled?selected:[],snaplen,max_packets_per_second:pps}),signal:controller.current.signal})
      if(alive.current)setPreview(result)
    }catch(error){if(alive.current){setPreview(null);setError(errorText(error))}}finally{if(alive.current)setBusy(false)}
  }
  const confirm=async()=>{
    if(!preview)return
    setBusy(true);setError('');controller.current=new AbortController()
    try{const result=await api<PacketPolicyView>('/api/capture/confirm',{method:'POST',body:JSON.stringify({proposal_id:preview.proposal_id,digest:preview.digest}),signal:controller.current.signal});if(alive.current){setView(result);setPreview(null);setConfirmed(true)}}catch(error){if(alive.current){setPreview(null);setError(errorText(error))}}finally{if(alive.current)setBusy(false)}
  }
  const expired=preview?Date.parse(preview.expires_at)<=Date.now():false
  return <Modal open onClose={onClose} title="Настройки захвата TCP / UDP" description="Двухэтапное применение только к разрешённым портам зарегистрированных сервисов." wide><form onSubmit={event=>void buildPreview(event)}><div className="dialog-body packet-config">
    {error&&<Notice variant="error">{error}</Notice>}{!view&&!error&&<p className="muted">Получаем настройки захвата…</p>}
    {view&&<><div className="packet-policy-facts"><span>Желаемая ревизия <strong>{view.desired_revision}</strong></span><span>Применённая <strong>{view.applied_revision}</strong></span><Badge tone={view.desired_revision===view.applied_revision?'good':'warn'}>{view.activation||'Состояние неизвестно'}</Badge></div>{view.error&&<Notice variant="warning">{view.error}</Notice>}{confirmed&&<Notice variant={view.desired_revision===view.applied_revision?'info':'warning'}>{view.desired_revision===view.applied_revision?'Политика применена collector.':'Политика сохранена; ожидается подтверждение применения collector. Захват по новой ревизии пока не подтверждён.'}</Notice>}
    {!preview?<>
      <label className="checkbox-label"><input type="checkbox" checked={enabled} disabled={busy} onChange={event=>{setEnabled(event.target.checked);changed()}}/>Включить пассивный захват выбранных портов.</label>
      <p className="section-note">Точка наблюдения — подтверждённый Docker bridge контейнера. Панель не принимает произвольные интерфейсы, BPF или адреса. После Deploy привязки контейнеров могут измениться: обновите цели и подтвердите новый план.</p>
      <div className="section-title"><h3>Порты сервисов</h3><div><Button type="button" variant="ghost" disabled={busy} onClick={()=>{setSelected([]);changed()}}>Очистить выбор</Button><Button type="button" variant="ghost" disabled={busy} onClick={()=>setReload(value=>value+1)}><RefreshCw size={14}/>Обновить цели</Button></div></div>
      {targets&&<><p className="muted">Разрешённые интерфейсы: {targets.allowed_interfaces.join(', ')||'Нет'}. Выбрано целей: {selected.length}.</p><div className="packet-target-list">{targets.targets.map(target=><label key={target.id}><input type="checkbox" disabled={busy||!enabled} checked={selected.includes(target.id)} onChange={event=>{setSelected(value=>event.target.checked?[...value,target.id]:value.filter(id=>id!==target.id));changed()}}/><span><strong>{target.service_name} / {target.component} · {target.protocol.toUpperCase()} :{target.target_port}</strong><code>{target.interface} (#{target.if_index}) · {target.addresses.join(', ')} · {({container_bridge:'Bridge',container_veth:'Veth в bridge',host_publication:'Опубликованный порт'} as Record<string,string>)[target.point]}{target.observed_port&&` :${target.observed_port}`}</code></span></label>)}{!targets.targets.length&&<Empty>Нет подтверждённых доступных портов для захвата.</Empty>}</div>{selected.some(id=>!targets.targets.some(target=>target.id===id))&&<Notice variant="warning">Часть сохранённых целей больше не доступна. Обновите выбор перед подготовкой нового плана.</Notice>}{targets.unavailable.length>0&&<details><summary>Недоступные цели ({targets.unavailable.length})</summary><div className="packet-preview-targets">{targets.unavailable.map((target,index)=><p key={index}>{target.service_id} / {target.component}: {target.reason}</p>)}</div></details>}</>}
      <div className="packet-form-grid"><label>Сохранять<select value={snaplen===0?'metadata':snaplen===65535?'frame':'prefix'} disabled={busy} onChange={event=>{setSnaplen(event.target.value==='metadata'?0:event.target.value==='frame'?65535:256);setAck(false);changed()}}><option value="metadata">Только метаданные · 0 байт</option><option value="prefix">Ограниченный префикс кадра</option><option value="frame">Кадр до 65 535 байт</option></select></label><label>Лимит пакетов в секунду<input type="number" required min="1" max="100000" value={pps} disabled={busy} onChange={event=>{setPPS(Number(event.target.value));changed()}}/></label>{snaplen>0&&<label>Не более байт кадра<input type="number" required min="64" max="65535" value={snaplen} disabled={busy} onChange={event=>{setSnaplen(Number(event.target.value));setAck(false);changed()}}/><small>Включая Ethernet/IP/TCP/UDP-заголовки. Остаток кадра будет усечён.</small></label>}</div>
      {snaplen>0&&<><Notice variant="warning">Сырые байты могут содержать пароли и флаги. Редактирование и расшифровка TLS не выполняются. Хранилище, квоты и PPS ограничивают объём; при перегрузке часть пакетов теряется.</Notice><label className="checkbox-label"><input type="checkbox" checked={ack} onChange={event=>setAck(event.target.checked)}/>Подтверждаю сохранение неотредактированных байтов выбранных сервисов в пределах указанного лимита.</label></>}
    </>:<>
      <h3>План применения</h3><div className="packet-policy-facts"><span>Ревизия {preview.previous_policy.revision} → {preview.policy.revision}</span><span>Наблюдалась применённая {preview.observed_applied_revision}</span><span>{preview.policy.enabled?'Захват включится':'Захват выключится'}</span></div><p className="section-note">{preview.policy.snaplen===0?'Будут сохраняться только метаданные.':`Будет сохраняться до ${preview.policy.snaplen} неотредактированных байт каждого кадра.`} Лимит: {preview.policy.max_packets_per_second} пакетов/с.</p>
      <div className="packet-preview-targets">{preview.policy.interfaces.map(iface=><div key={iface.name}><strong>{iface.name} (#{iface.index})</strong>{iface.endpoints.map((endpoint,index)=><p key={index}>{endpoint.service_id} / {endpoint.component} · {endpoint.protocol.toUpperCase()} {packetAddress(endpoint.address,endpoint.port)}</p>)}</div>)}</div>{preview.warnings.map((warning,index)=><Notice key={index} variant="warning">{warning}</Notice>)}<p className="packet-preview-digest">Digest: <code>{preview.digest}</code></p><p className="section-note">План действителен до {time(preview.expires_at)}. Изменение интерфейсов, контейнеров или политики требует нового preview.</p>{expired&&<Notice variant="warning">Срок плана истёк. Подготовьте новый план.</Notice>}
    </>}</>}
  </div><div className="dialog-footer">{preview?<><Button type="button" variant="ghost" disabled={busy} onClick={()=>setPreview(null)}>Изменить</Button><Button type="button" busy={busy} disabled={expired} onClick={()=>void confirm()}>Подтвердить применение</Button></>:<><Button type="button" variant="ghost" onClick={onClose}>Закрыть</Button><Button type="submit" busy={busy} disabled={!view||!targets||enabled&&snaplen>0&&!ack}>Подготовить план</Button></>}</div></form></Modal>
}
