import {useCallback,useEffect,useMemo,useRef,useState} from 'react'
import type {FormEvent} from 'react'
import {ArrowLeft,Check,Edit3,Network,Plus,RefreshCw,Shield,Trash2} from 'lucide-react'
import {api,post,time} from './api'
import type {Service,User} from './api'
import {Badge,Button,Empty,Modal,Notice} from './ui'
import {proxyProtocolLabel,proxyCutoverComponents,proxyCutoverGroupEvidence,proxyCutoverGroupRequest,proxyCutoverGroupTargets,proxyCutoverRoutes,proxyCutoverUpdateSettings,proxyListenAddress,proxyLoopbackIP,proxyLoopbackListener,proxyRouteChanges,proxyRouteDraft,proxyRouteID,proxyRouteInput,proxyServiceRatePolicy,proxyStatusView,wafBlocks,wafLabel,wafReasonLabel} from './proxyTypes'
import type {CapturePolicy,PolicyView,ProxyApply,ProxyBan,ProxyBans,ProxyCutoverContainer,ProxyCutoverGroupDraft,ProxyCutoverPreview,ProxyCutoverTarget,ProxyCutoverTargets,ProxyCutoverView,ProxyPreview,ProxyRoute,ProxyRouteInput,ProxyStatus,ProxyStatusEnvelope,ProxyTarget,ProxyTargets,ProxyTLSCertificate,ProxyTLSCertificates,RouteLimits,WafMode,WafPolicy} from './proxyTypes'

const errorText=(error:unknown)=>error instanceof Error?error.message:'Не удалось выполнить запрос'
const lines=(value:string)=>value.split(/[\n,]/).map(part=>part.trim()).filter(Boolean)
const defaultsCapture:CapturePolicy={mode:'metadata',max_body_bytes:65536,redact_headers:[],redact_query_fields:[],redact_body_fields:[],body_patterns:[]}
const defaultsWaf:WafPolicy={mode:'observe_only',rate_per_second:20,burst:40,violation_threshold:10,violation_window_seconds:60,ban_ttl_seconds:60,max_ip_states:4096,state_ttl_seconds:300,overflow_mode:'reject_new',exceptions:[]}
const defaultsLimits:RouteLimits={max_concurrent:128,max_header_bytes:65536,read_header_timeout_seconds:5,upstream_response_header_timeout_seconds:30,idle_timeout_seconds:60,max_connection_seconds:300,max_body_bytes:0}
const simpleRateMax=100000
const simpleRatePause=5
const validSimpleRate=(rate:number)=>Number.isInteger(rate)&&rate>=1&&rate<=simpleRateMax
const simpleRateWaf=(rate:number):WafPolicy=>({
  mode:'rate_limit',rate_per_second:rate,burst:0,violation_threshold:0,violation_window_seconds:0,ban_ttl_seconds:0,
  max_ip_states:defaultsWaf.max_ip_states,state_ttl_seconds:0,overflow_mode:defaultsWaf.overflow_mode,exceptions:[],
})
const targetKey=(target:Pick<ProxyTarget,'service_id'|'component'|'upstream_port'>)=>`${target.service_id}|${target.component}|${target.upstream_port}`
const listenerIP=(listener:string)=>listener.slice(0,listener.lastIndexOf(':')).replace(/^\[|\]$/g,'')
const listenerPort=(listener:string)=>listener.split(':').at(-1)||''
const cutoverRoute=(route:ProxyRouteInput)=>route.id.startsWith('route-cutover-')

function newRoute(target:ProxyTarget,listen:string,waf:WafPolicy=defaultsWaf):ProxyRouteInput{
  return {id:proxyRouteID(),service_id:target.service_id,component:target.component,upstream_port:target.upstream_port,listen,host:'',protocol:'http1',capture:{...defaultsCapture},waf:{...waf},trusted_proxy_cidrs:[],limits:{...defaultsLimits}}
}

function ServiceRateLimit({current,blocked,unavailable,onStage}:{
  current?:WafPolicy;blocked:boolean;unavailable:string;onStage:(policy:WafPolicy)=>void
}){
  const [rate,setRate]=useState(String(current?.rate_per_second??defaultsWaf.rate_per_second))
  const disabled=blocked||!!unavailable
  const submit=(event:FormEvent)=>{
    event.preventDefault()
    const value=Number(rate)
    if(!disabled&&validSimpleRate(value)&&value!==current?.rate_per_second)onStage(simpleRateWaf(value))
  }
  return <section className="panel">
    <div className="panel-heading"><div><h2>Лимит запросов по IP</h2><p>Один лимит на IP для всех HTTP-маршрутов сервиса. При превышении прокси отвечает HTTP 429 в течение {simpleRatePause} секунд.</p></div></div>
    <form className="dialog-body proxy-route-form" onSubmit={submit}>
      {unavailable&&<Notice>{unavailable}</Notice>}
      <label>Запросов в секунду<input type="number" required min={1} max={simpleRateMax} step={1} value={rate} disabled={disabled} onChange={event=>setRate(event.target.value)}/><small>При включении этот лимит заменит правила WAF маршрутов сервиса. Изменения проходят проверку checker и подтверждение плана.</small></label>
      <div className="dialog-footer">
        {current&&<Button variant="outline" type="button" disabled={disabled} onClick={()=>onStage({...defaultsWaf,rate_per_second:current.rate_per_second})}>Вернуть наблюдение</Button>}
        <Button type="submit" disabled={disabled||!validSimpleRate(Number(rate))||Number(rate)===current?.rate_per_second}>{current?'Изменить лимит в черновике':'Включить лимит в черновике'}</Button>
      </div>
    </form>
  </section>
}

function QuickRoute({targets,options,routes,serviceID,busy,blocked,checkerConfirmed,onCheckerConfirmed,onReview}:{
  targets:ProxyTarget[];options:ProxyTargets;routes:ProxyRouteInput[];serviceID:string;busy:boolean;blocked:boolean
  checkerConfirmed:boolean;onCheckerConfirmed:(confirmed:boolean)=>void;onReview:(routes:ProxyRouteInput[])=>void
}){
  const editable=routes.filter(route=>route.service_id===serviceID&&route.protocol==='http1'&&!route.host&&!cutoverRoute(route)&&targets.some(target=>targetKey(target)===targetKey(route)))
  const [routeID,setRouteID]=useState(editable[0]?.id||'')
  const existing=editable.find(route=>route.id===routeID)
  const serviceRate=proxyServiceRatePolicy(routes,serviceID)
  const candidates=targets.filter(target=>existing?target.component===existing.component&&(existing.waf.mode==='observe_only'||target.private_binding):!serviceRate||target.private_binding)
  const needsChecker=routes.some(route=>wafBlocks(route.waf.mode))
  return <section className="panel">
    <div className="panel-heading"><div><h2>Дополнительный HTTP-маршрут</h2><p>Отдельный порт для проверки или дополнительного входа. В журнал попадают запросы на этот порт прокси. {serviceRate?'Новый маршрут унаследует лимит запросов сервиса.':'Новый маршрут пишет метаданные, а WAF работает в режиме наблюдения.'}</p></div></div>
    {!candidates.length?<Empty>У сервиса пока нет подтверждённого Docker-порта для дополнительного маршрута.</Empty>:
      <div className="dialog-body proxy-route-form">
        {!!editable.length&&<label>Маршрут<select value={existing?.id||''} disabled={blocked||busy} onChange={event=>setRouteID(event.target.value)}>{editable.map(route=><option key={route.id} value={route.id}>{route.listen} · {route.component}</option>)}<option value="">Добавить маршрут</option></select></label>}
        <QuickRoutePorts key={existing?.id||'new'} existing={existing} serviceRate={serviceRate} targets={candidates} options={options} routes={routes} busy={busy} blocked={blocked} needsChecker={needsChecker} checkerConfirmed={checkerConfirmed} onCheckerConfirmed={onCheckerConfirmed} onReview={onReview}/>
      </div>}
  </section>
}

function QuickRoutePorts({existing,serviceRate,targets,options,routes,busy,blocked,needsChecker,checkerConfirmed,onCheckerConfirmed,onReview}:{
  existing?:ProxyRouteInput;serviceRate?:WafPolicy;targets:ProxyTarget[];options:ProxyTargets;routes:ProxyRouteInput[];busy:boolean;blocked:boolean;needsChecker:boolean
  checkerConfirmed:boolean;onCheckerConfirmed:(confirmed:boolean)=>void;onReview:(routes:ProxyRouteInput[])=>void
}){
  const first=targets.find(target=>existing&&targetKey(target)===targetKey(existing))||targets[0]
  const [backend,setBackend]=useState(first?targetKey(first):'')
  const [address,setAddress]=useState(existing?listenerIP(existing.listen):'')
  const [port,setPort]=useState(existing?listenerPort(existing.listen):undefined)
  const selected=targets.find(target=>targetKey(target)===backend)||first
  const rangeIPs=(options.allowed_listen_ips||[]).filter(ip=>selected?.private_binding||proxyLoopbackIP(ip))
  const exactEndpoints=(options.allowed_listen_endpoints||[]).filter(listener=>selected?.private_binding||proxyLoopbackListener(listener))
  const allowedIPs=[...new Set([...rangeIPs,...exactEndpoints.map(listenerIP)])]
  const defaultIP=allowedIPs.find(ip=>ip==='0.0.0.0')||allowedIPs.find(proxyLoopbackIP)||allowedIPs[0]||''
  const ip=address?(allowedIPs.includes(address)?address:''):defaultIP
  const inRange=rangeIPs.includes(ip)
  const exactPorts=exactEndpoints.filter(listener=>listenerIP(listener)===ip).map(listener=>Number(listenerPort(listener)))
  const usedPorts=new Set(routes.map(route=>Number(listenerPort(route.listen))))
  let suggestedPort=inRange?options.listen_port_min:undefined
  while(suggestedPort!==undefined&&suggestedPort<=options.listen_port_max&&usedPorts.has(suggestedPort))suggestedPort++
  if(suggestedPort===undefined||suggestedPort>options.listen_port_max)suggestedPort=exactPorts.find(value=>!usedPorts.has(value))
  const portValue=port??(suggestedPort===undefined?'':String(suggestedPort))
  const number=Number(portValue),listen=ip&&portValue?proxyListenAddress(ip,number):''
  const portValid=Number.isInteger(number)&&((inRange&&number>=options.listen_port_min&&number<=options.listen_port_max)||exactPorts.includes(number))
  const portHint=[...(inRange?[`${options.listen_port_min}–${options.listen_port_max}`]:[]),...exactPorts].join(', ')
  const unchanged=!!(existing&&selected&&listen===existing.listen&&targetKey(selected)===targetKey(existing))
  const disabled=busy||blocked||!selected||!listen||!portValid||unchanged||(needsChecker&&!checkerConfirmed)
  const submit=(event:FormEvent)=>{
    event.preventDefault()
    if(disabled||!selected)return
    const next=existing?{...existing,listen,upstream_port:selected.upstream_port}:newRoute(selected,listen,serviceRate)
    onReview(existing?routes.map(route=>route.id===existing.id?next:route):[...routes,next])
  }
  return <form onSubmit={submit}>
    <div className="form-columns">
      <label>IP прокси<select required value={ip} disabled={busy||blocked||!allowedIPs.length} onChange={event=>setAddress(event.target.value)}>{!ip&&<option value="" disabled>{allowedIPs.length?'Выберите разрешённый IP':'Нет разрешённых адресов'}</option>}{allowedIPs.map(value=><option key={value}>{value}</option>)}</select></label>
      <label>Внешний порт прокси<input type="number" required min={1024} max={65535} value={portValue} disabled={busy||blocked} onChange={event=>setPort(event.target.value)}/><small>{portHint?`Разрешённые порты этого IP: ${portHint}. Занятость проверяется при просмотре плана.`:'Сначала выберите разрешённый IP.'}</small></label>
    </div>
    <label>Внутренний порт (backend)<select required value={selected?targetKey(selected):''} disabled={busy||blocked} onChange={event=>setBackend(event.target.value)}>{targets.map(target=><option key={targetKey(target)} value={targetKey(target)}>{target.upstream_address.replace(/^http:\/\//,'')} · {target.component} ({target.upstream_port}/tcp)</option>)}</select><small>Выберите текущую публикацию Docker. Новый закрытый порт приложения задаётся при переносе игровых портов.</small></label>
    {selected?.private_binding===false&&<Notice>Прямую публикацию здесь можно проверить через локальный маршрут. Чтобы записывать запросы на привычный игровой адрес, перенесите игровой порт на прокси.</Notice>}
    {ip&&portValue&&!portValid&&<Notice variant="warning">Этот порт не разрешён для выбранного IP прокси.</Notice>}
    {!allowedIPs.length&&<Notice variant="warning">Для выбранного backend в этой установке нет разрешённого IP прокси.</Notice>}
    {needsChecker&&<label className="inline-check"><input type="checkbox" disabled={busy||blocked} checked={checkerConfirmed} onChange={event=>onCheckerConfirmed(event.target.checked)}/><span>Проверена совместимость checker с ограничениями WAF.</span></label>}
    <div className="dialog-footer"><Button type="submit" busy={busy} disabled={disabled}>Проверить маршрут</Button></div>
  </form>
}


export default function ProxyWaf({services,user,serviceID,onBack,onTraffic}:{services:Service[];user:User;serviceID?:string;onBack?:()=>void;onTraffic?:()=>void}){
  const [view,setView]=useState<PolicyView|null>(null),[status,setStatus]=useState<ProxyStatus|null>(null),[targets,setTargets]=useState<ProxyTargets|null>(null),[bans,setBans]=useState<ProxyBan[]>([]),[banTotal,setBanTotal]=useState(0),[bansTruncated,setBansTruncated]=useState(false)
  const [routes,setRoutes]=useState<ProxyRouteInput[]>([]),[editing,setEditing]=useState<ProxyRouteInput|null>(null),[preview,setPreview]=useState<ProxyPreview|null>(null)
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[connectionError,setConnectionError]=useState(''),[message,setMessage]=useState(''),[checkerConfirmed,setCheckerConfirmed]=useState(false),[applied,setApplied]=useState<number|null>(null)
  const [manualBan,setManualBan]=useState(false),[unban,setUnban]=useState<ProxyBan|null>(null)
  const [acknowledgedExternalRevision,setAcknowledgedExternalRevision]=useState<number|null>(null)
  const [certificates,setCertificates]=useState<ProxyTLSCertificate[]>([]),[certificateError,setCertificateError]=useState(''),[certificatesTruncated,setCertificatesTruncated]=useState(false),[certificateTotal,setCertificateTotal]=useState(0)
  const refreshedRevision=useRef<number|undefined>(undefined)
  const admin=user.role==='admin',canUnban=user.role!=='viewer'
  const refresh=useCallback(async()=>{
    setBusy(true);setError('')
    const values=await Promise.allSettled([admin?api<PolicyView>('/api/proxy/policy'):Promise.resolve(null),api<ProxyStatusEnvelope>('/api/proxy/status'),admin?api<ProxyTargets>('/api/proxy/targets'):Promise.resolve(null),api<ProxyBans>('/api/proxy/bans'),admin?api<ProxyTLSCertificates>('/api/proxy/tls/certificates'):Promise.resolve(null)])
    const approved=values[2].status==='fulfilled'&&values[2].value?values[2].value.targets||[]:[]
    if(values[0].status==='fulfilled'&&values[0].value){setView(values[0].value);setRoutes((values[0].value.policy.routes||[]).map(route=>proxyRouteInput(route,approved)))}
    if(values[1].status==='fulfilled')setStatus(proxyStatusView(values[1].value))
    if(values[2].status==='fulfilled'&&values[2].value)setTargets(values[2].value)
    if(values[3].status==='fulfilled'){setBans(values[3].value.bans||[]);setBanTotal(values[3].value.total??values[3].value.bans?.length??0);setBansTruncated(values[3].value.truncated||false)}
    if(values[4].status==='fulfilled'&&values[4].value){setCertificates(values[4].value.certificates||[]);setCertificateTotal(values[4].value.total??values[4].value.certificates?.length??0);setCertificatesTruncated(values[4].value.truncated);setCertificateError('')}else if(values[4].status==='rejected'){setCertificates([]);setCertificatesTruncated(false);setCertificateTotal(0);setCertificateError(errorText(values[4].reason))}
    const rejected=values.slice(0,4).find(value=>value.status==='rejected')
    if(rejected?.status==='rejected')setError(errorText(rejected.reason))
    setBusy(false)
  },[admin])
  useEffect(()=>{if(!admin){setView(null);setRoutes([]);setTargets(null);setCertificates([]);setCertificateError('')}void refresh()},[refresh,admin])
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const poll=async()=>{try{const [next,activeBans]=await Promise.all([api<ProxyStatusEnvelope>('/api/proxy/status',{signal:controller.signal}),api<ProxyBans>('/api/proxy/bans',{signal:controller.signal})]);if(active){setStatus(proxyStatusView(next));setBans(activeBans.bans||[]);setBanTotal(activeBans.total??activeBans.bans?.length??0);setBansTruncated(activeBans.truncated||false);setConnectionError('')}}catch(error){if(active)setConnectionError(errorText(error))}finally{if(active)timer=setTimeout(()=>void poll(),3000)}}
    timer=setTimeout(()=>void poll(),3000);return()=>{active=false;clearTimeout(timer);controller.abort()}
  },[])
  useEffect(()=>{if(applied!==null&&status?.available&&status.applied_revision>=applied){setMessage(`Proxy подтвердил применение ревизии ${applied}.`);setApplied(null)}},[applied,status])
  useEffect(()=>{setAcknowledgedExternalRevision(null);setPreview(null);setEditing(null)},[view?.desired_revision,view?.external_revision])
  const serviceName=(id:string)=>services.find(service=>service.id===id)?.name||id
  const dirty=useMemo(()=>view?JSON.stringify(routes)!==JSON.stringify((view.policy.routes||[]).map(route=>proxyRouteInput(route,targets?.targets||[]))):false,[routes,view,targets])
  const configured=status?.configured??view?.configured??false
  const externalAcknowledged=!!view?.external_revision&&acknowledgedExternalRevision===view.desired_revision
  const externalBlocked=!!view?.external_revision&&!externalAcknowledged
  const observationIP=targets?.allowed_listen_ips?.find(proxyLoopbackIP)
  const observationListen=observationIP&&targets?proxyListenAddress(observationIP,targets.listen_port_min):targets?.allowed_listen_endpoints?.find(proxyLoopbackListener)||''
  const listenHint=targets?[
    `${(targets.allowed_listen_ips||[]).join(', ')} · порты ${targets.listen_port_min}–${targets.listen_port_max}`,
    ...(targets.allowed_listen_endpoints||[]),
  ].join(' · '):''
  const listedRoutes=serviceID?routes.filter(route=>route.service_id===serviceID):routes
  const listedTargets=(targets?.targets||[]).filter(target=>!serviceID||target.service_id===serviceID)
  const unavailable=(targets?.unavailable||[]).filter(target=>!serviceID||target.service_id===serviceID)
  const manualBanRoutes=(view?.policy.routes||[]).filter(route=>route.waf.mode!=='rate_limit')
  const serviceRateFor=(id:string)=>proxyServiceRatePolicy(routes,id)
  const serviceRate=serviceID?serviceRateFor(serviceID):undefined
  const serviceRateAllowed=(id:string)=>routes.filter(route=>route.service_id===id).every(route=>
    (view?.policy.routes||[]).some(current=>current.id===route.id)&&listedTargets.some(target=>target.private_binding&&targetKey(target)===targetKey(route)))
  const additiveTargets=listedTargets.filter(target=>target.private_binding||!serviceRateFor(target.service_id))
  const needsChecker=routes.some(route=>wafBlocks(route.waf.mode))
  const rateUnavailable=!listedRoutes.length?'Сначала перенесите игровые порты или примените HTTP-маршрут с закрытым backend.':serviceID&&!serviceRateAllowed(serviceID)?'Для этого режима у всех маршрутов сервиса должны быть подтверждённые закрытые backend. Локальные маршруты наблюдения можно убрать перед настройкой лимита.':''
  const observationRoutes=new Set(serviceID?listedRoutes.filter(route=>!cutoverRoute(route)&&route.waf.mode==='observe_only'&&proxyLoopbackListener(route.listen)&&listedTargets.some(target=>target.private_binding===false&&targetKey(target)===targetKey(route))).map(route=>route.id):[])
  const appliedRevision=status?.applied_revision
  const pendingPolicy=!!status&&(status.desired_revision!==status.applied_revision||(view?.desired_revision??0)>status.applied_revision)
  const blocked=busy||dirty||externalBlocked||!!editing||!!preview
  useEffect(()=>{
    if(blocked||!view||appliedRevision===undefined||appliedRevision<=view.desired_revision||appliedRevision===refreshedRevision.current)return
    refreshedRevision.current=appliedRevision
    void refresh()
  },[appliedRevision,blocked,refresh,view])
  const review=async(nextRoutes=routes)=>{
    if(!view||externalBlocked)return
    if(!checkerConfirmed&&nextRoutes.some(route=>wafBlocks(route.waf.mode))){
      setError('Подтвердите проверку совместимости игрового checker с ограничениями WAF.')
      return
    }
    setBusy(true);setError('');setMessage('')
    try{setPreview(await post<ProxyPreview>('/api/proxy/preview',{expected_revision:view.desired_revision,routes:nextRoutes,confirm_checker:checkerConfirmed}))}catch(error){setError(errorText(error))}finally{setBusy(false)}
  }
  const confirm=async()=>{
    if(!preview)return
    setBusy(true);setError('')
    try{const result=await post<ProxyApply>('/api/proxy/confirm',{proposal_id:preview.proposal_id,digest:preview.digest});setPreview(null);setCheckerConfirmed(false);setApplied(result.desired_revision);setMessage(result.activation==='applied'?`Применена ревизия ${result.applied_revision}.`:`Ревизия ${result.desired_revision} подтверждена. Ожидаем применения proxy.`);await refresh()}catch(error){setError(errorText(error))}finally{setBusy(false)}
  }
  const create=()=>{
    const first=additiveTargets[0]
    if(!first||externalBlocked)return
    const listen=first.private_binding===false?observationListen:targets?.listeners?.[0]||proxyListenAddress(targets?.allowed_listen_ips?.[0]||'127.0.0.1',targets?.listen_port_min||18081)
    setEditing(newRoute(first,listen,serviceRateFor(first.service_id)))
  }
  const saveRoute=(value:ProxyRouteInput)=>{
    setRoutes(current=>proxyRouteDraft(current,value))
    setEditing(null)
    setPreview(null)
    setCheckerConfirmed(false)
  }
  const stageServiceRate=(policy:WafPolicy)=>{
    if(!serviceID||blocked||pendingPolicy||rateUnavailable)return
    setRoutes(current=>current.map(route=>route.service_id===serviceID?{...route,waf:policy}:route))
    setCheckerConfirmed(false)
    setMessage('Правила WAF сервиса добавлены в черновик. Проверьте совместимость с checker и откройте «Посмотреть план».')
  }
  const stageObservationRemoval=()=>{
    if(blocked||pendingPolicy)return
    setRoutes(current=>current.filter(route=>!observationRoutes.has(route.id)))
    setMessage('Удаление локальных маршрутов добавлено в черновик. Откройте «Посмотреть план» и подтвердите изменения перед переносом.')
  }
  const portCutovers=admin&&<PortCutovers configured={configured} serviceID={serviceID} blocked={blocked||pendingPolicy||!view} appliedRevision={appliedRevision} observationCount={observationRoutes.size} onStageObservationRemoval={stageObservationRemoval} services={services} certificates={certificates} certificateError={certificateError} onRefresh={()=>void refresh()}/>
  return <div className="proxy-view"><div className="page-title"><div><h1>{serviceID?`Прокси и трафик · ${serviceName(serviceID)}`:'Proxy / WAF'}</h1><p>HTTP-маршруты, ограничения запросов и временные блокировки IP.</p></div><div className="proxy-row-actions">{onBack&&<Button variant="ghost" disabled={busy||dirty||!!preview} onClick={onBack}><ArrowLeft size={15}/>К сервису</Button>}{onTraffic&&<Button variant="outline" disabled={busy||dirty||!!preview} onClick={onTraffic}>Трафик сервиса</Button>}<Button variant="outline" busy={busy} onClick={()=>void refresh()}><RefreshCw size={15}/>Обновить</Button></div></div>
    {error&&<Notice variant="error">{error}</Notice>}{connectionError&&<Notice variant="warning">{connectionError} Действующее состояние proxy сейчас не подтверждено.</Notice>}{message&&<Notice>{message}</Notice>}
    {status&&!configured&&<Notice>Модуль proxy не подключён к этой установке. После его подключения здесь появятся маршруты и состояние защиты.</Notice>}
    <div className="proxy-summary"><section className="panel"><span><Network size={16}/>Маршрутизация</span><strong>{connectionError?'Нет свежих данных':!status?'Ожидаем состояние':!configured?'Не подключена':status.available?'Proxy доступен':'Proxy недоступен'}</strong><small>Нужная ревизия: {status?.desired_revision??view?.desired_revision??'—'} · применена: {status?.applied_revision??'—'}</small></section><section className="panel"><span><Shield size={16}/>{serviceID?'WAF · все сервисы':'WAF'}</span><strong>{!status||connectionError?'Ожидаем состояние':status.waf_degraded?'Ограниченный режим':!admin?(status?.available?'Действует политика':'Нет актуальных данных'):needsChecker?'Есть правила блокировки':'Наблюдение / отключён'}</strong><small>{status?.routes??(admin?routes.length:'—')} маршрутов · {banTotal} активных банов</small></section></div>
    {(status?.error||status?.last_error||view?.error)&&<Notice variant="warning">{status?.error||status?.last_error||view?.error}</Notice>}
    {view?.external_revision&&<Notice variant="warning"><p>В файле задана аварийная ревизия {view.desired_revision}. Она может ещё ожидать применения. Согласование позволит продолжить работу с этой политикой в панели; после просмотра и подтверждения будет опубликована следующая ревизия.</p>{externalAcknowledged?<p>Ревизия {view.desired_revision} согласована для подготовки плана. Можно сохранить её параметры без изменений или изменить черновик.</p>:<Button variant="outline" disabled={busy} onClick={()=>{setAcknowledgedExternalRevision(view.desired_revision);setPreview(null);setCheckerConfirmed(false)}}>Согласовать аварийную политику</Button>}</Notice>}
    {pendingPolicy&&configured&&<Notice variant="warning">Подтверждённая ревизия ещё не совпадает с действующей. Proxy продолжает работу по последней успешно применённой политике.</Notice>}
    {serviceID&&portCutovers}
    {admin&&serviceID&&configured&&view&&targets&&<ServiceRateLimit key={`${view.desired_revision}:${serviceRate?.rate_per_second??''}`} current={serviceRate} blocked={blocked||pendingPolicy} unavailable={rateUnavailable} onStage={stageServiceRate}/>}
    {admin&&serviceID&&configured&&view&&targets&&<QuickRoute key={view.desired_revision} targets={listedTargets} options={targets} routes={routes} serviceID={serviceID} busy={busy} blocked={dirty||externalBlocked||!!editing||!!preview} checkerConfirmed={checkerConfirmed} onCheckerConfirmed={setCheckerConfirmed} onReview={next=>void review(next)}/>}
    <Notice>HTTP-прокси записывает запросы, прошедшие через его маршруты. Для HTTPS и HTTP/2 или gRPC выберите совместимый профиль. Остальной TCP/UDP-трафик можно исследовать в разделах пакетов и потоков.</Notice>
    {admin&&certificateError&&<Notice variant="warning">Список сертификатов недоступен: {certificateError} HTTP-маршруты можно настраивать без TLS.</Notice>}{admin&&certificatesTruncated&&<Notice variant="warning">Найдено не менее {certificateTotal} TLS-профилей; показан ограниченный список. Для выбора профиля обновите локальную конфигурацию сертификатов.</Notice>}
    {admin&&<section className="panel"><div className="panel-heading"><div><h2>Маршруты</h2><p>Новый маршрут начинает с наблюдения WAF. Изменения применяются после просмотра и подтверждения.</p></div>{admin&&<Button variant="outline" disabled={busy||!configured||externalBlocked||!additiveTargets.length} onClick={create}><Plus size={15}/>Добавить маршрут</Button>}</div>
      <div className="table-wrap"><table><thead><tr><th>Сервис / компонент</th><th>Внешний адрес → backend</th><th>WAF</th><th>Capture</th>{admin&&<th/>}</tr></thead><tbody>{listedRoutes.map(route=><tr key={route.id}><td>{serviceName(route.service_id)}<small>{route.component} · <code>{route.id}</code></small></td><td><code>{route.listen}</code><small>{proxyProtocolLabel(route.protocol)+(route.protocol!=='http1'?` · ${route.tls?.certificate_id||'сертификат не указан'}`:'')}</small><small>→ {targets?.targets?.find(target=>targetKey(target)===targetKey(route))?.upstream_address||view?.policy.routes?.find(value=>value.id===route.id)?.upstream||`порт ${route.upstream_port}`}</small>{route.host&&<small>Host: {route.host}</small>}</td><td><Badge tone={wafBlocks(route.waf.mode)?'warn':'neutral'}>{wafLabel(route.waf.mode)}</Badge><small>{route.waf.mode==='rate_limit'?`${route.waf.rate_per_second} запр./с на IP · HTTP 429 на ${simpleRatePause} с`:`${route.waf.rate_per_second} запр./с · burst ${route.waf.burst}`}</small></td><td>{route.capture.mode==='grpc_body'?'Сырые gRPC bytes':route.capture.mode==='bounded_body'?'Ограниченные тела':'Метаданные'}<small>{route.capture.mode!=='metadata'?`до ${Math.round(route.capture.max_body_bytes/1024)} KiB на тело`:'Тела не записываются'}</small></td>{admin&&<td><div className="proxy-row-actions"><Button variant="ghost" aria-label={`Изменить ${route.id}`} disabled={externalBlocked||busy} onClick={()=>setEditing(structuredClone(route))}><Edit3 size={15}/></Button><Button variant="ghost" aria-label={`Удалить из черновика ${route.id}`} disabled={externalBlocked||busy||cutoverRoute(route)} title={cutoverRoute(route)?'Для этого маршрута используйте возврат игровых портов':undefined} onClick={()=>{setRoutes(value=>value.filter(item=>item.id!==route.id));setPreview(null)}}><Trash2 size={15}/></Button></div></td>}</tr>)}</tbody></table></div>
      {!listedRoutes.length&&<Empty icon={<Network size={26}/>}><strong>Маршруты ещё не добавлены</strong><span>Выберите подтверждённый backend зарегистрированного HTTP-сервиса.</span></Empty>}
      {admin&&<div className="proxy-policy-actions">{dirty&&<Badge tone="warn">Изменения в черновике</Badge>}<label className="inline-check"><input type="checkbox" checked={checkerConfirmed} onChange={event=>setCheckerConfirmed(event.target.checked)}/><span>Проверена совместимость checker с ограничениями WAF.</span></label><div><Button busy={busy} disabled={!configured||!view||externalBlocked||(!dirty&&!externalAcknowledged)||(needsChecker&&!checkerConfirmed)} onClick={()=>void review()}>Посмотреть план</Button><Button variant="ghost" disabled={!dirty||busy} onClick={()=>{if(view)setRoutes((view.policy.routes||[]).map(route=>proxyRouteInput(route,targets?.targets||[])));setCheckerConfirmed(false);setMessage('')}}>Отменить черновик</Button></div></div>}
    </section>}
    {!serviceID&&portCutovers}
    {!admin&&<Notice>Параметры маршрутов и правила WAF доступны администратору. Ваша роль видит состояние proxy и активные временные баны.</Notice>}
    {!!unavailable.length&&<details className="proxy-unavailable"><summary>Компоненты без подтверждённого HTTP-маршрута ({unavailable.length})</summary><ul>{unavailable.map((target,index)=><li key={`${target.service_id}:${target.component}:${index}`}>{serviceName(target.service_id)} · {target.component}: {target.reason}</li>)}</ul></details>}
    {!serviceID&&bansTruncated&&<Notice variant="warning">Показаны {bans.length} из {banTotal} активных банов. Для конкретного адреса доступно снятие бана по IP.</Notice>}
    {!serviceID&&<section className="panel proxy-bans"><div className="panel-heading"><div><h2>Временные блокировки</h2><p>Лимит действует в пределах сервиса. Общий IP за NAT затрагивает всех клиентов с этим адресом.</p></div><div className="proxy-row-actions">{canUnban&&<Button variant="outline" disabled={!configured||!services.length} onClick={()=>setUnban({service_id:services[0].id,ip:'',reason:'',source:'',created_at:'',expires_at:''})}>Снять бан по IP</Button>}{admin&&<Button variant="outline" disabled={!configured||pendingPolicy||!manualBanRoutes.length} onClick={()=>setManualBan(true)}><Plus size={15}/>Заблокировать IP</Button>}</div></div><div className="table-wrap"><table><thead><tr><th>Сервис / IP</th><th>Причина / источник</th><th>До</th>{canUnban&&<th/>}</tr></thead><tbody>{bans.map(ban=><tr key={`${ban.service_id}|${ban.route_id||''}|${ban.ip}`}><td>{serviceName(ban.service_id)}<small><code>{ban.ip}</code>{ban.route_id&&` · ${ban.route_id}`}</small></td><td>{ban.source==='automatic'?wafReasonLabel(ban.reason):ban.reason}<small>{ban.source==='manual'?'Ручная блокировка':'Автобан'}</small></td><td title={ban.expires_at}>{time(ban.expires_at)}</td>{canUnban&&<td><Button variant="outline" onClick={()=>setUnban(ban)}>Снять бан</Button></td>}</tr>)}</tbody></table></div>{!bans.length&&<Empty>Активных временных банов нет.</Empty>}</section>}
    {editing&&<RouteEditor value={editing} existing={!!view?.policy.routes?.some(route=>route.id===editing.id)} targets={listedTargets} certificates={certificates} certificateError={certificateError} listenHint={listenHint} observationListen={observationListen} fixedBinding={cutoverRoute(editing)} onClose={()=>setEditing(null)} serviceRateFor={serviceRateFor} serviceRateAllowed={serviceRateAllowed} onSave={saveRoute}/>}
    {preview&&<Modal open onClose={()=>setPreview(null)} title="Подтвердить политику proxy" description="Будет активирована только эта проверенная ревизия маршрутов." wide><div className="dialog-body proxy-preview">{preview.policy.routes.some(route=>route.capture.mode==='grpc_body')&&<Notice variant="warning">Этот план явно включает сохранение сырых gRPC bytes после TLS termination. Флаги, пароли и protobuf-поля автоматически не редактируются; доступ к bytes требует sensitive access.</Notice>}{preview.warnings?.length>0&&<Notice variant="warning"><ul>{preview.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul></Notice>}<p>Применена ревизия {preview.observed_applied_revision??status?.applied_revision??'—'} → план ревизии {preview.policy.revision} · {(preview.policy.routes||[]).length} маршрутов.</p><PolicyDiff before={preview.previous_policy?.routes||view?.policy.routes||[]} after={preview.policy.routes||[]} serviceName={serviceName}/><p className="muted">Подтверждение относится к digest <code>{preview.digest}</code>{preview.expires_at&&<>. Срок: {time(preview.expires_at)}</>}.</p>{error&&<Notice variant="error">{error}</Notice>}<div className="dialog-footer"><Button variant="outline" disabled={busy} onClick={()=>setPreview(null)}>Назад</Button><Button busy={busy} onClick={()=>void confirm()}><Check size={15}/>Подтвердить</Button></div></div></Modal>}
    {manualBan&&<BanDialog routes={manualBanRoutes} serviceName={serviceName} onClose={()=>setManualBan(false)} onSaved={()=>{setManualBan(false);void refresh()}}/>}
    {unban&&<UnbanDialog ban={unban} services={services} serviceName={serviceName(unban.service_id)} onClose={()=>setUnban(null)} onSaved={()=>{setUnban(null);void refresh()}}/>}
  </div>
}

function policyFields(route:ProxyRoute):[string,string][]{
  const capture=route.capture,waf=route.waf,limits=route.limits
  const wafDetails:[string,string][]=waf.mode==='rate_limit'?
    [['Лимит на IP',`${waf.rate_per_second} запр./с`],['Ответ при превышении',`HTTP 429 на ${simpleRatePause} с`],['Область лимита','Все маршруты сервиса']]:[
    ['Лимит и всплеск',`${waf.rate_per_second} запр./с · burst ${waf.burst}`],['Автобан',`${waf.violation_threshold} нарушений за ${waf.violation_window_seconds} с · бан ${waf.ban_ttl_seconds} с`],
    ['Область лимита',waf.route_specific?'Отдельно для маршрута':'Общий лимит сервиса'],['IP-состояния',`${waf.max_ip_states} адресов · TTL ${waf.state_ttl_seconds} с · ${waf.overflow_mode}`],
    ['Исключения checker',(waf.exceptions||[]).map(value=>`${value.cidr} · rate ${value.bypass_rate?'исключён':'действует'} · autoban ${value.bypass_ban?'исключён':'действует'}${value.comment?' · '+value.comment:''}`).join('\n')||'Нет'],
  ]
  return [
    ['Сервис / компонент',`${route.service_id} · ${route.component}`],['Внешний адрес',route.listen],['Backend',route.upstream],['Host',route.host||'Любой Host'],['Профиль',proxyProtocolLabel(route.protocol)],['Сертификат TLS',route.tls?.certificate_id||'Не используется'],
    ['Режим WAF',wafLabel(waf.mode)],...wafDetails,
    ['Доверенные proxy',(route.trusted_proxy_cidrs||[]).join('\n')||'Нет · IP из TCP-соединения'],['Запись тел',capture.mode==='metadata'?'Только метаданные':`${capture.mode==='grpc_body'?'Сырые gRPC bytes без автоматического редактирования · ':''}до ${capture.max_body_bytes} байт на каждое тело`],
    ['Скрываемые заголовки',(capture.redact_headers||[]).join(', ')||'Обязательные секретные заголовки'],['Скрываемые query-поля',(capture.redact_query_fields||[]).join(', ')||'Стандартные секретные поля'],['Скрываемые поля тела',capture.mode==='grpc_body'?'К opaque protobuf не применяются; настроенные правила приводят к пропуску bytes':(capture.redact_body_fields||[]).join(', ')||'Стандартные секретные поля'],['Шаблоны скрытия',(capture.body_patterns||[]).join('\n')||'Нет дополнительных шаблонов'],
    ['Лимиты соединения',`${limits.max_concurrent} одновременно · заголовки ${limits.max_header_bytes} байт · срок ${limits.max_connection_seconds} с`],['Таймауты',`Заголовки ${limits.read_header_timeout_seconds} с · upstream ${limits.upstream_response_header_timeout_seconds} с · простой ${limits.idle_timeout_seconds} с`],['Передаваемое тело',limits.max_body_bytes?`${limits.max_body_bytes} байт`:'Без отдельного лимита тела'],
  ]
}

function PolicyDiff({before,after,serviceName}:{before:ProxyRoute[];after:ProxyRoute[];serviceName:(id:string)=>string}){
  const changes=proxyRouteChanges(before,after)
  if(!changes.length)return <Notice>Параметры маршрутов не изменились после нормализации плана.</Notice>
  return <div className="proxy-policy-diff">{changes.map(change=>{
    const previous=new Map(change.before?policyFields(change.before):[]),next=new Map(change.after?policyFields(change.after):[])
    const keys=[...new Set([...previous.keys(),...next.keys()])].filter(key=>change.kind!=='changed'||previous.get(key)!==next.get(key))
    const route=change.after||change.before!
    return <section key={change.id}><h3><Badge tone={change.kind==='removed'?'bad':change.kind==='added'?'good':'warn'}>{change.kind==='added'?'Добавить':change.kind==='removed'?'Удалить':'Изменить'}</Badge>{serviceName(route.service_id)} · {route.component}<code>{change.id}</code></h3><div className="table-wrap"><table><thead><tr><th>Параметр</th><th>Было</th><th>Будет</th></tr></thead><tbody>{keys.map(key=><tr key={key}><td>{key}</td><td><pre>{previous.get(key)||'—'}</pre></td><td><pre>{next.get(key)||'—'}</pre></td></tr>)}</tbody></table></div></section>
  })}</div>
}

type TLSSelection=Pick<ProxyRouteInput,'protocol'|'tls'|'host'>
function TLSProfileFields({value,certificates,error,onChange}:{value:TLSSelection;certificates:ProxyTLSCertificate[];error:string;onChange:(value:TLSSelection)=>void}){
  const selected=certificates.find(certificate=>certificate.id===value.tls?.certificate_id)
  const available=certificates.filter(certificate=>certificate.valid)
  return <div className="proxy-tls-profile"><div className="form-columns"><label>Внешний HTTP-профиль<select value={value.protocol} onChange={event=>{const protocol=event.target.value as TLSSelection['protocol'];onChange({protocol,host:value.host||'',tls:protocol!=='http1'?{certificate_id:value.tls?.certificate_id||available[0]?.id||''}:undefined})}}><option value="http1">HTTP · HTTP/1.1</option><option value="https1" disabled={!available.length}>HTTPS · HTTP/1.1{!available.length?' · нет действующего сертификата':''}</option><option value="https2" disabled={!available.length}>HTTPS · HTTP/2 / gRPC → h2c</option></select></label><label>Точный Host{value.protocol!=='http1'?' (обязательно)':' (необязательно)'}<input value={value.host||''} required={value.protocol!=='http1'} maxLength={253} onChange={event=>onChange({...value,host:event.target.value})} placeholder="service.ctf.local"/><small>{value.protocol!=='http1'?'Host должен совпадать с заголовком запроса, включая порт. Для нестандартного порта укажите Host как example.org:19080; сертификат и SNI проверяются по имени без порта. HTTP/2 включается только отдельным профилем HTTPS/2 → h2c; backend должен поддерживать plaintext HTTP/2.':'Пустое значение допускает любой Host.'}</small></label></div>
    {value.protocol!=='http1'&&<>{error&&<Notice variant="warning">Не удалось проверить список сертификатов: {error}</Notice>}<label>Локальный сертификат<select required value={value.tls?.certificate_id||''} onChange={event=>onChange({...value,tls:{certificate_id:event.target.value}})}><option value="" disabled>Выберите действующий сертификат</option>{value.tls?.certificate_id&&!selected&&<option value={value.tls.certificate_id} disabled>{value.tls.certificate_id} · недоступен</option>}{certificates.map(certificate=><option key={certificate.id} value={certificate.id} disabled={!certificate.valid}>{certificate.id} · {(certificate.dns_names||[]).concat(certificate.ip_addresses||[]).join(', ')||'без имён'}{!certificate.valid?' · недействителен':''}</option>)}</select><small>Сертификаты добавляются локально администратором. Для обновления используется новый ID; закрытые ключи через панель не передаются.</small></label>{selected&&<div className="proxy-tls-facts"><div><span>Состояние</span><Badge tone={selected.valid?'good':'bad'}>{selected.valid?'Действует':'Недействителен'}</Badge>{selected.error_code&&<code>{selected.error_code}</code>}</div><div><span>DNS / IP</span><code>{(selected.dns_names||[]).concat(selected.ip_addresses||[]).join(', ')||'—'}</code></div><div><span>Срок</span><span>{time(selected.not_before)} — {time(selected.not_after)}</span></div><div><span>SHA-256</span><code>{selected.fingerprint_sha256||'—'}</code></div></div>}</>}
  </div>
}

function RouteEditor({value,existing,targets,certificates,certificateError,listenHint,observationListen='',onClose,onSave,cutoverTarget,privatePort,busy=false,submitError='',fixedBinding=false,serviceRateFor,serviceRateAllowed}:{
  value:ProxyRouteInput;existing:boolean;targets:ProxyTarget[];certificates:ProxyTLSCertificate[];certificateError:string;listenHint:string
  observationListen?:string;onClose:()=>void;onSave:(route:ProxyRouteInput)=>void;cutoverTarget?:ProxyCutoverTarget;privatePort?:number;busy?:boolean
  submitError?:string;fixedBinding?:boolean;serviceRateFor?:(serviceID:string)=>WafPolicy|undefined;serviceRateAllowed?:(serviceID:string)=>boolean
}){
  const [route,setRoute]=useState(value),[validation,setValidation]=useState('')
  const availableTargets=targets.filter(target=>existing?target.service_id===value.service_id&&target.component===value.component:target.private_binding||!serviceRateFor?.(target.service_id))
  const selected=availableTargets.find(target=>targetKey(target)===targetKey(route))
  const observationOnly=!cutoverTarget&&selected?.private_binding===false
  const simple=route.waf.mode==='rate_limit'
  const inheritedRate=existing?undefined:serviceRateFor?.(route.service_id)
  const simpleAllowed=existing&&!!selected?.private_binding&&!!serviceRateAllowed?.(route.service_id)
  const setWaf=<K extends keyof WafPolicy>(key:K,next:WafPolicy[K])=>setRoute(current=>({...current,waf:{...current.waf,[key]:next}}))
  const changeWafMode=(mode:WafMode)=>{
    setValidation('')
    setRoute(current=>{
      const waf=current.waf.mode==='rate_limit'&&mode!=='rate_limit'&&value.waf.mode==='rate_limit'?
        {...defaultsWaf,rate_per_second:current.waf.rate_per_second}:current.waf
      return {...current,waf:{...waf,mode}}
    })
  }
  const setCapture=<K extends keyof CapturePolicy>(key:K,next:CapturePolicy[K])=>setRoute(current=>({...current,capture:{...current.capture,[key]:next}}))
  const selectTarget=(key:string)=>{
    const target=availableTargets.find(value=>targetKey(value)===key)
    if(!target)return
    setValidation('')
    setRoute(current=>{
      const waf=!existing&&current.service_id!==target.service_id?serviceRateFor?.(target.service_id)||defaultsWaf:current.waf
      const next={...current,service_id:target.service_id,component:target.component,upstream_port:target.upstream_port,waf}
      if(target.private_binding)return next
      return {...next,listen:proxyLoopbackListener(next.listen)?next.listen:observationListen,waf:{...next.waf,mode:'observe_only'}}
    })
  }
  const minimumStateTTL=Math.max(1,Math.ceil(route.waf.violation_window_seconds),route.waf.rate_per_second>0?Math.ceil(route.waf.burst/route.waf.rate_per_second):3601)
  const stateTTLInvalid=route.waf.state_ttl_seconds<minimumStateTTL||minimumStateTTL>3600
  const stateTTLMessage=minimumStateTTL>3600?'Сочетание лимита и всплеска требует хранения IP-состояния дольше 3600 с. Увеличьте число запросов в секунду или уменьшите всплеск.':`Для выбранного лимита и окна нарушений срок хранения IP-состояния должен быть не меньше ${minimumStateTTL} с.`
  const submit=(event:FormEvent)=>{
    event.preventDefault()
    if(!cutoverTarget&&!selected){setValidation('Выберите подтверждённый backend.');return}
    if(observationOnly&&!proxyLoopbackListener(route.listen)){setValidation('Укажите loopback-адрес и порт для локального маршрута наблюдения.');return}
    if(route.protocol!=='http1'&&(!route.host?.trim()||!certificates.some(certificate=>certificate.id===route.tls?.certificate_id&&certificate.valid))){setValidation('Для HTTPS нужны точный Host и доступный действующий сертификат.');return}
    if(route.capture.mode==='grpc_body'&&route.protocol!=='https2'){setValidation('Сырые gRPC bytes доступны только в профиле HTTPS/2.');return}
    if(route.protocol==='https2'&&route.limits.max_concurrent>128){setValidation('HTTPS/2 поддерживает до 128 одновременных RPC на маршрут.');return}
    if(simple){
      if(!simpleAllowed&&!inheritedRate){setValidation('Лимит можно включить после применения маршрутов с закрытыми backend.');return}
      if(!validSimpleRate(route.waf.rate_per_second)){setValidation(`Введите целое число запросов от 1 до ${simpleRateMax}.`);return}
      onSave({...route,waf:inheritedRate||simpleRateWaf(route.waf.rate_per_second)})
      return
    }
    if(stateTTLInvalid){setValidation(stateTTLMessage);return}
    onSave(observationOnly?{...route,waf:{...route.waf,mode:'observe_only'}}:route)
  }
  return <Modal open onClose={onClose} title={cutoverTarget?'Параметры переноса на proxy':existing?'Изменить маршрут':'Добавить HTTP-маршрут'} description={cutoverTarget?'Общие настройки HTTP, TLS и WAF для всех переносимых внешних адресов. Параметры сохраняются в черновике группы перед просмотром общего плана.':'Параметры будут добавлены в черновик и затем показаны в плане подтверждения.'} wide><form className="dialog-body proxy-route-form" onSubmit={submit}>{(validation||submitError)&&<Notice variant="error">{submitError||validation}</Notice>}
    {cutoverTarget?<div className="proxy-cutover-addresses"><div><span>Сервис / компонент</span><strong>{cutoverTarget.service_name} · {cutoverTarget.component}</strong></div><div><span>Все внешние привязки → proxy</span><pre>{cutoverTarget.original_bindings.join('\n')}</pre></div><div><span>Будущий приватный backend</span><code>127.0.0.1:{privatePort} → {cutoverTarget.upstream_port}/tcp</code></div><small>Будут перенесены все перечисленные адреса. Для каждого создаётся маршрут с одинаковыми настройками и WAF в режиме наблюдения.</small></div>:<div className="form-columns"><label>Зарегистрированный backend<select required disabled={fixedBinding} value={selected?targetKey(selected):''} onChange={event=>selectTarget(event.target.value)}>{!selected&&<option value="" disabled>Выберите подтверждённый backend</option>}{availableTargets.map(target=><option key={targetKey(target)} value={targetKey(target)}>{target.service_name} · {target.component} · {target.upstream_address}{target.private_binding===false?' · наблюдение за прямой публикацией':''}</option>)}</select></label><label>{observationOnly?'Локальный адрес и порт':'Внешний адрес и порт'}<input value={route.listen} required disabled={fixedBinding} maxLength={128} onChange={event=>setRoute(current=>({...current,listen:event.target.value}))} placeholder={observationOnly?observationListen||'127.0.0.1:19081':'0.0.0.0:18081'}/><small>{fixedBinding?'Привязка управляется мастером переноса игровых портов.':`Разрешённые адреса: ${listenHint||'заданы администратором'}.`}</small></label></div>}
    {observationOnly&&<Notice variant="warning">Сервис доступен и по прямому адресу. Журнал этого маршрута содержит только запросы через proxy. WAF работает в режиме наблюдения.</Notice>}
    <TLSProfileFields value={route} certificates={certificates} error={certificateError} onChange={value=>setRoute(current=>({...current,...value,capture:value.protocol!=='https2'&&current.capture.mode==='grpc_body'?{...current.capture,mode:'metadata'}:current.capture}))}/>
    <h3>WAF</h3>
    <div className="form-columns">
      <label>Режим
        <select value={observationOnly?'observe_only':route.waf.mode} disabled={observationOnly||!!inheritedRate} onChange={event=>changeWafMode(event.target.value as WafMode)}>
          <option value="rate_limit" disabled={!simpleAllowed&&!inheritedRate}>Лимит запросов по IP</option>
          <option value="observe_only">Наблюдение</option>
          <option value="off" disabled={!existing}>Отключён</option>
          <option value="enforce" disabled={!existing}>Блокировка · расширенная</option>
        </select>
        <small>{observationOnly?'Для прямой публикации доступно наблюдение.':inheritedRate?'Маршрут унаследует текущий лимит сервиса.':existing?'Лимит по IP применяется ко всем маршрутам сервиса.':'Лимит по IP можно включить после применения маршрута.'}</small>
      </label>
      <label>Запросов в секунду<input type="number" required min={simple?1:0.000001} max={simpleRateMax} step={simple?1:'any'} disabled={!!inheritedRate} value={route.waf.rate_per_second} onChange={event=>setWaf('rate_per_second',Number(event.target.value))}/></label>
      {!simple&&<>
        <label>Допустимый всплеск<input type="number" required min="1" max="100000" value={route.waf.burst} onChange={event=>setWaf('burst',Number(event.target.value))}/></label>
        <label>Нарушений до автобана<input type="number" required min="1" max="10000" value={route.waf.violation_threshold} onChange={event=>setWaf('violation_threshold',Number(event.target.value))}/></label>
        <label>Окно нарушений, с<input type="number" required min="1" max="3600" value={route.waf.violation_window_seconds} onChange={event=>setWaf('violation_window_seconds',Number(event.target.value))}/></label>
        <label>Срок автобана, с<input type="number" required min="1" max="3600" value={route.waf.ban_ttl_seconds} onChange={event=>setWaf('ban_ttl_seconds',Number(event.target.value))}/></label>
      </>}
    </div>
    {simple?<Notice>Каждый IP делит лимит между всеми маршрутами сервиса. При превышении прокси отвечает HTTP 429 в течение {simpleRatePause} секунд.</Notice>:<>
      {value.waf.mode==='rate_limit'&&<Notice>Новый режим применяется ко всем маршрутам сервиса.</Notice>}
      {value.waf.mode!=='rate_limit'&&<label className="inline-check"><input type="checkbox" checked={!!route.waf.route_specific} onChange={event=>setWaf('route_specific',event.target.checked)}/><span>Считать лимит отдельно для этого маршрута. По умолчанию все маршруты сервиса делят один IP-лимит.</span></label>}
    <label>Срок хранения IP-состояния (TTL), с<input type="number" required min="1" max="3600" value={route.waf.state_ttl_seconds} onChange={event=>setWaf('state_ttl_seconds',Number(event.target.value))}/><small>Не меньше окна нарушений и времени восстановления полного всплеска: {minimumStateTTL} с.</small></label>{stateTTLInvalid&&<Notice variant="warning">{stateTTLMessage}</Notice>}
    <h4>Исключения checker</h4><p className="muted">Исключение определяется подтверждённым IP/CIDR. Трафик по исключению продолжает записываться.</p><div className="proxy-exceptions">{route.waf.exceptions.map((exception,index)=><div key={index}><input aria-label={`CIDR исключения ${index+1}`} placeholder="192.0.2.10/32" required value={exception.cidr} onChange={event=>setWaf('exceptions',route.waf.exceptions.map((item,i)=>i===index?{...item,cidr:event.target.value}:item))}/><label className="inline-check"><input type="checkbox" checked={exception.bypass_rate} onChange={event=>setWaf('exceptions',route.waf.exceptions.map((item,i)=>i===index?{...item,bypass_rate:event.target.checked}:item))}/>Без rate limit</label><label className="inline-check"><input type="checkbox" checked={exception.bypass_ban} onChange={event=>setWaf('exceptions',route.waf.exceptions.map((item,i)=>i===index?{...item,bypass_ban:event.target.checked}:item))}/>Без автобана</label><input aria-label={`Комментарий исключения ${index+1}`} placeholder="Комментарий" maxLength={256} value={exception.comment||''} onChange={event=>setWaf('exceptions',route.waf.exceptions.map((item,i)=>i===index?{...item,comment:event.target.value}:item))}/><Button type="button" variant="ghost" aria-label={`Удалить исключение ${index+1}`} onClick={()=>setWaf('exceptions',route.waf.exceptions.filter((_,i)=>i!==index))}><Trash2 size={15}/></Button></div>)}</div><Button type="button" variant="outline" disabled={route.waf.exceptions.length>=32} onClick={()=>setWaf('exceptions',[...route.waf.exceptions,{cidr:'',bypass_rate:true,bypass_ban:true,comment:''}])}><Plus size={14}/>Исключение</Button>
    </>}
    <h3>Запись трафика</h3><div className="form-columns"><label>Режим capture<select value={route.capture.mode} onChange={event=>setCapture('mode',event.target.value as CapturePolicy['mode'])}><option value="metadata">Только метаданные</option><option value="bounded_body">Ограниченные тела с редактированием</option>{route.protocol==='https2'&&<option value="grpc_body">Сырые gRPC bytes (явное включение)</option>}</select></label><label>Байт на каждое тело<input type="number" min="1" max="65536" step="1" required disabled={route.capture.mode==='metadata'} value={route.capture.max_body_bytes} onChange={event=>setCapture('max_body_bytes',Number(event.target.value))}/><small>Ограничивает сохранение, а не передаваемое тело.</small></label></div>
    {route.capture.mode==='grpc_body'&&<Notice variant="warning">Сохраняются неотредактированные gRPC сообщения после TLS termination: они могут содержать флаги и пароли. Доступ — sensitive access. Шаблоны и поля redaction для opaque protobuf неприменимы: при их настройке bytes будут опущены. WAF считает начало RPC, а не отдельные сообщения потока.</Notice>}
    {route.capture.mode==='bounded_body'&&<Notice>Записанные тела доступны пользователям с sensitive access. Неизвестный формат с неприменимым редактированием будет сохранён только как метаданные.</Notice>}
    <details className="proxy-advanced"><summary>Редактирование, доверенные proxy и лимиты</summary><div className="form-columns"><label>Скрываемые заголовки<textarea rows={3} value={route.capture.redact_headers.join('\n')} onChange={event=>setCapture('redact_headers',lines(event.target.value))}/><small>Authorization, Cookie и другие секретные заголовки скрываются всегда.</small></label><label>Поля query для скрытия<textarea rows={3} value={route.capture.redact_query_fields.join('\n')} onChange={event=>setCapture('redact_query_fields',lines(event.target.value))}/></label><label>Поля тела для скрытия<textarea rows={3} value={route.capture.redact_body_fields.join('\n')} onChange={event=>setCapture('redact_body_fields',lines(event.target.value))}/></label><label>Шаблоны скрываемых данных (RE2)<textarea rows={3} value={route.capture.body_patterns.join('\n')} onChange={event=>setCapture('body_patterns',event.target.value.split('\n').filter(Boolean))} maxLength={8192}/></label></div><label>Доверенные непосредственные proxy, CIDR<textarea rows={3} value={(route.trusted_proxy_cidrs||[]).join('\n')} onChange={event=>setRoute(current=>({...current,trusted_proxy_cidrs:lines(event.target.value)}))}/><small>По умолчанию IP берётся из TCP-соединения; присланные клиентом X-Forwarded-For не считаются доверенными.</small></label><div className="form-columns">{!simple&&<label>Максимум IP-состояний<input type="number" min="1" max="65536" value={route.waf.max_ip_states} onChange={event=>setWaf('max_ip_states',Number(event.target.value))}/></label>}{([['max_concurrent','Одновременных соединений',1,1024],['max_header_bytes','Лимит заголовков, байт',1024,262144],['read_header_timeout_seconds','Ожидание заголовков, с',1,60],['upstream_response_header_timeout_seconds','Заголовки upstream, с',1,300],['idle_timeout_seconds','Простой соединения, с',1,300],['max_connection_seconds','Срок соединения / WebSocket, с',1,3600],['max_body_bytes','Лимит передаваемого тела, байт (0 — без лимита)',0,1073741824]] as const).map(([key,label,min,max])=><label key={key}>{label}<input type="number" required min={min} max={key==='max_concurrent'&&route.protocol==='https2'?128:max} value={route.limits[key]} onChange={event=>setRoute(current=>({...current,limits:{...current.limits,[key]:Number(event.target.value)}}))}/></label>)}</div>{!simple&&<p className="muted">При исчерпании IP-состояний режим блокировки отклоняет новые IP (reject_new). Существующие активные баны сохраняются.</p>}</details>
    <div className="dialog-footer"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Отмена</Button><Button type="submit" busy={busy}>{cutoverTarget?'Сохранить параметры порта':'В черновик'}</Button></div>
  </form></Modal>
}

type CutoverDraft=ProxyCutoverGroupDraft

function PortCutovers({configured,serviceID,blocked,appliedRevision,observationCount,onStageObservationRemoval,services,certificates,certificateError,onRefresh}:{
  configured:boolean;serviceID?:string;blocked:boolean;appliedRevision?:number;observationCount:number;onStageObservationRemoval:()=>void
  services:Service[];certificates:ProxyTLSCertificate[];certificateError:string;onRefresh:()=>void
}){
  const [allTargets,setTargets]=useState<ProxyCutoverTargets|null>(null),[allViews,setViews]=useState<ProxyCutoverView[]>([])
  const targets=serviceID&&allTargets?{...allTargets,targets:allTargets.targets.filter(target=>target.service_id===serviceID),unavailable:(allTargets.unavailable||[]).filter(target=>target.service_id===serviceID)}:allTargets
  const views=serviceID?allViews.filter(view=>view.service_id===serviceID):allViews
  const [loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[connectionError,setConnectionError]=useState(''),[targetError,setTargetError]=useState(''),[error,setError]=useState(''),[message,setMessage]=useState(''),[refreshGeneration,setRefreshGeneration]=useState(0)
  const [setup,setSetup]=useState(false),[draft,setDraft]=useState<CutoverDraft|null>(null),[editingTarget,setEditingTarget]=useState<number|null>(null),[plan,setPlan]=useState<{preview:ProxyCutoverPreview;returning:boolean}|null>(null)
  const serviceName=(id:string)=>services.find(service=>service.id===id)?.name||id
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    const poll=async()=>{
      try{const next=await api<ProxyCutoverView[]>('/api/proxy/cutovers',{signal:controller.signal});if(active){setViews(next||[]);setConnectionError('')}}catch(error){if(active)setConnectionError(errorText(error))}finally{if(active)timer=setTimeout(()=>void poll(),2000)}
    }
    const load=async()=>{
      setLoading(true)
      const next=await Promise.allSettled([api<ProxyCutoverTargets>('/api/proxy/cutover/targets',{signal:controller.signal}),api<ProxyCutoverView[]>('/api/proxy/cutovers',{signal:controller.signal})])
      if(!active)return
      if(next[0].status==='fulfilled'){setTargets(next[0].value);setTargetError('')}else{setTargets(null);setTargetError(errorText(next[0].reason))}
      if(next[1].status==='fulfilled'){setViews(next[1].value||[]);setConnectionError('')}else setConnectionError(errorText(next[1].reason))
      setLoading(false);timer=setTimeout(()=>void poll(),2000)
    }
    void load();return()=>{active=false;controller.abort();clearTimeout(timer)}
  },[refreshGeneration,appliedRevision])
  const reviewTransfer=async()=>{
    if(!draft||!targets||blocked)return
    setBusy(true);setError('');setMessage('')
    try{
      const request=proxyCutoverGroupRequest(draft,targets)
      if(draft.targets.some(row=>row.route.protocol!=='http1'&&!certificates.some(certificate=>certificate.id===row.route.tls?.certificate_id&&certificate.valid)))throw new Error('Выберите доступный действующий сертификат для каждого HTTPS-порта.')
      const preview=await post<ProxyCutoverPreview>('/api/proxy/cutover/preview',request)
      setPlan({preview,returning:false})
    }catch(error){setError(errorText(error))}finally{setBusy(false)}
  }
  const reviewReturn=async(view:ProxyCutoverView)=>{
    if(blocked||(!view.can_return&&!(view.requires_recovery&&view.recoverable)))return
    setBusy(true);setError('');setMessage('');setDraft(null);setEditingTarget(null)
    try{setPlan({preview:await post<ProxyCutoverPreview>('/api/proxy/cutover/return-preview',{cutover_id:view.id}),returning:true})}catch(error){setError(errorText(error))}finally{setBusy(false)}
  }
  const confirm=async()=>{
    if(!plan||blocked)return
    setBusy(true);setError('')
    try{
      const view=await post<ProxyCutoverView>('/api/proxy/cutover/confirm',{proposal_id:plan.preview.proposal_id,digest:plan.preview.digest})
      setViews(current=>[view,...current.filter(item=>item.id!==view.id)]);setPlan(null);setDraft(null);setEditingTarget(null);setMessage(`Операция ${view.id} принята. Её результат определяется состоянием и этапом ниже.`);setRefreshGeneration(value=>value+1)
    }catch(error){setError(errorText(error))}finally{setBusy(false)}
  }
  return <section className="panel proxy-cutovers">
    <div className="panel-heading">
      <div>
        <h2>{serviceID?'Игровой трафик через прокси':'Перенос занятых портов'}</h2>
        <p>{serviceID?'Прокси займёт текущие игровые адреса и порты, а приложения получат закрытые порты на 127.0.0.1. Запросы жюри и участников продолжат идти на прежние адреса и появятся в журнале.':'Все публикуемые компоненты и TCP-порты одного сервиса переносятся одним планом. Возврат всей группы подтверждается отдельно.'}</p>
      </div>
      <div className="proxy-row-actions">
        <Button variant="outline" busy={loading} disabled={busy} onClick={()=>{setRefreshGeneration(value=>value+1);onRefresh()}}><RefreshCw size={15}/>Обновить</Button>
        <Button disabled={!configured||blocked||busy||loading||observationCount>0||!!connectionError||!targets?.targets?.length} onClick={()=>{setError('');setSetup(true)}}><Network size={15}/>{serviceID?'Перенести игровые порты':'Перенести сервис'}</Button>
      </div>
    </div>
    <div className="proxy-cutover-content">{blocked&&<Notice variant="warning">Перед переносом или возвратом завершите просмотр плана, сохраните либо отмените черновик маршрутов и согласуйте аварийную политику.</Notice>}{error&&<Notice variant="error">{error}</Notice>}{message&&<Notice>{message}</Notice>}{targetError&&<Notice variant="warning">Не удалось получить доступные привязки: {targetError}</Notice>}{connectionError&&<Notice variant="warning">Состояние операций сейчас не подтверждено: {connectionError} Действия недоступны до успешного обновления.</Notice>}
      {serviceID&&configured&&<small>Для публикаций на всех IPv4-интерфейсах прокси будет слушать 0.0.0.0. Перенос прерывает текущие соединения и поддерживает возврат. Сохранение ограниченных фрагментов HTTP-тел включается в настройках маршрута.</small>}
      {observationCount>0&&<Notice variant="warning"><p>У сервиса есть локальные маршруты для проверки. Перед переносом уберите их из политики и дождитесь применения изменений.</p><Button variant="outline" disabled={blocked||busy||loading||!!connectionError} onClick={onStageObservationRemoval}>Убрать локальные маршруты в черновике</Button></Notice>}
      <div className="table-wrap"><table><thead><tr><th>Сервис / компонент</th><th>Состояние / этап</th><th>Прямые / приватные привязки</th><th>Ревизия proxy</th><th/></tr></thead><tbody>{views.map(view=><tr key={view.id}><td>{serviceName(view.service_id)}<small>{proxyCutoverComponents(view).join(', ')||'—'} · <code>{view.id}</code></small><small>{time(view.updated_at)}</small></td><td><Badge tone={view.requires_recovery?'bad':view.can_return?'good':'neutral'}>{view.state||'Не указано'}</Badge><small>Этап: <code>{view.stage||'—'}</code></small>{view.active_component&&<small>Сейчас: {view.active_component}</small>}{!!view.completed_components?.length&&<small>Обработаны: {view.completed_components.join(', ')}</small>}{view.requires_recovery&&<small className="text-warning">Требуется восстановление</small>}{view.error&&<p className="proxy-cutover-error">{view.error}</p>}</td><td><pre>{(view.original_bindings||[]).join('\n')||'—'}</pre><small>Приватные:</small><pre>{(view.private_bindings||[]).join('\n')||'—'}</pre></td><td><small>Нужна: {view.proxy_revision||'—'}</small><small>Применена: {view.applied_revision||'—'}</small></td><td>{(view.can_return||(view.requires_recovery&&view.recoverable))?<Button variant={view.requires_recovery?'danger':'outline'} busy={busy} disabled={blocked||!!connectionError||loading} onClick={()=>void reviewReturn(view)}>{view.requires_recovery?'Восстановить прямые порты':'Вернуть прямые порты'}</Button>:view.requires_recovery?<small>Автоматическое восстановление недоступно. Сохраните сообщение об ошибке для локальной диагностики.</small>:<small>Доступных действий нет</small>}</td></tr>)}</tbody></table></div>
      {!views.length&&<Empty>{loading?'Получаем состояние переносов…':connectionError?'Список переносов недоступен.':'Переносы портов ещё не выполнялись.'}</Empty>}
      {!!targets?.unavailable?.length&&<details className="proxy-unavailable" open={serviceID&&!targets.targets.length?true:undefined}><summary>Компоненты без доступного переноса ({targets.unavailable.length})</summary><ul>{targets.unavailable.map((item,index)=><li key={`${item.service_id}:${item.component}:${index}`}>{serviceName(item.service_id)} · {item.component}: {item.reason}</li>)}</ul></details>}
    </div>
    {setup&&targets&&<CutoverSetup targets={targets} onClose={()=>setSetup(false)} onNext={value=>{setDraft(value);setEditingTarget(null);setSetup(false);setError('')}}/>}
    {draft&&!plan&&editingTarget===null&&targets&&<CutoverGroupEditor draft={draft} targets={targets} busy={busy} error={error} onClose={()=>{if(!busy){setDraft(null);setError('')}}} onChange={setDraft} onEdit={setEditingTarget} onReview={()=>void reviewTransfer()}/>}
    {draft&&!plan&&editingTarget!==null&&draft.targets[editingTarget]&&<RouteEditor key={targetKey(draft.targets[editingTarget].target)} value={draft.targets[editingTarget].route} existing={false} targets={[]} certificates={certificates} certificateError={certificateError} listenHint="" cutoverTarget={draft.targets[editingTarget].target} privatePort={draft.targets[editingTarget].privatePort} busy={busy} onClose={()=>setEditingTarget(null)} onSave={route=>{setDraft(current=>current?{...current,targets:proxyCutoverUpdateSettings(current.targets,editingTarget,route)}:current);setEditingTarget(null);setError('')}}/>}
    {plan&&<CutoverPlan key={plan.preview.proposal_id} preview={plan.preview} returning={plan.returning} serviceName={serviceName(plan.preview.service_id)} busy={busy} error={error} blocked={blocked} onClose={()=>{if(!busy){setPlan(null);setError('')}}} onConfirm={()=>void confirm()}/>}
  </section>
}

function CutoverSetup({targets,onClose,onNext}:{targets:ProxyCutoverTargets;onClose:()=>void;onNext:(draft:CutoverDraft)=>void}){
  const services=[...new Map((targets.targets||[]).map(target=>[target.service_id,target.service_name])).entries()]
  const [serviceID,setServiceID]=useState(services[0]?.[0]||''),[ports,setPorts]=useState<Record<string,number>>({}),[error,setError]=useState('')
  let rows:ProxyCutoverTarget[]=[],invalid=''
  try{rows=proxyCutoverGroupTargets(targets,serviceID)}catch(error){invalid=errorText(error)}
  const unavailable=targets.unavailable?.filter(item=>item.service_id===serviceID)||[]
  const privatePort=(target:ProxyCutoverTarget,index:number)=>ports[targetKey(target)]??targets.backend_port_min+index
  const submit=(event:FormEvent)=>{
    event.preventDefault()
    try{
      if(invalid||unavailable.length)throw new Error(invalid||'Сервис содержит публикации, для которых полный перенос недоступен.')
      const draft:CutoverDraft={serviceID,targets:rows.map((target,index)=>{
        const routeIDBase=proxyRouteID('route-cutover-'),route=proxyCutoverRoutes(target,{host:'',protocol:'http1',capture:structuredClone(defaultsCapture),waf:structuredClone(defaultsWaf),trusted_proxy_cidrs:[],limits:{...defaultsLimits}},routeIDBase)[0]
        return {target,privatePort:privatePort(target,index),routeIDBase,route,hosts:{}}
      })}
      proxyCutoverGroupRequest(draft,targets)
      onNext(draft)
    }catch(error){setError(errorText(error))}
  }
  return <Modal open onClose={onClose} title="Перенести сервис на HTTP proxy" description="Выберите сервис и отдельный закрытый backend-порт для каждого публикуемого TCP-порта. Этот шаг ничего не меняет." wide><form className="dialog-body" onSubmit={submit}>{(error||invalid)&&<Notice variant="error">{error||invalid}</Notice>}<label>Сервис<select required value={serviceID} onChange={event=>{setServiceID(event.target.value);setPorts({});setError('')}}>{services.map(([id,name])=><option key={id} value={id}>{name}</option>)}</select></label><p>Переносятся все перечисленные компоненты и TCP-порты. Все эти порты должны обслуживать HTTP/HTTPS; совместимость игрового checker проверяется отдельно. Исключение отдельного порта оставило бы прямой обход proxy.</p><div className="table-wrap"><table><thead><tr><th>Компонент / порт контейнера</th><th>Все прежние внешние привязки</th><th>Закрытый порт на 127.0.0.1</th></tr></thead><tbody>{rows.map((target,index)=><tr key={targetKey(target)}><td>{target.component}<small>{target.upstream_port}/tcp</small></td><td><pre>{target.original_bindings.join('\n')}</pre></td><td><input aria-label={`Backend-порт ${target.component}:${target.upstream_port}`} required type="number" min={targets.backend_port_min} max={targets.backend_port_max} value={privatePort(target,index)} onChange={event=>setPorts(current=>({...current,[targetKey(target)]:Number(event.target.value)}))}/></td></tr>)}</tbody></table></div><small>Разрешено: {targets.backend_port_min}–{targets.backend_port_max}; каждому компоненту/порту нужен уникальный backend-порт. Лимит группы: {targets.max_components||8} компонентов, {targets.max_targets||16} TCP-портов, {targets.max_listeners||32} внешних привязок.</small>{!!unavailable.length&&<Notice variant="warning"><ul>{unavailable.map((item,index)=><li key={index}>{item.component}: {item.reason}</li>)}</ul></Notice>}<Notice variant="warning">Приложения будут последовательно пересозданы с текущими образами и подключёнными томами. Соединения прервутся; записываемые слои контейнеров пересоздаются. Содержимое томов не откатывается. Изменения начнутся только после подтверждения общего плана.</Notice><div className="dialog-footer"><Button type="button" variant="outline" onClick={onClose}>Отмена</Button><Button type="submit" disabled={!rows.length||!!invalid||!!unavailable.length}>Настроить маршруты группы</Button></div></form></Modal>
}

function CutoverGroupEditor({draft,targets,busy,error,onClose,onChange,onEdit,onReview}:{draft:CutoverDraft;targets:ProxyCutoverTargets;busy:boolean;error:string;onClose:()=>void;onChange:(draft:CutoverDraft)=>void;onEdit:(index:number)=>void;onReview:()=>void}){
  const [validation,setValidation]=useState('')
  const submit=(event:FormEvent)=>{event.preventDefault();try{proxyCutoverGroupRequest(draft,targets);setValidation('');onReview()}catch(error){setValidation(errorText(error))}}
  return <Modal open onClose={onClose} title="Маршруты группы" description="Параметры HTTP/TLS и записи настраиваются для каждого порта. Общий IP-лимит WAF согласован для всего сервиса." wide><form className="dialog-body proxy-cutover-group" onSubmit={submit}>{(error||validation)&&<Notice variant="error">{error||validation}</Notice>}{draft.targets.map((row,index)=><section className="proxy-cutover-target" key={targetKey(row.target)}><div className="panel-heading"><h3>{row.target.component} · {row.target.upstream_port}/tcp → 127.0.0.1:{row.privatePort}</h3><Button type="button" variant="outline" disabled={busy} onClick={()=>onEdit(index)}><Edit3 size={14}/>HTTP / TLS / capture / WAF</Button></div><p>{row.route.protocol!=='http1'?`HTTPS · сертификат ${row.route.tls?.certificate_id||'не выбран'}`:'HTTP'} · capture: {row.route.capture.mode} · WAF: наблюдение, {row.route.waf.route_specific?'отдельно для маршрутов':'общий лимит сервиса'}</p><div className="table-wrap"><table><thead><tr><th>Прежний адрес → proxy</th><th>Точный HTTP Host{row.route.protocol!=='http1'?' · обязателен':''}</th></tr></thead><tbody>{row.target.original_bindings.map(listen=><tr key={listen}><td><code>{listen}</code></td><td><input aria-label={`Host ${row.target.component}:${row.target.upstream_port} ${listen}`} required={row.route.protocol!=='http1'} maxLength={253} value={row.hosts[listen]??row.route.host??''} placeholder="example.org:19080" onChange={event=>onChange({...draft,targets:draft.targets.map((item,i)=>i===index?{...item,hosts:{...item.hosts,[listen]:event.target.value}}:item)})}/></td></tr>)}</tbody></table></div><small>Host совпадает с запросом клиента, включая нестандартный порт. Для разных внешних портов укажите точные значения отдельно; сертификат и SNI проверяются по имени без порта.</small></section>)}<Notice>Изменение общего WAF у одного порта применяется ко всем портам с общим лимитом сервиса. Явные отдельные лимиты маршрутов остаются отдельными. Все новые маршруты начинают в режиме наблюдения.</Notice><div className="dialog-footer"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Отмена</Button><Button type="submit" busy={busy}>Посмотреть общий план</Button></div></form></Modal>
}

function CutoverContainerEvidence({container,historical=false}:{container:ProxyCutoverContainer;historical?:boolean}){
  return <div className="proxy-cutover-container"><p>{container.component} · {container.name}</p><div><span>{historical?'Исторический ID опорного контейнера':'Текущий ID'}</span><code>{container.id}</code></div><div><span>Образ</span><code>{container.image_id}</code></div><div><span>{historical?'Привязки опорного состояния':'Текущие порты'}</span><pre>{(container.ports||[]).join('\n')||'—'}</pre></div><div><span>Подключения данных</span><pre>{(container.mounts||[]).map(mount=>`${mount.type} · ${mount.source||'—'} → ${mount.target}${mount.read_only?' · read-only':''}`).join('\n')||'Нет подключённых томов'}</pre></div></div>
}

function CutoverPlan({preview,returning,serviceName,busy,error,blocked,onClose,onConfirm}:{preview:ProxyCutoverPreview;returning:boolean;serviceName:string;busy:boolean;error:string;blocked:boolean;onClose:()=>void;onConfirm:()=>void}){
  const [downtimeAccepted,setDowntimeAccepted]=useState(false),[dataAccepted,setDataAccepted]=useState(false),[now,setNow]=useState(Date.now())
  useEffect(()=>{const timer=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(timer)},[])
  const expires=Date.parse(preview.expires_at),expired=!Number.isFinite(expires)||now>=expires
  const evidence=proxyCutoverGroupEvidence(preview)
  const portPlans=preview.targets?.length?preview.targets:[{component:preview.component,upstream_port:preview.upstream_port,private_port:preview.private_port,original_bindings:preview.original_bindings||[],private_binding:preview.private_bindings?.[0]||''}]
  return <Modal open onClose={onClose} title={returning?'Подтвердить возврат всей группы':'Подтвердить перенос сервиса на HTTP proxy'} description="Подтверждение запускает одну операцию с последовательным переключением приложений и перерывом доступа." wide><div className="dialog-body proxy-preview proxy-cutover-plan"><h3>{serviceName} · {evidence.components.join(', ')||'Компоненты не определены'}</h3><p>Пересоздаются только перечисленные приложения с текущими образами и подключёнными томами. Содержимое томов не откатывается; записываемые слои контейнеров пересоздаются. БД и незатронутые зависимости не пересоздаются. Возврат сохраняет текущую версию кода и данные.</p>
    <div className="table-wrap"><table><thead><tr><th>Компонент / порт контейнера</th><th>{returning?'Восстановить прямые привязки':'Внешние привязки → proxy'}</th><th>Закрытый backend</th></tr></thead><tbody>{portPlans.map((target,index)=><tr key={`${target.component}:${target.upstream_port}:${index}`}><td>{target.component}<small>{target.upstream_port}/tcp</small></td><td><pre>{target.original_bindings.join('\n')||'—'}</pre></td><td><code>{target.private_binding||'—'}</code></td></tr>)}</tbody></table></div>
    <small>{returning?'Прямой возврат убирает маршруты этой группы и защиту WAF на этих адресах. Текущее размещение после частичного сбоя сверяется по фактическим контейнерам ниже.':'Proxy получит все прежние внешние адреса; приложения будут доступны через отдельные закрытые backend-порты.'}</small>
    <h3>Фактические приложения к пересозданию</h3>{evidence.items.map(item=><section className="proxy-cutover-target" key={item.component}><h4>{item.component}</h4>{item.current.map(container=><CutoverContainerEvidence key={container.id} container={container}/>)}{item.createMissing&&<Notice variant="warning">Приложение {item.component} отсутствует. Восстановление создаст его из однозначного опорного образа и с указанными хранилищами. Исторический ID опорного контейнера не является текущим ID.</Notice>}{!item.canConfirm&&<Notice variant="error">Для {item.component} нет однозначного текущего контейнера либо явного разрешения восстановить отсутствующее приложение из одного опорного состояния.</Notice>}</section>)}{!evidence.canConfirm&&<Notice variant="error">Состав группы или доказательства текущего состояния неоднозначны. Подтверждение недоступно; подготовьте свежий план после сверки.</Notice>}
    {!!preview.recovery_baseline?.length&&<section className="proxy-recovery-baseline"><h3>Опорное состояние для восстановления</h3><p>Подтверждённые образы и хранилища; ID ниже относятся к исторической опоре, а не к текущему состоянию.</p>{preview.recovery_baseline.map(container=><CutoverContainerEvidence key={container.id} container={container} historical/>)}</section>}
    {!!evidence.other.length&&<details className="proxy-unavailable"><summary>Другие текущие компоненты — не пересоздаются ({evidence.other.length})</summary>{evidence.other.map(container=><CutoverContainerEvidence key={container.id} container={container}/>)}</details>}
    <p>Конфигурация сервиса: ревизия {preview.policy_revision} · состояние {preview.state_sequence}. Proxy: применена ревизия {preview.applied_revision} → план {preview.policy.revision}.</p><PolicyDiff before={preview.previous_policy?.routes||[]} after={preview.policy.routes||[]} serviceName={id=>id===preview.service_id?serviceName:id}/>{!!preview.changes?.length&&<ul className="proxy-cutover-changes">{preview.changes.map((change,index)=><li key={index}>{change}</li>)}</ul>}{!!preview.warnings?.length&&<Notice variant="warning"><ul>{preview.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul></Notice>}
    <label className="inline-check"><input type="checkbox" checked={downtimeAccepted} onChange={event=>setDowntimeAccepted(event.target.checked)}/><span>Подтверждаю перерыв доступа и разрыв соединений при последовательном пересоздании приложений группы.</span></label><label className="inline-check"><input type="checkbox" checked={dataAccepted} onChange={event=>setDataAccepted(event.target.checked)}/><span>Подтверждаю текущие образы и подключённые тома всех компонентов. Данные томов не откатываются; записываемые слои пересоздаются. Возврат прямых портов отключает защиту proxy для группы.</span></label><p className="muted">Digest: <code>{preview.digest}</code> · срок: {time(preview.expires_at)}.</p>{expired&&<Notice variant="warning">Срок плана истёк. Подготовьте свежий план.</Notice>}{error&&<Notice variant="error">{error}</Notice>}<div className="dialog-footer"><Button variant="outline" disabled={busy} onClick={onClose}>Назад</Button><Button variant={returning?'danger':'default'} busy={busy} disabled={blocked||!downtimeAccepted||!dataAccepted||expired||!evidence.canConfirm} onClick={onConfirm}><Check size={15}/>{returning?'Подтвердить возврат группы':'Подтвердить перенос группы'}</Button></div>
  </div></Modal>
}

function BanDialog({routes,serviceName,onClose,onSaved}:{routes:Pick<ProxyRoute,'id'|'service_id'|'waf'>[];serviceName:(id:string)=>string;onClose:()=>void;onSaved:()=>void}){
  const [serviceID,setServiceID]=useState(routes[0]?.service_id||''),[routeID,setRouteID]=useState(''),[ip,setIP]=useState(''),[ttl,setTTL]=useState(60),[comment,setComment]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('')
  const submit=async(event:FormEvent)=>{event.preventDefault();setBusy(true);setError('');try{await post('/api/proxy/bans',{service_id:serviceID,route_id:routeID||undefined,ip,ttl_seconds:ttl,comment});onSaved()}catch(error){setError(errorText(error))}finally{setBusy(false)}}
  return <Modal open onClose={onClose} title="Временно заблокировать IP"><form className="dialog-body" onSubmit={submit}>{error&&<Notice variant="error">{error}</Notice>}<label>Сервис<select required value={serviceID} onChange={event=>{setServiceID(event.target.value);setRouteID('')}}>{[...new Set(routes.map(route=>route.service_id))].map(id=><option value={id} key={id}>{serviceName(id)}</option>)}</select></label><label>Область<select value={routeID} onChange={event=>setRouteID(event.target.value)}><option value="">Весь сервис</option>{routes.filter(route=>route.service_id===serviceID&&route.waf.route_specific).map(route=><option key={route.id} value={route.id}>{route.id}</option>)}</select></label><label>IP клиента<input required value={ip} maxLength={64} onChange={event=>setIP(event.target.value)} placeholder="192.0.2.10"/></label><label>Срок, с<input type="number" required min="1" max="3600" value={ttl} onChange={event=>setTTL(Number(event.target.value))}/></label><label>Причина<textarea rows={3} minLength={3} maxLength={500} required value={comment} onChange={event=>setComment(event.target.value)}/></label><div className="dialog-footer"><Button variant="outline" type="button" onClick={onClose}>Отмена</Button><Button variant="danger" type="submit" busy={busy}>Заблокировать</Button></div></form></Modal>
}

function UnbanDialog({ban,services,serviceName,onClose,onSaved}:{ban:ProxyBan;services:Service[];serviceName:string;onClose:()=>void;onSaved:()=>void}){
  const [comment,setComment]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),[serviceID,setServiceID]=useState(ban.service_id),[routeID,setRouteID]=useState(ban.route_id||''),[ip,setIP]=useState(ban.ip)
  const submit=async(event:FormEvent)=>{event.preventDefault();setBusy(true);setError('');try{await post('/api/proxy/unban',{service_id:serviceID,route_id:routeID||undefined,ip,comment});onSaved()}catch(error){setError(errorText(error))}finally{setBusy(false)}}
  return <Modal open onClose={onClose} title="Снять временный бан"><form className="dialog-body" onSubmit={submit}>{ban.ip?<p>{serviceName} · <code>{ban.ip}</code> · срок до {time(ban.expires_at)}</p>:<><label>Сервис<select required value={serviceID} onChange={event=>setServiceID(event.target.value)}>{services.map(service=><option key={service.id} value={service.id}>{service.name}</option>)}</select></label><label>IP клиента<input required maxLength={64} value={ip} onChange={event=>setIP(event.target.value)} placeholder="192.0.2.10"/></label><label>ID маршрута (для отдельного лимита маршрута)<input maxLength={64} value={routeID} onChange={event=>setRouteID(event.target.value)} placeholder="Пусто — общий бан сервиса"/></label></>}{error&&<Notice variant="error">{error}</Notice>}<label>Комментарий для аудита<textarea rows={3} minLength={3} maxLength={500} required value={comment} onChange={event=>setComment(event.target.value)}/></label><div className="dialog-footer"><Button variant="outline" type="button" onClick={onClose}>Отмена</Button><Button type="submit" busy={busy}>Снять бан</Button></div></form></Modal>
}
