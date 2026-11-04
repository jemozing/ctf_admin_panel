export type WafMode = 'off'|'observe_only'|'rate_limit'|'enforce'
export type WafException = {cidr:string;bypass_rate:boolean;bypass_ban:boolean;comment?:string}
export type WafPolicy = {mode:WafMode;rate_per_second:number;burst:number;violation_threshold:number;violation_window_seconds:number;ban_ttl_seconds:number;max_ip_states:number;state_ttl_seconds:number;overflow_mode:'reject_new';route_specific?:boolean;exceptions:WafException[]}
export type CapturePolicy = {mode:'metadata'|'bounded_body'|'grpc_body';max_body_bytes:number;redact_headers:string[];redact_query_fields:string[];redact_body_fields:string[];body_patterns:string[]}
export type RouteLimits = {max_concurrent:number;max_header_bytes:number;read_header_timeout_seconds:number;upstream_response_header_timeout_seconds:number;idle_timeout_seconds:number;max_connection_seconds:number;max_body_bytes:number}
export type ProxyProtocol = 'http1'|'https1'|'https2'
export type ProxyTLSRoutePolicy = {certificate_id:string}
export type ProxyTLSCertificate = {id:string;dns_names:string[];ip_addresses:string[];not_before:string;not_after:string;fingerprint_sha256:string;valid:boolean;error_code?:string}
export type ProxyTLSCertificates = {certificates:ProxyTLSCertificate[];total:number;truncated:boolean}
export type ProxyRoute = {id:string;service_id:string;component:string;listen:string;host?:string;upstream:string;protocol:ProxyProtocol;tls?:ProxyTLSRoutePolicy;capture:CapturePolicy;waf:WafPolicy;trusted_proxy_cidrs?:string[];limits:RouteLimits}
export type ProxyPolicy = {schema_version:number;revision:number;routes:ProxyRoute[]}
export type ProxyTarget = {service_id:string;service_name:string;component:string;upstream_port:number;upstream_address:string;private_binding:boolean}
export type ProxyTargets = {targets:ProxyTarget[];unavailable:{service_id:string;component:string;reason:string}[];listeners?:string[];allowed_listen_ips:string[];allowed_listen_endpoints?:string[];listen_port_min:number;listen_port_max:number;warnings?:string[]}
export type ProxyStatus = {configured:boolean;available:boolean;desired_revision:number;applied_revision:number;state?:string;error?:string;last_error?:string;waf_degraded?:boolean;routes?:number;recorder_available?:boolean;collector_epoch?:string;counters?:Record<string,number>;limits?:{retention_seconds:number;max_bytes:number};capabilities?:{tls:boolean;cutover:boolean}}
export type ProxyStatusEnvelope = {configured:boolean;desired_revision:number;applied_revision:number;proxy:{available:boolean;desired_revision:number;applied_revision:number;routes:number;waf_degraded:boolean;last_error?:string;collector_epoch?:string;counters?:Record<string,number>};recorder:TrafficStatus;error?:string}
export function proxyStatusView(value:ProxyStatusEnvelope):ProxyStatus{return {...value.proxy,configured:value.configured,desired_revision:value.desired_revision,applied_revision:value.applied_revision,error:value.error,recorder_available:value.recorder?.available}}
export function proxyListenAddress(ip:string,port:number){return `${ip.includes(':')&&!ip.startsWith('[')?'['+ip+']':ip}:${port}`}
export function proxyLoopbackIP(value:string):boolean{
  if(/^127(?:\.\d{1,3}){3}$/.test(value))return value.split('.').every(part=>String(Number(part))===part&&Number(part)<=255)
  if(!value.includes(':')||!/^[0-9a-f:.]+$/i.test(value))return false
  try{
    const canonical=new URL(`http://[${value}]/`).hostname
    return canonical==='[::1]'||/^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(canonical)
  }catch{return false}
}
export function proxyLoopbackListener(value:string):boolean{
  const match=/^(?:\[([^\]]+)\]|([^:]+)):([1-9]\d{0,4})$/.exec(value)
  return !!match&&Number(match[3])<=65535&&proxyLoopbackIP(match[1]??match[2])
}
export function proxyRouteID(prefix='route-'){return prefix+Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('')}
export type PolicyView = {policy:ProxyPolicy;desired_revision:number;applied_revision:number;configured:boolean;external_revision?:boolean;error?:string;warnings?:string[]}
export type ProxyRouteInput = Omit<ProxyRoute,'upstream'> & {upstream_port:number}
export const wafBlocks=(mode:WafMode)=>mode==='rate_limit'||mode==='enforce'

export function proxyServiceRatePolicy(routes:ProxyRouteInput[],serviceID:string):WafPolicy|undefined{
  return routes.find(route=>route.service_id===serviceID&&route.waf.mode==='rate_limit')?.waf
}

export function proxyRouteDraft(routes:ProxyRouteInput[],updated:ProxyRouteInput):ProxyRouteInput[]{
  const previous=routes.find(route=>route.id===updated.id)
  if(!previous)return [...routes,updated]
  const policyChanged=JSON.stringify(canonical(previous.waf))!==JSON.stringify(canonical(updated.waf))
  const allRoutes=previous.waf.mode==='rate_limit'||updated.waf.mode==='rate_limit'
  return routes.map(route=>{
    if(route.id===updated.id)return updated
    if(!policyChanged||route.service_id!==updated.service_id)return route
    if(allRoutes||(!updated.waf.route_specific&&!route.waf.route_specific))return {...route,waf:updated.waf}
    return route
  })
}
export type ProxyPreview = {proposal_id:string;digest:string;policy:ProxyPolicy;previous_policy?:ProxyPolicy;observed_applied_revision?:number;warnings:string[];changes?:string[];expires_at?:string}
export type ProxyApply = {desired_revision:number;applied_revision:number;activation:'pending'|'applied';operation_id?:string}
export type ProxyBan = {service_id:string;route_id?:string;ip:string;reason:string;source:string;created_at:string;expires_at:string}
export type ProxyBans = {bans:ProxyBan[];total:number;truncated:boolean;available?:boolean;error?:string}
export type ProxyCutoverTarget = {service_id:string;service_name:string;component:string;upstream_port:number;original_bindings:string[]}
export type ProxyCutoverTargets = {targets:ProxyCutoverTarget[];unavailable:{service_id:string;component:string;reason:string}[];allowed_listen_ips:string[];allowed_listen_endpoints?:string[];listen_port_min:number;listen_port_max:number;backend_port_min:number;backend_port_max:number;max_components?:number;max_targets?:number;max_listeners?:number}
export type ProxyCutoverSelection={component:string;upstream_port:number;private_port:number}
export type ProxyCutoverTargetPlan=ProxyCutoverSelection&{original_bindings:string[];private_binding:string}
export type ProxyCutoverContainer = {id:string;name:string;project:string;component:string;image_id:string;state:string;health:string;ports:string[];mounts:{type:string;source?:string;target:string;read_only:boolean}[]}
export type ProxyCutoverPreview = {proposal_id:string;digest:string;expires_at:string;mode:string;cutover_id:string;service_id:string;component:string;upstream_port:number;private_port:number;targets?:ProxyCutoverTargetPlan[];components?:string[];missing_applications?:string[];policy_revision:number;state_sequence:number;configuration_digest:string;runtime_digest:string;proxy_revision:number;applied_revision:number;original_bindings:string[];private_bindings:string[];containers:ProxyCutoverContainer[];recovery_baseline?:ProxyCutoverContainer[];application_missing?:boolean;policy:ProxyPolicy;previous_policy:ProxyPolicy;changes:string[];warnings:string[]}
export type ProxyCutoverView = {id:string;proposal_id:string;mode:string;service_id:string;component:string;components?:string[];targets?:ProxyCutoverTargetPlan[];active_component?:string;completed_components?:string[];state:string;stage:string;digest:string;sequence:number;updated_at:string;error?:string;recoverable:boolean;can_return:boolean;requires_recovery:boolean;original_bindings:string[];private_bindings:string[];proxy_revision:number;applied_revision:number}
export type ProxyCutoverRouteSettings=Pick<ProxyRouteInput,'host'|'protocol'|'tls'|'capture'|'waf'|'trusted_proxy_cidrs'|'limits'>
export function proxyCutoverApplicationEvidence(preview:Pick<ProxyCutoverPreview,'component'|'containers'|'recovery_baseline'|'application_missing'>){
  const current=(preview.containers||[]).filter(container=>container.component===preview.component),baseline=(preview.recovery_baseline||[]).filter(container=>container.component===preview.component)
  const createMissing=preview.application_missing===true&&current.length===0&&baseline.length===1
  return {current,baseline,createMissing,canConfirm:current.length===1||createMissing}
}

export function proxyCutoverListener(value:string):string{
  const match=/^(\[[0-9a-fA-F:.]+\]|[0-9.]+):(\d+)$/.exec(value)
  if(!match)throw new Error('Переносимая привязка должна содержать явный IP-адрес и внешний порт.')
  const host=match[1].replace(/^\[|\]$/g,''),published=Number(match[2])
  if(published<1||published>65535)throw new Error('Привязка содержит недопустимый порт.')
  const listen=proxyListenAddress(host,published)
  if(listen!==value)throw new Error('Привязка должна использовать подтверждённую каноническую запись адреса и порта.')
  return listen
}

export function proxyCutoverRoutes(target:ProxyCutoverTarget,settings:ProxyCutoverRouteSettings,routeIDBase:string,hosts:Record<string,string>={}):ProxyRouteInput[]{
  if(!target.original_bindings?.length||target.original_bindings.length>32||target.upstream_port<1||target.upstream_port>65535)throw new Error('Для переноса требуется от одной до 32 подтверждённых привязок и явный порт контейнера.')
  const seen=new Set<string>()
  return target.original_bindings.map((raw,index)=>{
    const listen=proxyCutoverListener(raw)
    if(seen.has(listen))throw new Error('Набор привязок содержит повтор внешнего адреса.')
    seen.add(listen)
    return {id:`${routeIDBase}-${index+1}`,service_id:target.service_id,component:target.component,upstream_port:target.upstream_port,listen,host:hosts[listen]??settings.host??'',protocol:settings.protocol,...(settings.tls?{tls:{certificate_id:settings.tls.certificate_id}}:{}),capture:structuredClone(settings.capture),waf:{...structuredClone(settings.waf),mode:'observe_only'},trusted_proxy_cidrs:[...(settings.trusted_proxy_cidrs||[])],limits:{...settings.limits}}
  })
}

export type ProxyCutoverDraftTarget={target:ProxyCutoverTarget;privatePort:number;routeIDBase:string;route:ProxyRouteInput;hosts:Record<string,string>}
export type ProxyCutoverGroupDraft={serviceID:string;targets:ProxyCutoverDraftTarget[]}
export function proxyCutoverGroupTargets(value:ProxyCutoverTargets,serviceID:string):ProxyCutoverTarget[]{
  const rows=(value.targets||[]).filter(row=>row.service_id===serviceID).sort((a,b)=>a.component.localeCompare(b.component)||a.upstream_port-b.upstream_port)
  const components=new Set<string>(),pairs=new Set<string>(),listeners=new Set<string>()
  if(!rows.length||rows.length>(value.max_targets||16))throw new Error('Сервис не содержит допустимый полный набор переносимых портов.')
  for(const row of rows){
    const pair=`${row.component}:${row.upstream_port}`
    if(!row.component||pairs.has(pair))throw new Error('Набор портов содержит неоднозначный компонент или повтор порта.')
    pairs.add(pair);components.add(row.component)
    for(const raw of row.original_bindings||[]){const listener=proxyCutoverListener(raw);if(listeners.has(listener))throw new Error('Внешняя привязка повторяется у разных компонентов или портов.');listeners.add(listener)}
    if(!row.original_bindings?.length)throw new Error('Для порта отсутствуют подтверждённые внешние привязки.')
  }
  if(components.size>(value.max_components||8)||listeners.size>(value.max_listeners||32))throw new Error('Сервис превышает разрешённый размер группового переноса.')
  return rows
}

export function proxyCutoverUpdateSettings(rows:ProxyCutoverDraftTarget[],index:number,route:ProxyRouteInput):ProxyCutoverDraftTarget[]{
  return rows.map((row,i)=>i===index?{...row,route:structuredClone(route)}:!route.waf.route_specific&&!row.route.waf.route_specific?{...row,route:{...row.route,waf:structuredClone(route.waf)}}:row)
}

export function proxyCutoverGroupRequest(draft:ProxyCutoverGroupDraft,available:ProxyCutoverTargets){
  const required=proxyCutoverGroupTargets(available,draft.serviceID),pairs=new Map(required.map(row=>[`${row.component}:${row.upstream_port}`,row]))
  const seen=new Set<string>(),ports=new Set<number>(),routes:ProxyRouteInput[]=[],targets:ProxyCutoverSelection[]=[]
  let sharedWaf:string|undefined
  for(const row of draft.targets){
    const key=`${row.target.component}:${row.target.upstream_port}`,approved=pairs.get(key)
    if(!approved||seen.has(key)||row.target.service_id!==draft.serviceID||JSON.stringify(approved.original_bindings)!==JSON.stringify(row.target.original_bindings))throw new Error('Черновик не совпадает с полным подтверждённым набором публикаций сервиса.')
    seen.add(key)
    if(!Number.isInteger(row.privatePort)||row.privatePort<available.backend_port_min||row.privatePort>available.backend_port_max||ports.has(row.privatePort))throw new Error('Каждому порту компонента нужен уникальный backend-порт из разрешённого диапазона.')
    ports.add(row.privatePort)
    for(const listener of Object.keys(row.hosts))if(!approved.original_bindings.includes(listener))throw new Error('Host задан для неподтверждённого listener.')
    const built=proxyCutoverRoutes(approved,row.route,row.routeIDBase,row.hosts)
    if(row.route.protocol!=='http1'&&(!row.route.tls?.certificate_id||built.some(route=>!route.host?.trim())))throw new Error('Для каждого HTTPS listener нужны точный Host и сертификат.')
    if(!row.route.waf.route_specific){const serialized=JSON.stringify(canonical({...row.route.waf,mode:'observe_only'}));if(sharedWaf!==undefined&&sharedWaf!==serialized)throw new Error('Маршруты с общим IP-лимитом сервиса должны использовать одну политику WAF.');sharedWaf=serialized}
    routes.push(...built);targets.push({component:approved.component,upstream_port:approved.upstream_port,private_port:row.privatePort})
  }
  if(seen.size!==pairs.size)throw new Error('Нельзя пропустить компонент или TCP-порт и оставить прямой обход proxy.')
  if(routes.length>(available.max_listeners||32)||new Set(routes.map(route=>route.listen)).size!==routes.length||new Set(routes.map(route=>route.id)).size!==routes.length)throw new Error('Набор маршрутов превышает лимит либо содержит повтор.')
  return {service_id:draft.serviceID,targets,routes}
}

export function proxyCutoverComponents(value:{components?:string[];component?:string;targets?:ProxyCutoverTargetPlan[]}):string[]{return value.components?.length?[...value.components]:value.targets?.length?[...new Set(value.targets.map(target=>target.component))]:value.component?[value.component]:[]}
export function proxyCutoverGroupEvidence(preview:Pick<ProxyCutoverPreview,'component'|'components'|'targets'|'missing_applications'|'containers'|'recovery_baseline'|'application_missing'>){
  const components=proxyCutoverComponents(preview),selected=new Set(components)
  const missing=preview.missing_applications??(preview.application_missing&&preview.component?[preview.component]:[]),missingSet=new Set(missing)
  const targetComponents=new Set((preview.targets||[]).map(target=>target.component))
  const plansMatch=!preview.targets?.length||(preview.targets.length<=16&&targetComponents.size===selected.size&&[...targetComponents].every(component=>selected.has(component)))
  const validSet=plansMatch&&components.length>0&&components.length<=8&&components.every(component=>/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(component))&&selected.size===components.length&&missingSet.size===missing.length&&missing.every(component=>selected.has(component))
  const items=components.map(component=>{
    const current=(preview.containers||[]).filter(container=>container.component===component),baseline=(preview.recovery_baseline||[]).filter(container=>container.component===component)
    const createMissing=missingSet.has(component)&&current.length===0&&baseline.length===1
    return {component,current,baseline,createMissing,canConfirm:current.length===1&&!missingSet.has(component)||createMissing}
  })
  return {components,items,other:(preview.containers||[]).filter(container=>!selected.has(container.component)),canConfirm:validSet&&items.every(item=>item.canConfirm)}
}

export type TrafficBody = {sensitive_raw?:boolean;data?:string;text?:string;encoding?:string;content_type?:string;content_encoding?:string;observed_bytes:number;captured_bytes:number;truncated:boolean;not_captured_reason?:string}
export type TrafficExchange = {request_id:string;sequence:number;collector_epoch:string;at:string;updated_at?:string;service_id:string;route_id:string;peer_ip?:string;client_ip:string;client_ip_source?:string;method:string;url:string;status:number;response_source?:string;duration_ms:number;request_bytes:number;response_bytes:number;waf_decision:string;waf_reason?:string;policy_revision?:number;state:'in_progress'|'completed'|'aborted';truncated?:boolean;dropped?:boolean;body_not_captured?:boolean;recorder_unavailable?:boolean;error?:string;upstream?:string;http_protocol?:string;request_trailers?:Record<string,string[]>;response_trailers?:Record<string,string[]>;request_headers?:Record<string,string[]>;response_headers?:Record<string,string[]>;request_body?:TrafficBody;response_body?:TrafficBody}
export type TrafficStatus = {available:boolean;epoch:string;started_at:string;counters_scope:string;previous_epoch_counters_unknown:boolean;counters:Record<string,number>;stored_records:number;stored_bytes:number;payload_budget_bytes:number;disk_bytes:number;quota_bytes:number;per_service_bytes:number;retention_seconds:number;max_records:number;retired_sequence:number;last_error?:string}
export type TrafficPage = {records:TrafficExchange[];next_cursor?:string;live_cursor:string;has_more:boolean;gap:boolean;epoch:string;counters:TrafficStatus}
export type TrafficFilters = {services:string[];route:string;from:string;until:string;ip:string;method:string;status:string;url:string;waf:string}

export function proxyRouteInput(route:ProxyRoute,targets:ProxyTarget[]):ProxyRouteInput{
  // The frozen upstream uses a published HOST port. The browser input selects
  // a registered CONTAINER port, so it must be resolved through approved targets.
  const target=targets.find(value=>value.service_id===route.service_id&&value.component===route.component&&value.upstream_address===route.upstream)
  return {id:route.id,service_id:route.service_id,component:route.component,listen:route.listen,host:route.host||'',upstream_port:target?.upstream_port||0,protocol:route.protocol,...(route.tls?{tls:{certificate_id:route.tls.certificate_id}}:{}),capture:{...route.capture,redact_headers:route.capture.redact_headers||[],redact_query_fields:route.capture.redact_query_fields||[],redact_body_fields:route.capture.redact_body_fields||[],body_patterns:route.capture.body_patterns||[]},waf:{...route.waf,exceptions:route.waf.exceptions||[]},trusted_proxy_cidrs:route.trusted_proxy_cidrs||[],limits:route.limits}
}

export type ProxyRouteChange = {id:string;kind:'added'|'removed'|'changed';before?:ProxyRoute;after?:ProxyRoute}
const canonical=(value:unknown):unknown=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).sort(([a],[b])=>a.localeCompare(b)).map(([key,child])=>[key,canonical(child)])):value
export function proxyRouteChanges(before:ProxyRoute[],after:ProxyRoute[]):ProxyRouteChange[]{
  const previous=new Map(before.map(route=>[route.id,route])),next=new Map(after.map(route=>[route.id,route])),changes:ProxyRouteChange[]=[]
  for(const id of [...new Set([...previous.keys(),...next.keys()])].sort()){
    const old=previous.get(id),updated=next.get(id)
    if(!old)changes.push({id,kind:'added',after:updated})
    else if(!updated)changes.push({id,kind:'removed',before:old})
    else if(JSON.stringify(canonical(old))!==JSON.stringify(canonical(updated)))changes.push({id,kind:'changed',before:old,after:updated})
  }
  return changes
}

export const wafLabels:Record<string,string>={off:'Отключён',observe_only:'Наблюдение',rate_limit:'Лимит запросов по IP',enforce:'Блокировка',allow:'Пропущен',allowed:'Пропущен',observe:'Превышение · наблюдение',would_block:'Был бы заблокирован',rate_limited:'Лимит запросов',banned:'Временный бан',deny:'Отклонён',blocked:'Отклонён',exempt:'Исключение checker',exception:'Исключение checker',not_evaluated:'WAF не применён',state_full:'Лимит IP-состояний',degraded:'Защита ограничена'}
export const wafLabel=(value:string)=>wafLabels[value]||value
export const wafReasonLabel=(value:string)=>({request_rate:'Превышен лимит запросов',rate_limit_cooldown:'Действует пятисекундная блокировка по лимиту запросов',request_rate_repeated:'Повторные превышения лимита запросов',active_ban:'Действует временный бан',autoban:'Временный автобан за повторные превышения',waf_state_unavailable:'Состояние WAF недоступно',ip_state_capacity:'Исчерпан бюджет IP-состояний',ban_state_capacity:'Исчерпан бюджет временных банов',checker_rate_exception:'Исключение checker из rate limit',unsupported_protocol:'Протокол не поддерживается этим HTTP-профилем',unsupported_request_profile:'Запрос не соответствует профилю HTTP/1.1',unknown_host:'Host не совпадает с маршрутом',invalid_forwarding_chain:'Не удалось проверить цепочку доверенных proxy',connection_capacity:'Достигнут лимит соединений',request_body_limit:'Превышен лимит передаваемого тела'} as Record<string,string>)[value]||value
export const captureReasonLabel=(value:string)=>({metadata_only:'Для маршрута включена запись только метаданных.',stream_read_error:'Передача тела прервана.',encoded_body_not_decoded:'Сжатое тело не декодируется этим профилем capture.',body_not_fully_observed:'Тело ещё не получено полностью.',truncated_body_redaction_not_complete:'Лимит захвата достигнут; полное редактирование тела невозможно, поэтому байты не сохранены.',unsupported_binary_redaction:'Этот бинарный формат не поддерживает безопасное редактирование.',unsupported_content_type:'Тип тела не поддерживается для безопасного захвата.',invalid_json_redaction:'JSON не удалось безопасно отредактировать.',json_depth_budget:'Превышена допустимая глубина JSON.',invalid_form_redaction:'Поля формы не удалось безопасно отредактировать.',redacted_representation_exceeds_budget:'Отредактированное тело превышает лимит захвата.',in_progress:'Передача продолжается; доступны промежуточные счётчики.',websocket_frames_not_captured:'Сохраняются handshake и счётчики WebSocket; кадры не захватываются.',content_metadata_budget:'Метаданные Content-Type или Content-Encoding превышают лимит.'} as Record<string,string>)[value]||value


export function trafficQuery(filters:TrafficFilters,cursor?:string,zone:'browser'|'UTC'='browser'){
  const query=new URLSearchParams({limit:'50'})
  for(const service of [...new Set(filters.services)].sort())query.append('service_id',service)
  for(const [key,value] of Object.entries({route_id:filters.route,ip:filters.ip,method:filters.method,status:filters.status,url:filters.url,waf:filters.waf}))if(value.trim())query.set(key,value.trim())
  for(const [key,value] of [['from',filters.from],['until',filters.until]])if(value){const date=new Date(zone==='UTC'?value+'Z':value);if(Number.isFinite(date.getTime()))query.set(key,date.toISOString())}
  if(cursor)query.set('cursor',cursor)
  return query.toString()
}

export function trafficBytes(body:TrafficBody):Uint8Array{
  if(body.text!==undefined||body.encoding==='utf8')return new TextEncoder().encode((body.text??body.data??'').slice(0,65536)).slice(0,65536)
  if(!body.data)return new Uint8Array()
  try{const raw=atob(body.data.slice(0,Math.ceil(65536/3)*4));return Uint8Array.from(raw.slice(0,65536),character=>character.charCodeAt(0))}catch{return new Uint8Array()}
}

export function trafficHex(value:Uint8Array){
  const result:string[]=[]
  for(let i=0;i<value.length;i+=16){const row=value.slice(i,i+16);result.push(`${i.toString(16).padStart(6,'0')}  ${Array.from(row,byte=>byte.toString(16).padStart(2,'0')).join(' ').padEnd(47,' ')}  ${Array.from(row,byte=>byte>=32&&byte<127?String.fromCharCode(byte):'.').join('')}`)}
  return result.join('\n')
}

export const proxyProtocolLabel=(value:ProxyProtocol)=>({http1:'HTTP · HTTP/1.1',https1:'HTTPS · HTTP/1.1',https2:'HTTPS · HTTP/2 / gRPC → h2c'}[value])
