// Packet metadata is deliberately separate from the sensitive frame bytes.
export type PacketCandidate = {service_id:string;component:string}
export type PacketMetadata = {sequence:number;packet_id:string;collector_epoch:string;policy_revision:number;at:string;service_id?:string;component?:string;interface:string;if_index:number;direction:string;protocol:string;source_ip:string;destination_ip:string;source_port:number;destination_port:number;tcp_flags:number;wire_length:number;captured_length:number;truncated:boolean;link_type:number;attribution:string;candidates?:PacketCandidate[];not_captured_reason?:string}
export type PacketRecord = PacketMetadata & {data?:string}
export type PacketStoreStatus = {available:boolean;epoch:string;started_at:string;counters_scope:string;previous_epoch_counters_unknown:boolean;counters:Record<string,number>;stored_records:number;stored_bytes:number;disk_bytes:number;quota_bytes:number;payload_budget_bytes:number;per_service_bytes:number;retention_seconds:number;max_records:number;retired_sequence:number;last_error?:string}
export type PacketPage = {records:PacketMetadata[];next_cursor?:string;live_cursor:string;has_more:boolean;gap:boolean;epoch:string;counters:PacketStoreStatus}
export type PacketFilters = {services:string[];component:string;protocol:string;ip:string;sourcePort:string;destinationPort:string;direction:string;from:string;until:string}
export type PacketQuery = {service_ids?:string[];component?:string;protocol?:string;ip?:string;source_port?:number;destination_port?:number;direction?:string;from?:string;until?:string;cursor?:string;limit:number}
export type PacketExportRequest = {query:PacketQuery;max_packets:number;max_bytes:number}
export type PacketEndpoint = {service_id:string;component:string;protocol:string;address:string;port:number}
export type PacketInterfacePolicy = {name:string;index:number;endpoints:PacketEndpoint[]}
export type PacketCapturePolicy = {schema_version:number;revision:number;enabled:boolean;lease_until?:string;snaplen:number;max_packets_per_second:number;interfaces:PacketInterfacePolicy[]}
export type PacketCaptureStatus = {available:boolean;enabled:boolean;running:boolean;paused:boolean;lease_until?:string;lease_expired:boolean;mode:string;epoch:string;started_at:string;revision:number;digest:string;snaplen:number;interfaces:PacketInterfacePolicy[];queue_depth:number;queue_capacity:number;counters:Record<string,number>;counters_scope:string;previous_epoch_counters_unknown:boolean;kernel_drops_known:boolean;deduplication:string;last_error?:string}
export type PacketStatus = {configured:boolean;capture?:PacketCaptureStatus;store?:PacketStoreStatus;error?:string}
export type PacketCaptureTarget = {id:string;service_id:string;service_name:string;component:string;protocol:'tcp'|'udp';target_port:number;interface:string;if_index:number;addresses:string[];point:'container_bridge'|'container_veth'|'host_publication';point_group?:string;observed_port?:number;release_id?:string;source_digest?:string}
export type PacketCaptureTargets = {targets:PacketCaptureTarget[];unavailable:{service_id:string;component:string;reason:string}[];allowed_interfaces:string[]}
export type PacketPolicyView = {configured:boolean;policy:PacketCapturePolicy;selected_target_ids:string[];desired_revision:number;applied_revision:number;activation:string;error?:string}
export type PacketCapturePreview = {proposal_id:string;digest:string;policy:PacketCapturePolicy;selected_target_ids:string[];warnings:string[];expires_at:string;previous_policy:PacketCapturePolicy;observed_applied_revision:number}

export function packetCaptureState(status:PacketStatus){
  if(!status.configured)return 'Компоненты захвата не настроены.'
  const capture=status.capture
  if(!capture?.available)return 'Collector недоступен.'
  if(capture.running)return 'Пассивный захват работает.'
  if(capture.paused)return 'Захват приостановлен до повторной проверки привязок.'
  if(capture.enabled&&capture.lease_expired)return 'Захват остановлен: срок подтверждения привязок истёк.'
  return capture.enabled?'Политика включена; работа захвата пока не подтверждена.':'Захват выключен.'
}

export function packetCaptureSelection(targets:PacketCaptureTargets,selected:string[]){
  const ids=new Set(selected),available=new Map(targets.targets.map(target=>[target.id,target]))
  if(ids.size!==selected.length)throw new Error('Цель захвата выбрана несколько раз.')
  if(selected.some(id=>!available.has(id)))throw new Error('Привязки целей изменились. Обновите доступные цели и подготовьте новый план.')
  const result=selected.map(id=>available.get(id)!)
  if(result.some(target=>!['container_bridge','container_veth','host_publication'].includes(target.point)||!targets.allowed_interfaces.includes(target.interface)))throw new Error('Цель не соответствует разрешённой точке захвата.')
  const groups=new Map<string,string>()
  for(const target of result){if(!target.point_group)continue;const previous=groups.get(target.point_group);if(previous&&(previous!=='host_publication'||target.point!=='host_publication'))throw new Error('Выберите одну точку наблюдения: bridge, veth или опубликованный порт.');groups.set(target.point_group,target.point)}
  return result
}
export const initialPacketFilters:PacketFilters={services:[],component:'',protocol:'',ip:'',sourcePort:'',destinationPort:'',direction:'',from:'',until:''}
export const maxPacketBytes=65535
export const maxPCAPBytes=8*1024*1024

function packetPort(value:string){
  if(!value.trim())return undefined
  if(!/^\d+$/.test(value.trim())||Number(value)<1||Number(value)>65535)throw new Error('Порт должен быть целым числом от 1 до 65535.')
  return Number(value)
}
function packetDate(value:string,zone:'browser'|'UTC'){
  if(!value)return undefined
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value))throw new Error('Укажите корректную дату и время.')
  const date=new Date(zone==='UTC'?value+'Z':value)
  if(!Number.isFinite(date.getTime()))throw new Error('Укажите корректную дату и время.')
  const expected=value.length===16?value+':00':value
  if(localPacketTime(date,zone)!==expected)throw new Error('Укажите существующую дату и время в выбранном часовом поясе.')
  return date.toISOString()
}
export function packetFilterQuery(filters:PacketFilters,cursor?:string,zone:'browser'|'UTC'='browser'):PacketQuery{
  const from=packetDate(filters.from,zone),until=packetDate(filters.until,zone)
  if(from&&until&&from>=until)throw new Error('Начало интервала должно быть раньше конца.')
  const sourcePort=packetPort(filters.sourcePort),destinationPort=packetPort(filters.destinationPort)
  return {limit:50,...(filters.services.length?{service_ids:[...new Set(filters.services)].sort()}:{}),...(filters.component.trim()?{component:filters.component.trim()}:{}),...(filters.protocol?{protocol:filters.protocol}:{}),...(filters.ip.trim()?{ip:filters.ip.trim()}:{}),...(sourcePort?{source_port:sourcePort}:{}),...(destinationPort?{destination_port:destinationPort}:{}),...(filters.direction?{direction:filters.direction}:{}),...(from?{from}:{}),...(until?{until}:{}),...(cursor?{cursor}:{})}
}
export function packetQueryString(query:PacketQuery){
  const params=new URLSearchParams({limit:String(query.limit)})
  for(const id of query.service_ids||[])params.append('service_id',id)
  for(const [key,value] of Object.entries(query))if(key!=='service_ids'&&key!=='limit'&&value!==undefined)params.set(key,String(value))
  return params.toString()
}
export function packetExportRequest(filters:PacketFilters,maxPackets:number,maxBytes:number,zone:'browser'|'UTC'='browser'):PacketExportRequest{
  const query=packetFilterQuery(filters,undefined,zone)
  if(!query.from||!query.until)throw new Error('Для PCAP укажите начало и конец интервала.')
  if(new Date(query.until).getTime()-new Date(query.from).getTime()>3600000)throw new Error('Один экспорт ограничен интервалом в 60 минут.')
  if(!Number.isInteger(maxPackets)||maxPackets<1||maxPackets>10000)throw new Error('Лимит экспорта: от 1 до 10 000 пакетов.')
  if(!Number.isInteger(maxBytes)||maxBytes<24||maxBytes>maxPCAPBytes)throw new Error('Лимит PCAP: от 24 байт до 8 MiB.')
  return {query,max_packets:maxPackets,max_bytes:maxBytes}
}
export function packetBytes(data?:string):Uint8Array{
  if(!data)return new Uint8Array()
  try{const raw=atob(data.slice(0,Math.ceil(maxPacketBytes/3)*4));return Uint8Array.from(raw.slice(0,maxPacketBytes),character=>character.charCodeAt(0))}catch{return new Uint8Array()}
}
export function packetHex(value:Uint8Array){
  const lines:string[]=[]
  for(let offset=0;offset<Math.min(value.length,maxPacketBytes);offset+=16){const row=value.subarray(offset,Math.min(offset+16,maxPacketBytes));lines.push(`${offset.toString(16).padStart(6,'0')}  ${Array.from(row,byte=>byte.toString(16).padStart(2,'0')).join(' ').padEnd(47,' ')}  ${Array.from(row,byte=>byte>=32&&byte<=126?String.fromCharCode(byte):'.').join('')}`)}
  return lines.join('\n')
}
export function packetFlags(value:number){return [[0x02,'SYN'],[0x10,'ACK'],[0x01,'FIN'],[0x04,'RST'],[0x08,'PSH'],[0x20,'URG'],[0x40,'ECE'],[0x80,'CWR']].filter(([mask])=>(value&Number(mask))!==0).map(([,label])=>label).join(' · ')||'—'}
export function packetAddress(ip:string,port:number){return `${ip.includes(':')?'['+ip+']':ip}:${port}`}
export function packetDirection(value:string){return ({ingress:'К сервису',egress:'От сервиса',ambiguous:'Неоднозначно (оба конца выбраны)'} as Record<string,string>)[value]||value||'—'}
export function packetReason(value?:string){return ({metadata_only:'Политика сохраняет только метаданные.',snaplen_zero:'Политика сохраняет только метаданные.',payload_not_retained:'Байты пакета не сохранены.',quota:'Байты не сохранены из-за квоты.'} as Record<string,string>)[value||'']||value||'Байты пакета не сохранены.'}
export function localPacketTime(date:Date,zone:'browser'|'UTC'){
  const adjusted=zone==='UTC'?date:new Date(date.getTime()-date.getTimezoneOffset()*60000)
  return adjusted.toISOString().slice(0,19)
}
