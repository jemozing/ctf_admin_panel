export type Role = 'admin' | 'defender' | 'viewer'
export type User = {id:string;username:string;role:Role;disabled:boolean;sensitive_access:boolean;created_at:string}
export type Session = {user:User;csrf_token:string;expires_at:string}
export type ManagedPath = {path:string;kind:string;exclusions?:string[]}
export type DataPath = {name:string;kind:string;source:string;target:string;component:string;significant:boolean;loss_accepted?:boolean;allow_code_updates?:boolean;shared_resource?:string}
export type Service = {id:string;name:string;description?:string;compose_project:string;project_directory:string;source_directory:string;targets:string[];policy_revision:number;managed_paths:ManagedPath[];data_paths?:DataPath[];containers:{component:string;role:string;id?:string;image_id?:string}[]}
export type RegistrationService = Service & {schema_version:number;compose_files:string[];profiles?:string[];file_map_revision:number}
export type RegistrationOptions = {discovery_roots:string[];workspace_roots:string[]}
export type RegistrationBrowseRequest = {directory:string}
export type RegistrationDirectoryEntry = {name:string;path:string}
export type RegistrationDirectoryListing = {directory:string;parent?:string;directories:RegistrationDirectoryEntry[];compose_files:string[];truncated:boolean}
export type RegistrationInspection = {service:RegistrationService;warnings:string[]}
export type RegistrationManagedPathsRequest = {service_id:string;code_bindings:string[]}
export type RegistrationManagedPathsResult = {managed_paths:ManagedPath[]}
export type RegistrationProposal = {id:string;digest:string;service:RegistrationService;configuration_digest:string;actor:string;created_at:string}
export type RegistrationApproval = {service:Service;initialized:boolean;initialization_error?:string;operation?:Operation}
export type GitSource = {configured:boolean;url?:string;ref?:string;subdirectory?:string;username?:string;has_credentials:boolean;revision:number;last_fetch?:{commit:string;snapshot_id:string;at:string}}
export type GitSourceInput = {url:string;ref:string;subdirectory?:string;username?:string;token?:string;clear_credentials?:boolean}
export type GitProbeResult = {branches:{name:string;ref:string;commit:string}[];default_branch?:string;selected_ref:string;resolved_commit?:string;ref_status:'available'|'missing'|'unverified'|'ambiguous';truncated:boolean;checked_at:string}
export type GitDirectoryListing = {directory:string;parent?:string;directories:{name:string;path:string}[];truncated:boolean}
export type Container = {id:string;name:string;component:string;image_id:string;state:string;health:string;ports:string[]}
export type GitProvenance = {url:string;ref:string;subdirectory?:string;commit:string;source_revision:number}
export type Release = {id:string;service_id:string;created_at:string;author:string;source:string;git_source?:GitProvenance;snapshot_id:string;tree_digest:string;policy_revision:number;images:{component:string;image_id:string;retention_tag:string}[]}
export type Snapshot = {id:string;purpose:string;created_at:string;git_source?:GitProvenance;tree_digest:string;bytes:number}
export type Drift = {state:'unknown'|'changed'|'unchanged'|'unverified';reason?:string;expected_digest?:string;current_digest?:string;at:string}
export type ComponentVersion = {component:string;container_id?:string;image_id?:string;recorded_image_id?:string;recorded_release_id?:string;state:string;observed_release_id?:string;possible_release_ids:string[];release_evidence?:string;ambiguity_reason?:string}
export type HealthSignal = {source:string;state:string;reason?:string;observed_at?:string;valid_until?:string}
export type Details = {service:Service;containers:Container[];current_release_id?:string;candidate_id?:string;releases:Release[];snapshots:Snapshot[];capabilities:Record<string,boolean>;observed_state:string;health:HealthSignal[];drift?:Drift;component_versions?:ComponentVersion[]}
export type Action = 'fetch_source'|'prepare'|'prepare_compose'|'build'|'deploy'|'snapshot'|'restore_snapshot'|'rollback'|'start'|'stop'|'restart'|'recover'
export type Operation = {spec:{id:string;service_id:string;kind:Action;initiator:string;release_id?:string;snapshot_id?:string};state:string;stage:string;created_at:string;updated_at:string;outcome:{reason?:string};recovery_point_id?:string;cancel_requested?:boolean;mutation_started?:boolean;queue_wait?:{reason:string;blockers:{resource:string;operation_id:string;actor:string}[];lane?:string;limit?:number}}
export type OperationEvent = {sequence:number;at:string;kind:string;message:string}
export type Submit = {service_id:string;action:Action;idempotency_key:string;candidate_id?:string;snapshot_id?:string;release_id?:string;recovery_operation_id?:string;plan_digest?:string;confirm_data_compatibility?:boolean;accept_file_drift?:boolean;compose_from_git?:boolean;confirm_compose_change?:boolean}
export type ComposeChange = {component:string;setting:string;before:string;after:string}
export type Preview = {space?:{estimate_known:boolean;snapshot_bytes:number;staging_bytes:number;apply_temporary_bytes:number;docker_reserve_bytes:number;minimum_free_bytes:number;minimum_free_inodes:number;state_available_bytes:number|null;state_available_inodes:number|null};snapshot_id?:string;active_file_drift?:boolean;accepted_file_drift?:boolean;drift_changed_files?:{path:string;change:string}[];health_check_revision?:number;health_settings?:{warmup_seconds:number;overall_timeout_seconds:number;attempts:number;retry_interval_seconds:number;validity_seconds:number};check_summaries?:{id:string;source:string;kind:string;targets:string[];timeout_seconds:number}[];service_id:string;action:Action;git_source?:GitSource;active_release_id?:string;candidate_id?:string;target_release_id?:string;recovery_operation_id?:string;targets:string[];changed_files:{path:string;change:string}[];plan_digest:string;policy_revision:number;current_tree_digest:string;data_compatibility_required:boolean;has_rollback:boolean;images?:{component:string;image_id:string}[];compose_change?:boolean;compose_changes?:ComposeChange[]}
export type LogResult = {content:string;truncated:boolean}
export type LogRecord = {id:string;at?:string;component:string;container_id:string;stream:string;text:string;truncated?:boolean}
export type LogPage = {at:string;records:LogRecord[];sources:{component:string;container_id?:string;driver?:string;error?:string;tty?:boolean}[];truncated:boolean;limit:number}
export type FileEntry = {path:string;type:string;size:number;digest?:string;mode:number;uid:number;gid:number}
export type FileDifference = {path:string;change:string;before?:FileEntry;after?:FileEntry}
export type FilesResult = {comparison:string;before_digest:string;after_digest:string;snapshot_id?:string;changes:FileDifference[];truncated:boolean;at:string;file?:{path:string;before:string|null;after:string|null;before_reason?:string;after_reason?:string}}
export type ReleaseEvidence = {release_id:string;at:string;active:boolean;can_apply:boolean;data_confirmation_required:boolean;checks:Record<string,string>;reasons:string[];runs:{operation_id:string;action:Action;state:string;at:string;reason?:string}[];local_checks:{at:string;signals:HealthSignal[]}[];manual_confirmations:{at:string;actor:string;comment:string;state:string;valid_until:string}[]}
export type DiagnosticChunk = {sequence:number;at:string;stage:string;content:string}
export type DiagnosticLog = {chunks:DiagnosticChunk[];bytes:number;returned_bytes:number;next_sequence:number;has_more:boolean;dropped_bytes:number;truncated:boolean}
export type ContainerMetrics = {component:string;container_id?:string;state:string;observed_at?:string;cpu_percent:number|null;cpu_limit_percent:number|null;memory_usage_bytes:number|null;memory_limit_bytes:number|null;network_rx_bytes:number|null;network_tx_bytes:number|null;block_read_bytes:number|null;block_write_bytes:number|null;pids_current:number|null;pids_limit:number|null;restart_count:number|null;oom_killed:boolean|null;error?:string}
export type MetricsSample = {at:string;containers:ContainerMetrics[]}
export type Metrics = {service_id:string;available:boolean;stale:boolean;latest:MetricsSample;history:MetricsSample[];interval_seconds:number;retention_seconds:number;history_component:string;available_components:string[];history_reset_at?:string;history_storage:'memory'}
export type HostFilesystemMetrics = {name:string;source:string;available_bytes:number|null;total_bytes:number|null;available_inodes:number|null;total_inodes:number|null;error?:string}
export type HostMetricsSample = {at:string;source:'approved_host_proc_files'|'unconfigured';scope:'docker_engine_host'|'executor_mounts'|'local_executor';core_count:number|null;cpu_percent:number|null;memory_total_bytes:number|null;memory_available_bytes:number|null;memory_used_bytes:number|null;swap_total_bytes:number|null;swap_used_bytes:number|null;load_average_1:number|null;load_average_5:number|null;load_average_15:number|null;uptime_seconds:number|null;network_rx_bytes:number|null;network_tx_bytes:number|null;network_interfaces?:{name:string;rx_bytes:number;tx_bytes:number}[];filesystems:HostFilesystemMetrics[];errors?:Record<string,string>}
export type HostMetrics = {available:boolean;stale:boolean;latest:HostMetricsSample;history:HostMetricsSample[];interval_seconds:number;retention_seconds:number;history_reset_at?:string;history_storage:'memory'}
export type Audit = {id:number;at:string;actor:string;action:string;target:string;result:string;operation_id?:string}

let csrf = ''
export function setCSRF(value:string){csrf=value}
export class APIError extends Error {constructor(public status:number, public code:string,message:string){super(message)}}
export async function api<T>(url:string,init:RequestInit={}):Promise<T>{
  const headers = new Headers(init.headers)
  if (init.body) headers.set('Content-Type','application/json')
  if (init.method && !['GET','HEAD'].includes(init.method)) headers.set('X-CSRF-Token',csrf)
  const response=await fetch(url,{...init,headers,credentials:'same-origin',cache:'no-store'})
  const data=await response.json()
  if(!response.ok){if(response.status===401&&url!='/api/auth/login'&&url!='/api/auth/session')window.dispatchEvent(new Event('auth-expired'));throw new APIError(response.status,data.code,data.message||'Ошибка запроса')}
  return data as T
}
export function post<T>(url:string,body:unknown){return api<T>(url,{method:'POST',body:JSON.stringify(body)})}
export async function postBlob(url:string,body:unknown,options:{signal?:AbortSignal}={}):Promise<{blob:Blob;headers:Headers}>{
  const response=await fetch(url,{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},credentials:'same-origin',cache:'no-store',signal:options.signal})
  if(!response.ok){
    if(response.status===401)window.dispatchEvent(new Event('auth-expired'))
    const reader=response.body?.getReader();const chunks:Uint8Array[]=[];let total=0;let data:{code?:string;message?:string}={}
    try{if(reader){while(true){const item=await reader.read();if(item.done)break;total+=item.value.byteLength;if(total>65536){await reader.cancel();break}chunks.push(item.value)}if(total<=65536){const raw=new Uint8Array(total);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length}data=JSON.parse(new TextDecoder().decode(raw))||{}}}}catch{}finally{reader?.releaseLock()}
    throw new APIError(response.status,data.code||'export_failed',data.message||'Ошибка экспорта')
  }
  const length=Number(response.headers.get('Content-Length'))
  if(Number.isFinite(length)&&length>8*1024*1024){await response.body?.cancel();throw new APIError(502,'export_too_large','Ответ превысил лимит экспорта')}
  const reader=response.body?.getReader();if(!reader)throw new APIError(502,'empty_export','Пустой ответ экспорта')
  const chunks:Uint8Array<ArrayBuffer>[]=[];let total=0
  try{while(true){const item=await reader.read();if(item.done)break;total+=item.value.byteLength;if(total>8*1024*1024){await reader.cancel();throw new APIError(502,'export_too_large','Ответ превысил лимит экспорта')}chunks.push(new Uint8Array(item.value))}}finally{reader.releaseLock()}
  return {blob:new Blob(chunks,{type:'application/vnd.tcpdump.pcap'}),headers:response.headers}
}
export const labels:Record<string,string> = {
  admin:'Admin',defender:'Defender',viewer:'Viewer',
  fetch_source:'Получить из Git',prepare:'Подготовить',prepare_compose:'Подготовка Compose',build:'Собрать',deploy:'Применить',snapshot:'Снимок файлов',restore_snapshot:'Создать кандидат из снимка',rollback:'Откатить',start:'Запустить',stop:'Остановить',restart:'Перезапустить',recover:'Восстановление',
  queued:'В очереди',running:'Выполняется',succeeded:'Успешно',failed:'Ошибка',cancelled:'Отменена',interrupted:'Прервана',requires_recovery:'Требуется восстановление',
  validation:'Проверка',copying:'Копирование',building:'Сборка',recovery_point:'Точка возврата',switching:'Переключение',warmup:'Прогрев',functional_check:'Проверка сервиса',recording:'Сохранение результата',reconciliation:'Сверка состояния',
  container:'Контейнеры',docker_healthcheck:'Docker healthcheck',readiness:'Готовность',local_functional:'Функциональная проверка',external_checker:'Checker организаторов',manual:'Ручная проверка',
  healthy:'Пройдена',unhealthy:'Ошибка',unknown:'Неизвестно',not_configured:'Не настроена',stale:'Устарела',
  baseline:'Baseline',candidate_source:'Кандидат',recovery:'Точка возврата',manual_snapshot:'Ручной снимок',complete:'Готов',resource_locked:'Ожидание занятого ресурса',lane_limit:'Достигнут лимит параллельных операций',scheduler:'Ожидает планировщик',
}
export const label=(value:string)=>labels[value]||value
export type DisplayTimeZone = 'browser'|'UTC'
let displayTimeZone:DisplayTimeZone='browser'
try{if(typeof localStorage!=='undefined'&&localStorage.getItem('ctfm.timezone')==='UTC')displayTimeZone='UTC'}catch{}
export const getDisplayTimeZone=()=>displayTimeZone
export function setDisplayTimeZone(value:DisplayTimeZone){displayTimeZone=value;try{localStorage.setItem('ctfm.timezone',value)}catch{}}
export const time=(value:string)=>{const date=new Date(value);return !Number.isFinite(date.getTime())||date.getUTCFullYear()<1970?'—':date.toLocaleString('ru-RU',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',...(displayTimeZone==='UTC'?{timeZone:'UTC'}:{})})}
export const short=(value?:string)=>value?value.replace('sha256:','').slice(0,12):'—'
export function bytes(n:number){if(!Number.isFinite(n)||n<0)return '—';const units=['B','KiB','MiB','GiB','TiB','PiB'];let value=n,index=0;while(value>=1024&&index<units.length-1){value/=1024;index++}return `${index?value.toFixed(1):value} ${units[index]}`}
