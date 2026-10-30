import {useCallback,useEffect,useState} from 'react'
import type {FormEvent} from 'react'
import {api,label,post,time} from './api'
import type {Role} from './api'
import {Badge,Button,Notice} from './ui'

type Settings={warmup_seconds:number;overall_timeout_seconds:number;attempts:number;retry_interval_seconds:number;validity_seconds:number}
type Manual={id:string;release_id:string;actor:string;comment:string;observed_at:string;valid_until:string;state:string}
type CheckSummary={id:string;kind:string;source:string;targets:string[];steps:number;cleanup_steps:number;timeout_seconds:number}
type View={warning?:string;revision:number;service_policy_revision:number;settings:Settings;checks:CheckSummary[];current_release_id?:string;state_sequence:number;runtime_digest:string;manual_confirmations:Manual[]}
const defaults:Settings={warmup_seconds:45,overall_timeout_seconds:60,attempts:1,retry_interval_seconds:1,validity_seconds:30}
const examples:Record<string,unknown[]>={
 http:[{id:'ready',source:'readiness',kind:'http',url:'http://service:8080/health',expected_status:200,body_contains:'ok',timeout_seconds:3}],
 tcp:[{id:'tcp-ready',source:'readiness',kind:'tcp',address:'service:8080',timeout_seconds:3}],
 http_sequence:[{id:'functional',source:'local_functional',kind:'http_sequence',timeout_seconds:3,steps:[{method:'GET',url:'http://service:8080/status',expected_status:200,body_contains:'expected test data'}]}],
}
const errorText=(error:unknown)=>error instanceof Error?error.message:'Не удалось выполнить запрос'

export default function HealthChecks({serviceID,role,canConfirm,onUpdated}:{serviceID:string;role:Role;canConfirm:boolean;onUpdated?:()=>void}){
 const [view,setView]=useState<View|null>(null),[settings,setSettings]=useState<Settings>(defaults),[checks,setChecks]=useState(''),[confirmed,setConfirmed]=useState(false)
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[message,setMessage]=useState(''),[healthy,setHealthy]=useState('healthy'),[comment,setComment]=useState(''),[ttl,setTTL]=useState(300)
 const refresh=useCallback(async()=>{const value=await api<View>(`/api/services/${serviceID}/checks`);setView(value);setSettings(value.settings)},[serviceID])
 useEffect(()=>{setView(null);setChecks('');setConfirmed(false);setError('');setMessage('');void refresh().catch(error=>setError(errorText(error)))},[refresh])
 const configure=async(event:FormEvent)=>{event.preventDefault();if(!view)return;setBusy(true);setError('');setMessage('');try{
  const parsed:unknown=JSON.parse(checks);if(!Array.isArray(parsed))throw new Error('Укажите массив проверок; [] отключает локальные проверки.')
  const value=await post<View>(`/api/services/${serviceID}/checks`,{expected_revision:view.revision,confirmed,policy:{...settings,checks:parsed}})
  setView(value);setSettings(value.settings);setChecks('');setConfirmed(false);setMessage('Политика проверок сохранена. Она применяется при следующем запуске, перезапуске или переключении релиза.');onUpdated?.()
 }catch(error){setError(errorText(error))}finally{setBusy(false)}}
 const confirm=async(event:FormEvent)=>{event.preventDefault();if(!view?.current_release_id)return;setBusy(true);setError('');setMessage('');try{
  await post(`/api/services/${serviceID}/checks/manual`,{expected_release_id:view.current_release_id,expected_state_sequence:view.state_sequence,expected_runtime_digest:view.runtime_digest,ttl_seconds:ttl,healthy:healthy==='healthy',comment})
  setComment('');await refresh();setMessage('Результат ручной проверки сохранён с автором, временем и сроком актуальности.');onUpdated?.()
 }catch(error){setError(errorText(error));void refresh().catch(()=>{})}finally{setBusy(false)}}
 return <div className="panel"><div className="panel-heading"><div><h2>Проверки работоспособности</h2><p>Готовность, функциональный сценарий и ручное подтверждение сохраняются отдельно от Docker healthcheck и checker организаторов.</p></div><Button variant="outline" disabled={busy} onClick={()=>void refresh().catch(error=>setError(errorText(error)))}>Обновить</Button></div>
 {error&&<Notice variant="error">{error}</Notice>}{message&&<Notice>{message}</Notice>}
 <Notice>Проверки выполняются из сети executor. Адрес 127.0.0.1 относится к executor; используйте подтверждённый доступный адрес сервиса. Ответы, заголовки и тела запросов не публикуются. Переходы HTTP на другой адрес не выполняются.</Notice>
 {view&&<>{view.warning&&<Notice variant="warning">{view.warning}</Notice>}<p className="muted">Ревизия проверок {view.revision} · политика сервиса {view.service_policy_revision}. Прогрев до {view.settings.warmup_seconds} с; общий срок проверок {view.settings.overall_timeout_seconds} с; попыток {view.settings.attempts}.</p>
 <div className="table-wrap"><table><thead><tr><th>Проверка</th><th>Тип / назначение</th><th>Подтверждённые адреса</th><th>Шаги / timeout</th></tr></thead><tbody>{view.checks.map(check=><tr key={check.id}><td>{check.id}</td><td>{check.kind} · {label(check.source)}</td><td>{check.targets.join(', ')}</td><td>{check.steps} + {check.cleanup_steps} cleanup · {check.timeout_seconds} с</td></tr>)}</tbody></table>{view.checks.length===0&&<p className="muted">Локальные автоматические проверки не настроены.</p>}</div>
 {role==='admin'&&<form onSubmit={event=>void configure(event)}><h3>Заменить политику проверок</h3><p className="muted">Сохранённые адреса с параметрами, ожидания ответа, заголовки и тела запросов доступны только executor. Для изменения задайте полный новый набор; пустой массив отключает проверки.</p>
 <div className="toolbar-secondary">{Object.keys(examples).map(kind=><Button key={kind} type="button" variant="outline" disabled={busy} onClick={()=>setChecks(JSON.stringify(examples[kind],null,2))}>{kind==='http'?'Пример HTTP':kind==='tcp'?'Пример TCP':'Пример HTTP-сценария'}</Button>)}<Button type="button" variant="ghost" disabled={busy} onClick={()=>setChecks('[]')}>Отключить проверки</Button></div>
 <label>Полный набор типизированных проверок<textarea aria-label="Полный набор типизированных проверок" rows={14} required value={checks} onChange={event=>setChecks(event.target.value)} autoComplete="off" spellCheck={false}/></label>
 <p className="muted">HTTP-сценарий: до 8 steps и 4 cleanup_steps на одном адресе, с cookies между запросами. Для POST/PUT/PATCH/DELETE укажите side_effects_reviewed: true и cleanup_description с процедурой удаления только тестовых данных. Не используйте игровые флаги. Каждый шаг принимает method, url, expected_status, необязательные headers, body и body_contains.</p>
 <div className="preview-facts">{([['warmup_seconds','Прогрев, с',300],['overall_timeout_seconds','Общий срок проверок, с',300],['attempts','Попытки',10],['retry_interval_seconds','Интервал попыток, с',30],['validity_seconds','Актуальность результата, с',3600]] as const).map(([key,name,max])=><label key={key}>{name}<input type="number" min={1} max={max} required value={settings[key]} onChange={event=>setSettings(value=>({...value,[key]:Number(event.target.value)}))}/></label>)}</div>
 <label className="checkbox-label"><input type="checkbox" checked={confirmed} onChange={event=>setConfirmed(event.target.checked)}/><span>Подтверждаю адреса из сети executor, безопасные тестовые данные и процедуру очистки. Новый набор заменит текущие проверки целиком.</span></label><Button type="submit" busy={busy} disabled={!confirmed||!checks}>Сохранить проверки</Button></form>}
 <h3>Ручная проверка</h3><p className="muted">Подтверждение относится к текущему релизу и экземплярам контейнеров. После переключения, перезапуска или окончания срока оно устаревает. Оно не заменяет функциональный тест и не объявляет релиз автоматически проверенным.</p>
 {canConfirm&&<form onSubmit={event=>void confirm(event)}><label>Результат<select value={healthy} onChange={event=>setHealthy(event.target.value)}><option value="healthy">Проверка пройдена</option><option value="unhealthy">Проверка не пройдена</option></select></label><label>Комментарий без паролей и игровых секретов<textarea rows={3} minLength={3} maxLength={1024} required value={comment} onChange={event=>setComment(event.target.value)}/></label><label>Срок актуальности, с<input type="number" min={1} max={3600} required value={ttl} onChange={event=>setTTL(Number(event.target.value))}/></label><Button type="submit" busy={busy} disabled={!view.current_release_id}>Сохранить ручную проверку</Button></form>}
 <div className="table-wrap"><table><thead><tr><th>Время / срок</th><th>Результат</th><th>Автор / релиз</th><th>Комментарий</th></tr></thead><tbody>{view.manual_confirmations.map(value=><tr key={value.id}><td>{time(value.observed_at)}<small>До {time(value.valid_until)}</small></td><td><Badge tone={value.state==='healthy'?'good':value.state==='unhealthy'?'bad':'warn'}>{label(value.state)}</Badge></td><td>{value.actor}<small>{value.release_id}</small></td><td>{value.comment}</td></tr>)}</tbody></table>{view.manual_confirmations.length===0&&<p className="muted">Ручных подтверждений пока нет.</p>}</div>
 </>}
 </div>
}
