import {useEffect,useState} from 'react'
import {Activity,Boxes,Clock3,Cpu,HardDrive,MemoryStick,Network,Server} from 'lucide-react'
import {api,bytes,short,time} from './api'
import type {HostMetrics,Metrics} from './api'
import {duration,historyWindow,metricSegments,networkRates} from './metricHistory'
import type {MetricPoint} from './metricHistory'
import {Badge,Empty,Notice} from './ui'

type RangeMinutes = 15|60
const measurement=(value:number|null|undefined,format:(value:number)=>string)=>value===null||value===undefined||!Number.isFinite(value)?'—':format(value)
const percent=(value:number)=>`${value.toFixed(1)}%`
const count=(value:number)=>value.toLocaleString('ru-RU')

function useMetrics<T>(url:string){
  const [value,setValue]=useState<T|null>(null),[error,setError]=useState('')
  useEffect(()=>{
    let active=true,timer:ReturnType<typeof setTimeout>|undefined
    const controller=new AbortController()
    setValue(null);setError('')
    const refresh=async()=>{
      try{const result=await api<T>(url,{signal:controller.signal});if(active){setValue(result);setError('')}}catch(error){if(active)setError(error instanceof Error?error.message:'Метрики недоступны')}
      finally{if(active)timer=setTimeout(()=>void refresh(),5000)}
    }
    void refresh()
    return()=>{active=false;clearTimeout(timer);controller.abort()}
  },[url])
  return {value,error}
}

function MetricsToolbar({minutes,onChange}:{minutes:RangeMinutes;onChange:(minutes:RangeMinutes)=>void}){
  return <div className="metrics-toolbar"><p>Измерения обновляются автоматически каждые 5 с.</p><label>История<select aria-label="Период истории метрик" value={minutes} onChange={event=>onChange(Number(event.target.value) as RangeMinutes)}><option value={15}>15 минут</option><option value={60}>60 минут</option></select></label></div>
}

export function HostMetricsView(){
  const [minutes,setMinutes]=useState<RangeMinutes>(15)
  return <div className="metrics-view"><MetricsToolbar minutes={minutes} onChange={setMinutes}/><HostMetricsSection minutes={minutes}/></div>
}

export default function MetricsView({serviceID}:{serviceID:string}){
  const [minutes,setMinutes]=useState<RangeMinutes>(15)
  return <div className="metrics-view"><MetricsToolbar minutes={minutes} onChange={setMinutes}/><HostMetricsSection minutes={minutes}/><ContainerMetricsSection key={serviceID} serviceID={serviceID} minutes={minutes}/><RuntimeEvents serviceID={serviceID}/></div>
}

type RuntimeEventHistory={events:{sequence:number;container_id:string;component:string;kind:string;at:string;observed_at:string}[];connected:boolean;connected_at?:string;error?:string;retained_global:number;returned_limit:number}
function RuntimeEvents({serviceID}:{serviceID:string}){
  const {value,error}=useMetrics<RuntimeEventHistory>(`/api/services/${encodeURIComponent(serviceID)}/runtime-events`)
  const names:Record<string,string>={oom:'OOM',restart:'Перезапуск',die:'Завершение',start:'Запуск',destroy:'Удаление контейнера'}
  return <section className="panel metrics-component"><div className="panel-heading"><h2>События контейнеров</h2><Badge tone={value?.connected?'good':'warn'}>{value?.connected?'Сбор подключён':'Сбор недоступен'}</Badge></div>
    {(error||value?.error)&&<Notice variant="warning">{error||value?.error}</Notice>}
    <p className="muted">Журнал хранится в SQLite и сохраняется при перезапуске executor. Последние {value?.returned_limit||200} событий сервиса, общий лимит {value?.retained_global||10000}. Во время отключения возможны пропуски: буфер Docker ограничен. Событие «Запуск» само по себе не подтверждает автоматический перезапуск.</p>
    {value?.events.length?<div className="table-wrap"><table><thead><tr><th>Время</th><th>Событие</th><th>Компонент / контейнер</th></tr></thead><tbody>{value.events.map(event=><tr key={event.sequence}><td title={`${event.at} · получено ${event.observed_at}`}>{time(event.at)}</td><td><Badge tone={event.kind==='oom'?'bad':'neutral'}>{names[event.kind]||event.kind}</Badge></td><td>{event.component}<small><code>{short(event.container_id)}</code></small></td></tr>)}</tbody></table></div>:<Empty>События ещё не записаны.</Empty>}
  </section>
}

function HostMetricsSection({minutes}:{minutes:RangeMinutes}){
  const {value,error}=useMetrics<HostMetrics>('/api/metrics/host')
  const latest=value?.latest,now=Date.now(),history=historyWindow(value?.history||[],minutes,now)
  const points=(field:'cpu_percent'|'memory_used_bytes'):MetricPoint[]=>history.map(sample=>({at:sample.at,value:sample[field],identity:sample.source}))
  const unavailable=!latest||latest.source==='unconfigured'
  return <section className="panel metrics-component host-metrics"><div className="panel-heading"><div><h2><Server size={16}/>Ресурсы хоста</h2><p>{latest?.scope==='docker_engine_host'?'Машина Docker Engine · при виртуализации — Linux VM.':latest?.scope==='local_executor'?'Доступные ресурсы локальной машины executor.':'Файловые системы подтверждённых каталогов executor.'}</p></div><div className="metric-observed"><Badge tone={error||value?.stale?'warn':value?.available?'good':'neutral'}>{error?'Нет связи':value?.stale?'Устарело':value?.available?'Измерено':'Нет данных'}</Badge><span>{latest?.at&&Date.parse(latest.at)>0?time(latest.at):'Ожидаем измерения'}</span></div></div>
    {error&&<Notice variant="error">{error}</Notice>}
    {value?.stale&&<Notice variant="warning">Актуальные измерения хоста недоступны. Последние полученные значения показаны со временем наблюдения.</Notice>}
    {unavailable?<div className="metrics-empty"><Empty icon={<Server/>}>{value?'Системные источники не подключены. Сбор настраивает администратор хоста.':'Получаем метрики хоста…'}</Empty></div>:<>
      <div className={`metrics-cards host-metrics-cards ${error||value?.stale?'measurements-stale':''}`}>
        <div><span><Cpu size={15}/>CPU</span><strong>{measurement(latest.cpu_percent,percent)}</strong><small>{latest.cpu_percent===null?'Нужны два последовательных измерения':`100% — все ядра (${measurement(latest.core_count,count)})`}</small></div>
        <div><span><MemoryStick size={15}/>Память</span><strong>{measurement(latest.memory_used_bytes,bytes)}</strong><small>Всего {measurement(latest.memory_total_bytes,bytes)} · доступно {measurement(latest.memory_available_bytes,bytes)}</small><small>Swap {measurement(latest.swap_used_bytes,bytes)} / {measurement(latest.swap_total_bytes,bytes)}</small></div>
        <div><span><Activity size={15}/>Средняя нагрузка</span><strong className="load-value">{[latest.load_average_1,latest.load_average_5,latest.load_average_15].map((number,index)=><span key={index}>{measurement(number,number=>number.toFixed(2))}</span>)}</strong><small>За 1 / 5 / 15 минут · число задач</small></div>
        <div><span><Clock3 size={15}/>Время работы</span><strong className="uptime-value">{duration(latest.uptime_seconds)}</strong><small>С момента запуска хоста Docker Engine</small></div>
      </div>
      {!!Object.keys(latest.errors||{}).length&&<Notice variant="warning">Часть измерений недоступна: {Object.keys(latest.errors||{}).map(source=>({cpu:'CPU',memory:'память',load:'нагрузка',uptime:'время работы',network:'сеть'}[source]||source)).join(', ')}. Отсутствующие значения показаны как «—».</Notice>}
      <div className="metric-chart-grid"><Chart title="CPU хоста" points={points('cpu_percent')} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={percent}/><Chart title="Занятая память хоста" points={points('memory_used_bytes')} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={bytes}/><Chart title="Сеть · приём" points={networkRates(history,'network_rx_bytes',value?.interval_seconds||5)} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={value=>`${bytes(value)}/с`}/><Chart title="Сеть · передача" points={networkRates(history,'network_tx_bytes',value?.interval_seconds||5)} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={value=>`${bytes(value)}/с`}/></div>
      <div className="metric-network-total"><Network size={14}/><span>Сумма счётчиков интерфейсов без loopback: ↓ {measurement(latest.network_rx_bytes,bytes)} · ↑ {measurement(latest.network_tx_bytes,bytes)}. Включает внутренний трафик и может учитывать его несколько раз.</span></div>
    </>}
    {latest&&<div className="metric-filesystems"><h3><HardDrive size={15}/>Файловые системы</h3>{latest.filesystems?.length?<div className="table-wrap"><table><thead><tr><th>Хранилище</th><th>Доступно / всего</th><th>Свободные inode / всего</th></tr></thead><tbody>{latest.filesystems.map(filesystem=><tr key={filesystem.name}><td>{filesystem.name}<small>{filesystem.error||'Подтверждённый каталог хоста'}</small></td><td>{measurement(filesystem.available_bytes,bytes)} / {measurement(filesystem.total_bytes,bytes)}</td><td>{measurement(filesystem.available_inodes,count)} / {measurement(filesystem.total_inodes,count)}</td></tr>)}</tbody></table></div>:<p className="muted">Файловые системы для наблюдения не настроены.</p>}</div>}
    {value&&<HistoryNote retention={value.retention_seconds} resetAt={value.history_reset_at}/>}
  </section>
}

function ContainerMetricsSection({serviceID,minutes}:{serviceID:string;minutes:RangeMinutes}){
  const [selected,setSelected]=useState('')
  const {value,error}=useMetrics<Metrics>(`/api/services/${encodeURIComponent(serviceID)}/metrics${selected?`?component=${encodeURIComponent(selected)}`:''}`)
  const component=selected||value?.history_component||'',container=value?.latest.containers?.find(item=>item.component===component),now=Date.now(),history=historyWindow(value?.history||[],minutes,now)
  const points=(field:'cpu_percent'|'memory_usage_bytes'):MetricPoint[]=>history.map(sample=>{const item=sample.containers.find(item=>item.component===component);return {at:sample.at,value:item?.[field]??null,identity:item?.container_id}})
  return <section className="panel metrics-component"><div className="panel-heading"><div><h2><Boxes size={16}/>Контейнеры сервиса</h2><p>CPU: 100% соответствует одному ядру. Память без неактивного файлового cache.</p></div>{!!value?.available_components?.length&&<select aria-label="Компонент для метрик" value={component} onChange={event=>setSelected(event.target.value)}>{value.available_components.map(component=><option key={component}>{component}</option>)}</select>}</div>
    {error&&<Notice variant="error">{error}</Notice>}
    {value?.stale&&<Notice variant="warning">Измерения контейнеров ещё не получены или устарели. Нулевые значения вместо отсутствующих измерений не подставляются.</Notice>}
    {!container?<div className="metrics-empty"><Empty icon={<Activity/>}>Ожидаем измерения зарегистрированных контейнеров.</Empty></div>:<>
      <div className="metric-container-heading"><strong>{container.component}</strong><code>{short(container.container_id)}</code><div className="metric-observed"><Badge>{container.state}</Badge><span>{container.observed_at?time(container.observed_at):'Нет измерения'}</span></div></div>
      {container.error&&<Notice variant="warning">{container.error}</Notice>}
      <div className={`metrics-cards ${error||value?.stale?'measurements-stale':''}`}><div><span><Cpu size={15}/>CPU</span><strong>{measurement(container.cpu_percent,percent)}</strong><small>{container.cpu_percent===null?'Нужны два последовательных измерения':'Относительно одного ядра'}</small></div><div><span><MemoryStick size={15}/>Рабочая память</span><strong>{measurement(container.memory_usage_bytes,bytes)}</strong><small>Лимит: {measurement(container.memory_limit_bytes,bytes)}</small></div><div><span><Network size={15}/>Сеть · накопленные байты</span><strong className="network-value">↓ {measurement(container.network_rx_bytes,bytes)}</strong><small>↑ {measurement(container.network_tx_bytes,bytes)}</small></div></div>
      <div className="metric-extra-values"><span>Дисковые операции: чтение {measurement(container.block_read_bytes,bytes)} · запись {measurement(container.block_write_bytes,bytes)}</span><span>Процессы: {measurement(container.pids_current,count)} / {measurement(container.pids_limit,count)}</span><span>Перезапуски: {measurement(container.restart_count,count)}</span><span>OOM при последнем завершении: {container.oom_killed===null||container.oom_killed===undefined?'—':container.oom_killed?'да':'нет'}</span></div>
      <div className="metric-chart-grid"><Chart title="CPU контейнера" points={points('cpu_percent')} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={percent}/><Chart title="Память контейнера" points={points('memory_usage_bytes')} minutes={minutes} now={now} interval={value?.interval_seconds||5} format={bytes}/></div>
      <p className="metric-chart-explanation">Пропуски измерений и смена контейнера оставляют разрыв на графике.</p>
    </>}
    {value&&<HistoryNote retention={value.retention_seconds} resetAt={value.history_reset_at}/>}
  </section>
}

function HistoryNote({retention,resetAt}:{retention:number;resetAt?:string}){
  return <p className="metric-history-note">До {retention/60} мин истории в памяти executor · при перезапуске история очищается.{resetAt&&<> Начало текущего сбора: {time(resetAt)}.</>}</p>
}

function Chart({title,points,minutes,now,interval,format}:{title:string;points:MetricPoint[];minutes:RangeMinutes;now:number;interval:number;format:(value:number)=>string}){
  const start=now-minutes*60_000,observed=points.map(point=>point.value).filter((value):value is number=>value!==null&&Number.isFinite(value)&&value>=0),maximum=Math.max(1,...observed)*1.1
  const segments=metricSegments(points,start,now,maximum,interval)
  return <div className="metric-chart"><div className="metric-chart-heading"><span>{title}</span><span>{observed.length?`0 — ${format(maximum)}`:'Нет измерений'}</span></div>{observed.length?<svg viewBox="0 0 600 105" role="img" aria-label={`${title}, последние ${minutes} минут`} preserveAspectRatio="none"><line className="chart-gridline" x1="10" x2="590" y1="30" y2="30"/><line className="chart-gridline" x1="10" x2="590" y1="60" y2="60"/><line className="chart-gridline" x1="10" x2="590" y1="90" y2="90"/>{segments.map((segment,index)=>segment.length===1?<circle key={index} className="chart-point" cx={segment[0].x} cy={segment[0].y} r="2.3"/>:<polyline key={index} className="chart-line" points={segment.map(point=>`${point.x.toFixed(1)},${point.y.toFixed(1)}`).join(' ')}/>)}</svg>:<div className="chart-wait">В этом интервале пока нет измерений.</div>}<div className="chart-times"><span>{time(new Date(start).toISOString())}</span><span>{time(new Date(now).toISOString())}</span></div></div>
}
