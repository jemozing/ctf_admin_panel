import {useEffect,useState} from 'react'
import {api,bytes,time} from './api'
import {Badge,Button,Notice} from './ui'

type Storage={policy:{snapshot_max_bytes:number;staging_max_bytes:number;state_max_bytes:number;docker_max_bytes:number;minimum_free_bytes:number;minimum_free_inodes:number;manual_snapshots:number;candidate_snapshots:number;verified_releases:number};state:{bytes:number};snapshots:{bytes:number};staging:{bytes:number};state_capacity:{available_bytes:number;available_inodes:number};docker_usage_bytes:number;docker_capacity?:{available_bytes:number;available_inodes:number};retention_plan:{at:string;retire_releases:string[];delete_snapshots:string[];protected_snapshots:Record<string,string[]>;protected_releases:Record<string,string[]>}}
export default function StorageView(){
  const [value,setValue]=useState<Storage|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false)
  const refresh=async()=>{setBusy(true);try{setValue(await api<Storage>('/api/storage'));setError('')}catch(e){setError(e instanceof Error?e.message:'Хранилище недоступно')}finally{setBusy(false)}}
  useEffect(()=>{void refresh()},[])
  const rows=value?[["Состояние executor",value.state.bytes,value.policy.state_max_bytes],["Снимки",value.snapshots.bytes,value.policy.snapshot_max_bytes],["Временные сборки",value.staging.bytes,value.policy.staging_max_bytes],["Docker",value.docker_usage_bytes,value.policy.docker_max_bytes]] as const:[]
  return <section className="panel"><div className="panel-heading"><h2>Хранилище и ротация</h2><Button variant="outline" busy={busy} onClick={()=>void refresh()}>Обновить</Button></div>{error&&<Notice variant="error">{error}</Notice>}
    <p className="muted">Лимиты задаёт администратор executor. План показывает артефакты, подходящие под обычную ротацию; состояние может измениться с новой операцией. Backup и restore выполняются локальными административными командами.</p>
    {value&&<><div className="table-wrap"><table><thead><tr><th>Хранилище</th><th>Занято / квота</th><th>Состояние</th></tr></thead><tbody>{rows.map(([name,used,max])=><tr key={name}><td>{name}</td><td>{bytes(used)} / {bytes(max)}</td><td><Badge tone={used>=max?'bad':used>=max*.9?'warn':'good'}>{used>=max?'Квота исчерпана':used>=max*.9?'Мало места':'В пределах квоты'}</Badge></td></tr>)}</tbody></table></div>
    <p>Резерв: {bytes(value.policy.minimum_free_bytes)} и {value.policy.minimum_free_inodes.toLocaleString('ru-RU')} inode. Сохраняется до {value.policy.manual_snapshots} ручных снимков, {value.policy.candidate_snapshots} кандидатов и {value.policy.verified_releases} проверенных релизов на сервис; защищённые ссылки сохраняются дополнительно.</p>
    <p title={value.retention_plan.at}>План на {time(value.retention_plan.at)}: релизов к выводу {value.retention_plan.retire_releases.length}, снимков к удалению {value.retention_plan.delete_snapshots.length}. Защищено релизов {Object.keys(value.retention_plan.protected_releases).length}, снимков {Object.keys(value.retention_plan.protected_snapshots).length}.</p>
    <details><summary>Причины защиты артефактов</summary><div className="table-wrap"><table><thead><tr><th>Артефакт</th><th>Ссылки, удерживающие артефакт</th></tr></thead><tbody>{[...Object.entries(value.retention_plan.protected_releases),...Object.entries(value.retention_plan.protected_snapshots)].map(([id,reasons])=><tr key={id}><td><code>{id}</code></td><td>{reasons.join(', ')}</td></tr>)}</tbody></table></div></details></>}
  </section>
}
