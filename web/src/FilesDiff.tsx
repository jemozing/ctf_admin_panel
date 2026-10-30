import {useEffect,useState} from 'react'
import {FileText,RefreshCw} from 'lucide-react'
import {api,bytes,label,short,time} from './api'
import type {Details,FilesResult} from './api'
import {Badge,Button,Empty,Notice} from './ui'

export default function FilesDiff({details,sensitiveAccess}:{details:Details;sensitiveAccess:boolean}){
 const [comparison,setComparison]=useState(details.candidate_id?'candidate':'drift'),[release,setRelease]=useState(details.releases[0]?.id||''),[path,setPath]=useState(''),[revision,setRevision]=useState(0)
 const [value,setValue]=useState<FilesResult|null>(null),[error,setError]=useState(''),[loading,setLoading]=useState(false)
 const key=`${details.service.id}:${details.candidate_id}:${details.current_release_id}`
 useEffect(()=>{setPath('')},[comparison,release,key])
 useEffect(()=>{
  if(!sensitiveAccess)return;let active=true;const controller=new AbortController();setLoading(true);setError('')
  const q=new URLSearchParams({comparison});if(comparison==='release')q.set('release_id',release);if(path)q.set('path',path)
  api<FilesResult>(`/api/services/${details.service.id}/files?${q}`,{signal:controller.signal}).then(result=>{if(active)setValue(result)}).catch(error=>{if(active){setError(error instanceof Error?error.message:'Сравнение недоступно');setValue(null)}}).finally(()=>{if(active)setLoading(false)})
  return()=>{active=false;controller.abort()}
 },[comparison,release,key,path,revision,sensitiveAccess,details.service.id])
 if(!sensitiveAccess)return <Empty icon={<FileText/>}>Доступ к файлам и diff выдаёт администратор команды.</Empty>
 const beforeTitle=comparison==='drift'?'Сохранённый активный релиз':'Активные файлы',afterTitle={candidate:'Неизменяемый кандидат',workspace:'Workspace',release:'Выбранный релиз',drift:'Фактические активные файлы'}[comparison]||comparison
 return <div className="panel"><div className="panel-heading"><div><h2><FileText size={17}/>Файлы и изменения</h2><p>Точное сравнение manifest: содержимое, тип, UID/GID и mode. Игровые данные исключены.</p></div><Button variant="outline" busy={loading} onClick={()=>setRevision(value=>value+1)}><RefreshCw size={14}/>Обновить diff</Button></div>
 <div className="diff-toolbar"><label>Сравнение<select value={comparison} onChange={event=>setComparison(event.target.value)}><option value="candidate" disabled={!details.candidate_id}>Активные файлы → кандидат</option><option value="workspace">Активные файлы → workspace</option><option value="release">Активные файлы → релиз</option><option value="drift">Сохранённый релиз → активные файлы · drift</option></select></label>{comparison==='release'&&<label>Релиз<select value={release} onChange={event=>setRelease(event.target.value)}>{details.releases.map(value=><option key={value.id} value={value.id}>{value.id}</option>)}</select></label>}</div>
 {error&&<Notice variant="error">{error}</Notice>}{value&&<><div className="preview-facts"><div className="fact"><span>{beforeTitle}</span><code>{short(value.before_digest)}</code></div><div className="fact"><span>{afterTitle}</span><code>{short(value.after_digest)}</code></div><div className="fact"><span>Измерено</span><span title={value.at}>{time(value.at)}</span></div></div>{value.truncated&&<Notice variant="warning">Список ограничен первыми 2 000 изменениями.</Notice>}
 {value.changes.length?<div className="table-wrap"><table><thead><tr><th>Файл</th><th>Изменение</th><th>Размер до / после</th><th>UID:GID · mode до / после</th></tr></thead><tbody>{value.changes.map(change=><tr key={change.path}><td><button className="table-link" onClick={()=>setPath(change.path)}>{change.path}</button></td><td><Badge>{label(change.change)}</Badge></td><td>{change.before?bytes(change.before.size):'—'} / {change.after?bytes(change.after.size):'—'}</td><td className="mono">{change.before?`${change.before.uid}:${change.before.gid} ${change.before.mode.toString(8)}`:'—'} / {change.after?`${change.after.uid}:${change.after.gid} ${change.after.mode.toString(8)}`:'—'}</td></tr>)}</tbody></table></div>:<Empty>Изменений управляемых файлов нет.</Empty>}
 {value.file&&<><h3 className="inner-heading"><code>{value.file.path}</code></h3><div className="file-text-diff"><section><h4>{beforeTitle}</h4>{value.file.before===null?<Notice>{value.file.before_reason}</Notice>:<pre>{value.file.before}</pre>}</section><section><h4>{afterTitle}</h4>{value.file.after===null?<Notice>{value.file.after_reason}</Notice>:<pre>{value.file.after}</pre>}</section></div></>}
 </>}
 <p className="muted section-note">Показ текста ограничен UTF-8 файлами кода до 64 KiB. Конфигурация и чувствительные пути скрыты; известные private inputs редактируются. Конкурентное изменение требует нового просмотра.</p></div>
}
