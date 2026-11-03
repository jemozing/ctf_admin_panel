import {useEffect,useRef,useState} from 'react'
import type {FormEvent} from 'react'
import {ArrowUp,Check,ChevronRight,Download,Folder,GitBranch,RefreshCw} from 'lucide-react'
import {APIError,api,post,time} from './api'
import type {GitDirectoryListing,GitProbeResult,GitSource,GitSourceInput,Role} from './api'
import {Badge,Button,Notice} from './ui'
import {acceptsGitProbeReply,gitProbeBranchRef,gitProbeSnapshot,matchingGitProbeBranch,sameGitProbeRepository} from './gitProbeState'
import type {GitProbeSnapshot} from './gitProbeState'

export type GitDraft = {url:string;ref:string;subdirectory:string;username:string;token:string;clearCredentials:boolean}
export const emptyGitDraft:GitDraft={url:'',ref:'HEAD',subdirectory:'',username:'',token:'',clearCredentials:false}
const errorMessage=(error:unknown)=>error instanceof Error?error.message:'Не удалось выполнить запрос'

export function gitSourceInput(draft:GitDraft):GitSourceInput {
  return {url:draft.url.trim(),ref:draft.ref.trim()||'HEAD',subdirectory:draft.subdirectory.trim(),username:draft.username.trim(),...(draft.token?{token:draft.token}:{}),...(draft.clearCredentials?{clear_credentials:true}:{})}
}

function probeErrorMessage(error:unknown){
  const messages:Record<string,string>={git_dns_failed:'Не удалось определить адрес Git-сервера. Проверьте URL и DNS на сервере панели.',git_restricted_host:'Git-сервер указывает на закрытый или служебный адрес. Для подключения нужен публичный HTTPS-адрес.',git_access_failed:'Не удалось получить доступ к репозиторию. Проверьте Git URL, пользователя, токен и доступность HTTPS.',git_timeout:'Сервер Git не ответил вовремя. Повторите проверку.',git_limits:'Список версий репозитория превысил допустимый объём. Используйте другой репозиторий или уточните источник.'}
  return error instanceof APIError&&messages[error.code]?messages[error.code]:errorMessage(error)
}

function GitDirectoryPicker({draft,refName,serviceID,disabled,onChoose}:{draft:GitDraft;refName:string;serviceID?:string;disabled:boolean;onChoose:(path:string)=>void}){
  const [request,setRequest]=useState({directory:''})
  const [reply,setReply]=useState<{request:typeof request;listing?:GitDirectoryListing;error?:string}|null>(null)
  const {url,username,token,clear_credentials}=gitSourceInput(draft)
  const current=reply?.request===request?reply:null
  const listing=current?.listing
  const directory=request.directory
  const parent=listing?.parent??directory.slice(0,Math.max(0,directory.lastIndexOf('/')))
  const selected=draft.subdirectory.trim()

  useEffect(()=>{
    const controller=new AbortController()
    const body={source:{url,ref:refName,username,token,clear_credentials},service_id:serviceID,directory:request.directory}
    void api<GitDirectoryListing>('/api/git/directories',{method:'POST',body:JSON.stringify(body),signal:controller.signal}).then(listing=>{
      if(!controller.signal.aborted)setReply({request,listing})
    }).catch(error=>{
      if(controller.signal.aborted)return
      const messages:Record<string,string>={
        git_limits:'Дерево репозитория превысило допустимый объём.',
        git_directory_missing:'Папка отсутствует в выбранной версии репозитория.',
      }
      const message=error instanceof APIError&&messages[error.code]?messages[error.code]:probeErrorMessage(error)
      setReply({request,error:message})
    })
    return ()=>controller.abort()
  },[url,refName,username,token,clear_credentials,serviceID,request])

  return <section className="directory-picker git-directory-picker" aria-label="Папки Git-репозитория" aria-busy={!current}>
    <div className="directory-picker-heading"><h3>Выбор подкаталога</h3></div>
    <div className="directory-picker-location"><span>Открытая папка</span><code>{directory||'Корень репозитория'}</code></div>
    <div className="directory-picker-toolbar">
      {directory&&<Button type="button" variant="ghost" disabled={disabled} onClick={()=>setRequest({directory:parent})}><ArrowUp size={14}/>На уровень выше</Button>}
      {current?.error&&<Button type="button" variant="outline" disabled={disabled} onClick={()=>setRequest({directory})}>Повторить загрузку папок</Button>}
    </div>
    {!current&&<div className="directory-picker-status" role="status"><RefreshCw size={14} className="spin"/>Загружаем папки…</div>}
    {current?.error&&<Notice variant="warning">{current.error} Подкаталог можно указать вручную.</Notice>}
    {listing&&(listing.directories.length?<ul className="directory-picker-list" aria-label="Подкаталоги">{listing.directories.map(entry=><li key={entry.path}>
      <button type="button" disabled={disabled} aria-label={`Открыть папку ${entry.name}`} onClick={()=>setRequest({directory:entry.path})}><Folder size={15}/><span><strong>{entry.name}</strong></span><ChevronRight size={14}/></button>
    </li>)}</ul>:<p className="directory-picker-status">В этой папке нет подкаталогов.</p>)}
    {listing?.truncated&&<Notice variant="warning">Показана только часть папок. Остальные пути можно указать вручную.</Notice>}
    <div className="directory-picker-footer">
      <Button type="button" variant="outline" disabled={disabled} onClick={()=>{onChoose('');if(directory)setRequest({directory:''})}}>Использовать корень</Button>
      {listing?.directory&&<Button type="button" disabled={disabled} onClick={()=>onChoose(listing.directory)}>Выбрать эту папку</Button>}
    </div>
    <div className="directory-picker-location" role="status"><span>Подкаталог сервиса</span><code>{selected||'Корень репозитория'}</code></div>
  </section>
}

export function GitFields({draft,onChange,disabled=false,hasCredentials=false,serviceID}:{draft:GitDraft;onChange:(draft:GitDraft)=>void;disabled?:boolean;hasCredentials?:boolean;serviceID?:string}){
  const [probe,setProbe]=useState<{input:GitProbeSnapshot;requestID:number;result:GitProbeResult}|null>(null),[pending,setPending]=useState(false),[probeError,setProbeError]=useState('')
  const generation=useRef(0),active=useRef(false),abort=useRef<AbortController|null>(null)
  const current=gitProbeSnapshot(draft,serviceID,hasCredentials),latest=useRef(current)
  latest.current=current
  const invalidate=()=>{generation.current++;abort.current?.abort();abort.current=null;setPending(false);setProbeError('')}
  useEffect(()=>{active.current=true;return()=>{active.current=false;generation.current++;abort.current?.abort()}},[])
  useEffect(()=>{invalidate();setProbe(previous=>previous&&sameGitProbeRepository(previous.input,latest.current)?previous:null)},[draft.url,draft.ref,draft.subdirectory,draft.username,draft.token,draft.clearCredentials,serviceID,hasCredentials])
  const edit=(next:GitDraft,keepBranches=false)=>{invalidate();if(!keepBranches)setProbe(null);onChange(next)}
  const change=(key:keyof GitDraft,value:string|boolean)=>edit({...draft,[key]:value},key==='subdirectory')
  const check=async()=>{
    if(disabled||pending)return
    abort.current?.abort()
    const controller=new AbortController(),input=gitProbeSnapshot(draft,serviceID,hasCredentials),requestID=++generation.current
    abort.current=controller;setPending(true);setProbeError('');setProbe(null)
    try{
      const result=await api<GitProbeResult>('/api/git/probe',{method:'POST',body:JSON.stringify({source:gitSourceInput(draft),...(serviceID?{service_id:serviceID}:{})}),signal:controller.signal})
      if(acceptsGitProbeReply(input,latest.current,requestID,generation.current,active.current))setProbe({input,requestID,result})
    }catch(error){if(acceptsGitProbeReply(input,latest.current,requestID,generation.current,active.current))setProbeError(probeErrorMessage(error))}
    finally{if(acceptsGitProbeReply(input,latest.current,requestID,generation.current,active.current)){setPending(false);abort.current=null}}
  }
  const repository=probe&&sameGitProbeRepository(probe.input,current)?probe:null
  const checked=repository&&repository.result.selected_ref===(draft.ref.trim()||'HEAD')&&!pending?repository.result:null
  const branch=repository?matchingGitProbeBranch(repository.result.branches,draft.ref.trim()):''
  // Browse a checked ref or a full branch ref selected from its advertisement.
  // A short name may be ambiguous even when it matches a branch in the list.
  let directoryRef=''
  if(checked?.ref_status==='available')directoryRef=checked.selected_ref
  if(!checked&&branch===draft.ref.trim())directoryRef=branch
  return <div className="form-fields">
    <label>Git URL<input type="url" required disabled={disabled} value={draft.url} autoComplete="off" onChange={event=>change('url',event.target.value)} placeholder="https://github.com/team/service.git"/><small>HTTPS-ссылка GitHub, GitLab или другого Git-сервера. Токен укажите отдельным полем.</small></label>
    <div className="form-columns"><label>Ветка, тег или commit<input disabled={disabled} value={draft.ref} onChange={event=>change('ref',event.target.value)} placeholder="HEAD"/></label><label>Подкаталог сервиса<input disabled={disabled} value={draft.subdirectory} onChange={event=>change('subdirectory',event.target.value)} placeholder="services/my-service"/><small>Оставьте пустым для корня репозитория.</small></label></div>
    <div className="form-columns"><label>Пользователь для доступа<input disabled={disabled} value={draft.username} autoComplete="off" onChange={event=>change('username',event.target.value)} placeholder="oauth2"/></label><label>{hasCredentials?'Заменить сохранённый токен':'Токен · для закрытого репозитория'}<input type="password" disabled={disabled||draft.clearCredentials} value={draft.token} autoComplete="new-password" onChange={event=>change('token',event.target.value)} placeholder={hasCredentials?'Сохранён · значение скрыто':'Необязательно'}/></label></div>
    {hasCredentials&&<><small>Пустое поле сохраняет токен при прежних URL и пользователе. При смене адреса или пользователя введите токен заново.</small><label className="inline-check"><input type="checkbox" disabled={disabled} checked={draft.clearCredentials} onChange={event=>edit({...draft,clearCredentials:event.target.checked,token:''})}/>Удалить сохранённый токен</label></>}
    <section className="git-probe" aria-label="Проверка Git-репозитория" aria-busy={pending}>
      <div className="git-probe-actions"><Button type="button" variant="outline" disabled={disabled||!draft.url.trim()} busy={pending} onClick={()=>void check()}>{!pending&&<RefreshCw size={14}/>}Проверить подключение</Button>{pending&&<span role="status">Проверяем доступ и выбранную версию…</span>}</div>
      <small>После проверки доступа и версии можно выбрать папку репозитория.</small>
      {probeError&&<Notice variant="error">{probeError}</Notice>}
      {repository&&<>
        {checked?<Notice variant={checked.ref_status==='available'?'info':'warning'}><div className="git-probe-result"><Badge tone={checked.ref_status==='available'?'good':'warn'}>{checked.ref_status==='available'?<><Check size={12}/>Подключение и версия проверены</>:'Репозиторий доступен · уточните версию'}</Badge>{checked.ref_status==='available'?<p>Выбранная версия <code>{checked.selected_ref}</code> найдена.</p>:checked.ref_status==='missing'?<p>Ветка или тег <code>{checked.selected_ref}</code> не найдены среди опубликованных версий. Выберите ветку из списка или исправьте поле версии.</p>:checked.ref_status==='ambiguous'?<p>Имя <code>{checked.selected_ref}</code> неоднозначно. Выберите ветку из списка или укажите полный ref.</p>:<p>Доступ подтверждён, но наличие указанного SHA нельзя подтвердить по опубликованным версиям. Оно проверяется при получении исходников.</p>}{checked.default_branch&&<p>Основная ветка: <code>{checked.default_branch}</code>.</p>}{checked.resolved_commit&&<p>Git SHA: <code>{checked.resolved_commit}</code>.</p>}<small>Проверено {time(checked.checked_at)}.</small></div></Notice>:!directoryRef&&<p className="git-probe-stale" role="status">Версия изменена. Нажмите «Проверить подключение» для новой проверки.</p>}
        {repository.result.branches.length?<label>Выбрать ветку<select disabled={disabled||pending} value={branch} onChange={event=>{const ref=gitProbeBranchRef(repository.result.branches,event.target.value);if(ref)edit({...draft,ref},true)}}><option value="" disabled>Выберите ветку</option>{repository.result.branches.map(value=><option key={value.ref} value={value.ref}>{value.name}{value.name===repository.result.default_branch?' · основная':''}</option>)}</select><small>Выбранная ветка подставляется в поле «Ветка, тег или commit». Тег или SHA можно ввести вручную.</small></label>:<p className="git-probe-empty">{repository.result.truncated?'В этом списке нет веток для выбора.':'Опубликованных веток нет.'}</p>}
        {repository.result.truncated&&<Notice variant="warning">Показана только часть веток. Можно оставить HEAD или ввести нужную версию вручную и проверить отдельно.</Notice>}
        {directoryRef&&<GitDirectoryPicker key={`${repository.requestID}:${directoryRef}`} draft={draft} refName={directoryRef} serviceID={serviceID} disabled={disabled} onChoose={path=>{if(path!==draft.subdirectory)change('subdirectory',path)}}/>}
      </>}
    </section>
  </div>
}

export default function GitSourceView({serviceID,candidateID,role,canFetch,initialized,onFetch}:{serviceID:string;candidateID?:string;role:Role;canFetch:boolean;initialized:boolean;onFetch:()=>void}){
  const [source,setSource]=useState<GitSource|null>(null),[draft,setDraft]=useState<GitDraft>(emptyGitDraft),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[dirty,setDirty]=useState(false),[error,setError]=useState(''),[fetchError,setFetchError]=useState(''),[saved,setSaved]=useState(false)
  useEffect(()=>{
    let active=true,first=true
    const refresh=async()=>{try{const value=await api<GitSource>(`/api/services/${serviceID}/source`);if(!active)return;setSource(value);if(first){setDraft({...emptyGitDraft,url:value.url||'',ref:value.ref||'HEAD',subdirectory:value.subdirectory||'',username:value.username||''});first=false}setFetchError('')}catch(error){if(active)setFetchError(errorMessage(error))}finally{if(active)setLoading(false)}}
    void refresh();const timer=setInterval(()=>void refresh(),5000);return()=>{active=false;clearInterval(timer)}
  },[serviceID])
  const save=async(event:FormEvent)=>{event.preventDefault();setBusy(true);setError('');setSaved(false);try{const value=await post<GitSource>(`/api/services/${serviceID}/source`,gitSourceInput(draft));setSource(value);setDraft({...emptyGitDraft,url:value.url||'',ref:value.ref||'HEAD',subdirectory:value.subdirectory||'',username:value.username||''});setDirty(false);setSaved(true)}catch(error){setError(errorMessage(error));setDraft(value=>({...value,token:''}))}finally{setBusy(false)}}
  return <div className="panel"><div className="panel-heading"><div><h2><GitBranch size={17}/>Источник Git</h2><p>Получить из Git → Собрать → Применить. Утверждённые Compose-файлы сервера сохраняются в Git-кандидате.</p></div><Badge tone={source?.configured?'good':'neutral'}>{source?.configured?'Подключён':'Не подключён'}</Badge></div>
    <div className="source-content">{loading?<div className="loading-line"><RefreshCw size={16} className="spin"/>Получаем настройки источника…</div>:<>
      {fetchError&&<Notice variant="error">{fetchError}</Notice>}{error&&<Notice variant="error">{error}</Notice>}{saved&&<Notice>Настройки Git сохранены. Получите исходники, затем соберите и примените кандидат.</Notice>}
      {!initialized&&<Notice>Для получения из Git завершите инициализацию сервиса и необходимые операции восстановления. Проверьте журнал во вкладке «Операции».</Notice>}
      {role==='admin'?<form onSubmit={event=>void save(event)}><GitFields draft={draft} serviceID={serviceID} hasCredentials={source?.has_credentials} disabled={busy} onChange={value=>{setDraft(value);setDirty(true);setSaved(false)}}/><div className="source-actions"><Button type="submit" variant="outline" busy={busy} disabled={!dirty}>Сохранить настройки</Button><Button type="button" disabled={!canFetch||busy||dirty} onClick={onFetch}><Download size={15}/>Получить из Git</Button></div>{dirty&&<small>Сохраните изменения перед получением исходников.</small>}</form>:<><div className="source-facts"><div><span>Репозиторий</span><code>{source?.url||'Не подключён'}</code></div><div><span>Ветка / тег / commit</span><code>{source?.ref||'—'}</code></div><div><span>Подкаталог</span><code>{source?.subdirectory||'Корень репозитория'}</code></div></div>{role==='viewer'?<p className="section-note">Источник настраивает Admin, исходники получают Admin и Defender.</p>:<Button disabled={!canFetch} onClick={onFetch}><Download size={15}/>Получить из Git</Button>}</>}
      {source?.last_fetch&&<div className="git-last-fetch"><div><span>Последний полученный commit</span><code>{source.last_fetch.commit}</code></div><small>{time(source.last_fetch.at)} · снимок <code>{source.last_fetch.snapshot_id}</code></small><p>{source.last_fetch.snapshot_id===candidateID?'Этот Git-кандидат выбран для следующей сборки.':'Для следующей сборки выбран другой кандидат. Чтобы снова собрать из Git, нажмите «Получить из Git».'} Действующий релиз указан во вкладке «Релизы».</p></div>}
    </>}
    </div></div>
}
