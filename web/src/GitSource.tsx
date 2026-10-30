import {useEffect,useState} from 'react'
import type {FormEvent} from 'react'
import {Download,GitBranch,RefreshCw} from 'lucide-react'
import {api,post,time} from './api'
import type {GitSource,GitSourceInput,Role} from './api'
import {Badge,Button,Notice} from './ui'

export type GitDraft = {url:string;ref:string;subdirectory:string;username:string;token:string;clearCredentials:boolean}
export const emptyGitDraft:GitDraft={url:'',ref:'HEAD',subdirectory:'',username:'',token:'',clearCredentials:false}
const errorMessage=(error:unknown)=>error instanceof Error?error.message:'Не удалось выполнить запрос'

export function gitSourceInput(draft:GitDraft):GitSourceInput {
  return {url:draft.url.trim(),ref:draft.ref.trim()||'HEAD',subdirectory:draft.subdirectory.trim(),username:draft.username.trim(),...(draft.token?{token:draft.token}:{}),...(draft.clearCredentials?{clear_credentials:true}:{})}
}

export function GitFields({draft,onChange,disabled=false,hasCredentials=false}:{draft:GitDraft;onChange:(draft:GitDraft)=>void;disabled?:boolean;hasCredentials?:boolean}){
  const change=(key:keyof GitDraft,value:string|boolean)=>onChange({...draft,[key]:value})
  return <div className="form-fields">
    <label>Git URL<input type="url" required disabled={disabled} value={draft.url} autoComplete="off" onChange={event=>change('url',event.target.value)} placeholder="https://github.com/team/service.git"/><small>HTTPS-ссылка GitHub, GitLab или другого Git-сервера. Токен укажите отдельным полем.</small></label>
    <div className="form-columns"><label>Ветка, тег или commit<input disabled={disabled} value={draft.ref} onChange={event=>change('ref',event.target.value)} placeholder="HEAD"/></label><label>Подкаталог сервиса<input disabled={disabled} value={draft.subdirectory} onChange={event=>change('subdirectory',event.target.value)} placeholder="services/my-service"/><small>Оставьте пустым для корня репозитория.</small></label></div>
    <div className="form-columns"><label>Пользователь для доступа<input disabled={disabled} value={draft.username} autoComplete="off" onChange={event=>change('username',event.target.value)} placeholder="oauth2"/></label><label>{hasCredentials?'Заменить сохранённый токен':'Токен · для закрытого репозитория'}<input type="password" disabled={disabled||draft.clearCredentials} value={draft.token} autoComplete="new-password" onChange={event=>change('token',event.target.value)} placeholder={hasCredentials?'Сохранён · значение скрыто':'Необязательно'}/></label></div>
    {hasCredentials&&<><small>Пустое поле сохраняет токен при прежних URL и пользователе. При смене адреса или пользователя введите токен заново.</small><label className="inline-check"><input type="checkbox" disabled={disabled} checked={draft.clearCredentials} onChange={event=>onChange({...draft,clearCredentials:event.target.checked,token:''})}/>Удалить сохранённый токен</label></>}
  </div>
}

export default function GitSourceView({serviceID,role,canFetch,initialized,onFetch}:{serviceID:string;role:Role;canFetch:boolean;initialized:boolean;onFetch:()=>void}){
  const [source,setSource]=useState<GitSource|null>(null),[draft,setDraft]=useState<GitDraft>(emptyGitDraft),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[dirty,setDirty]=useState(false),[error,setError]=useState(''),[fetchError,setFetchError]=useState(''),[saved,setSaved]=useState(false)
  useEffect(()=>{
    let active=true,first=true
    const refresh=async()=>{try{const value=await api<GitSource>(`/api/services/${serviceID}/source`);if(!active)return;setSource(value);if(first){setDraft({...emptyGitDraft,url:value.url||'',ref:value.ref||'HEAD',subdirectory:value.subdirectory||'',username:value.username||''});first=false}setFetchError('')}catch(error){if(active)setFetchError(errorMessage(error))}finally{if(active)setLoading(false)}}
    void refresh();const timer=setInterval(()=>void refresh(),5000);return()=>{active=false;clearInterval(timer)}
  },[serviceID])
  const save=async(event:FormEvent)=>{event.preventDefault();setBusy(true);setError('');setSaved(false);try{const value=await post<GitSource>(`/api/services/${serviceID}/source`,gitSourceInput(draft));setSource(value);setDraft({...emptyGitDraft,url:value.url||'',ref:value.ref||'HEAD',subdirectory:value.subdirectory||'',username:value.username||''});setDirty(false);setSaved(true)}catch(error){setError(errorMessage(error));setDraft(value=>({...value,token:''}))}finally{setBusy(false)}}
  return <div className="panel"><div className="panel-heading"><div><h2><GitBranch size={17}/>Источник Git</h2><p>Получение исходников создаёт кандидат для сборки. Применение выполняется отдельно.</p></div><Badge tone={source?.configured?'good':'neutral'}>{source?.configured?'Подключён':'Не подключён'}</Badge></div>
    <div className="source-content">{loading?<div className="loading-line"><RefreshCw size={16} className="spin"/>Получаем настройки источника…</div>:<>
      {fetchError&&<Notice variant="error">{fetchError}</Notice>}{error&&<Notice variant="error">{error}</Notice>}{saved&&<Notice>Настройки Git сохранены. Получите исходники, затем соберите и примените кандидат.</Notice>}
      {!initialized&&<Notice>Для получения из Git завершите инициализацию сервиса и необходимые операции восстановления. Проверьте журнал во вкладке «Операции».</Notice>}
      {role==='admin'?<form onSubmit={event=>void save(event)}><GitFields draft={draft} hasCredentials={source?.has_credentials} disabled={busy} onChange={value=>{setDraft(value);setDirty(true);setSaved(false)}}/><div className="source-actions"><Button type="submit" variant="outline" busy={busy} disabled={!dirty}>Сохранить настройки</Button><Button type="button" disabled={!canFetch||busy||dirty} onClick={onFetch}><Download size={15}/>Получить из Git</Button></div>{dirty&&<small>Сохраните изменения перед получением исходников.</small>}</form>:<><div className="source-facts"><div><span>Репозиторий</span><code>{source?.url||'Не подключён'}</code></div><div><span>Ветка / тег / commit</span><code>{source?.ref||'—'}</code></div><div><span>Подкаталог</span><code>{source?.subdirectory||'Корень репозитория'}</code></div></div>{role==='viewer'?<p className="section-note">Источник настраивает Admin, исходники получают Admin и Defender.</p>:<Button disabled={!canFetch} onClick={onFetch}><Download size={15}/>Получить из Git</Button>}</>}
      {source?.last_fetch&&<div className="git-last-fetch"><div><span>Последний полученный commit</span><code>{source.last_fetch.commit}</code></div><small>{time(source.last_fetch.at)} · снимок <code>{source.last_fetch.snapshot_id}</code></small><p>Этот commit относится к полученному кандидату. Действующий релиз указан во вкладке «Релизы».</p></div>}
    </>}
    </div></div>
}
