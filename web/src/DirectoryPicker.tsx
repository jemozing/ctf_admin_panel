import {useEffect,useRef,useState} from 'react'
import {ArrowUp,Check,ChevronRight,Folder,FolderTree,RefreshCw,X} from 'lucide-react'
import {post} from './api'
import type {RegistrationDirectoryListing} from './api'
import {initialBrowseDirectory,selectableBrowseDirectory} from './directoryBrowserState'
import {Button,Notice} from './ui'

type View={directory:string;revision:number;listing:RegistrationDirectoryListing|null;loading:boolean;error:string}

export default function DirectoryPicker({initialDirectory,roots,disabled=false,onSelect,onClose}:{initialDirectory:string;roots:string[];disabled?:boolean;onSelect:(path:string)=>void;onClose:()=>void}){
  const [directory,setDirectory]=useState(()=>initialBrowseDirectory(initialDirectory,roots))
  const [revision,setRevision]=useState(0)
  const [view,setView]=useState<View>({directory:'',revision:-1,listing:null,loading:true,error:''})
  const heading=useRef<HTMLHeadingElement>(null)
  useEffect(()=>{heading.current?.focus()},[])
  useEffect(()=>{
    let active=true
    setView({directory,revision,listing:null,loading:true,error:''})
    post<RegistrationDirectoryListing>('/api/registration/directories',{directory}).then(listing=>{
      if(active)setView({directory,revision,listing,loading:false,error:listing.directory===directory?'':'Каталог изменился. Обновите список папок.'})
    }).catch(error=>{
      if(active)setView({directory,revision,listing:null,loading:false,error:error instanceof Error?error.message:'Не удалось открыть папку.'})
    })
    // Late replies from a previous folder, a closed picker or React effect
    // cleanup must never replace the current navigation or select a path.
    return()=>{active=false}
  },[directory,revision])
  const loading=view.loading||view.directory!==directory||view.revision!==revision
  const listing=!loading&&!view.error?view.listing:null
  const selected=selectableBrowseDirectory(listing,directory,loading||disabled,roots)
  const navigate=(path:string)=>{if(!disabled)setDirectory(path)}
  return <section id="registration-directory-picker" className="directory-picker" aria-labelledby="registration-directory-heading" aria-busy={loading}>
    <div className="directory-picker-heading"><h3 id="registration-directory-heading" ref={heading} tabIndex={-1}>Папки Docker-хоста</h3><Button type="button" variant="ghost" disabled={disabled} onClick={onClose} aria-label="Закрыть выбор папки"><X size={16}/></Button></div>
    <p className="directory-picker-help">Выберите папку сервиса на сервере, где работает Docker. Доступны только подключённые каталоги.</p>
    <div className="directory-picker-toolbar">
      <Button type="button" variant="outline" disabled={disabled||directory===''} onClick={()=>navigate('')}><FolderTree size={14}/>Все каталоги</Button>
      <Button type="button" variant="ghost" disabled={disabled||loading||!listing?.parent} onClick={()=>{if(listing?.parent)navigate(listing.parent)}}><ArrowUp size={14}/>Выше</Button>
      <Button type="button" variant="ghost" disabled={disabled||loading} onClick={()=>setRevision(value=>value+1)} aria-label="Обновить список папок"><RefreshCw size={14}/></Button>
    </div>
    <div className="directory-picker-location"><span>Текущий каталог</span><code>{directory||'Разрешённые каталоги'}</code></div>
    {loading?<div className="directory-picker-status" role="status"><RefreshCw size={15} className="spin"/>Загружаем папки…</div>:view.error?<div className="directory-picker-error"><Notice variant="error">{view.error}</Notice><Button type="button" variant="outline" disabled={disabled} onClick={()=>setRevision(value=>value+1)}>Повторить</Button></div>:listing&&<>
      {listing.directories.length?<ul className="directory-picker-list" aria-label={directory?'Вложенные папки':'Разрешённые каталоги'}>{listing.directories.map(entry=><li key={entry.path}><button type="button" disabled={disabled} onClick={()=>navigate(entry.path)} aria-label={`Открыть папку ${entry.name}`}><Folder size={17}/><span><strong>{entry.name}</strong>{!directory&&<code>{entry.path}</code>}</span><ChevronRight size={15}/></button></li>)}</ul>:<p className="directory-picker-status">{directory?'Вложенных папок нет.':'Каталоги сервисов не подключены.'}</p>}
      {directory&&<p className="directory-picker-compose">{listing.compose_files.length?<>Compose-файлы: <code>{listing.compose_files.join(', ')}</code></>:'Стандартные Compose-файлы в этой папке не найдены.'}</p>}
      {listing.truncated&&<Notice variant="warning">Показана только часть папок. Если нужной нет в списке, закройте выбор и введите полный путь вручную.</Notice>}
    </>}
    <div className="directory-picker-footer"><Button type="button" variant="ghost" disabled={disabled} onClick={onClose}>Отмена</Button><Button type="button" disabled={!selected} onClick={()=>{if(selected)onSelect(selected)}}><Check size={14}/>Выбрать эту папку</Button></div>
  </section>
}
