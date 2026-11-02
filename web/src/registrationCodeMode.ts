import type {DataPath,ManagedPath,RegistrationService} from './api'

export type StorageUsage='unclassified'|'significant'|'disposable'|'code'
export const storageUsage=(data:DataPath):StorageUsage=>data.allow_code_updates?'code':data.significant?'significant':data.loss_accepted?'disposable':'unclassified'
export const codeBindings=(service:RegistrationService)=>service.data_paths?.filter(data=>data.kind==='bind'&&data.allow_code_updates)||[]
export const codeBindingNames=(service:RegistrationService)=>codeBindings(service).map(data=>data.name).sort()
export const codeTargetsSelected=(service:RegistrationService)=>codeBindings(service).every(data=>service.targets.includes(data.component))
export const codeBindingEligible=(data:DataPath,root:string)=>data.kind==='bind'&&typeof data.source==='string'&&(data.source===root||data.source.startsWith(root+'/'))

export function classifyStorage(service:RegistrationService,index:number,usage:StorageUsage):RegistrationService{
  const selected=service.data_paths?.[index]
  if(!selected||usage==='code'&&!codeBindingEligible(selected,service.project_directory))throw new Error('Кодовый bind должен находиться внутри каталога сервиса.')
  return {...service,data_paths:service.data_paths?.map((data,i)=>i===index?{...data,significant:usage==='significant',loss_accepted:usage==='disposable'||usage==='code',allow_code_updates:usage==='code'}:data)}
}

const relativePath=(path:unknown):path is string=>typeof path==='string'&&path.length>0&&path.length<=4096&&path.trim()===path&&!/[\\\x00-\x1f\x7f]/.test(path)&&!path.startsWith('/')&&path.split('/').every(part=>part!==''&&part!=='.'&&part!=='..')
export function managedPathsResult(value:unknown):ManagedPath[]{
  if(!value||typeof value!=='object'||!('managed_paths' in value)||!Array.isArray(value.managed_paths)||value.managed_paths.length>4096)throw new Error('Не удалось проверить список управляемых путей. Повторите выбор назначения.')
  const paths:ManagedPath[]=[]
  for(const item of value.managed_paths){
    if(!item||typeof item!=='object'||!relativePath(item.path)||!['code','configuration'].includes(item.kind)||item.exclusions!==undefined&&(!Array.isArray(item.exclusions)||!item.exclusions.every(relativePath)))throw new Error('Получен некорректный список управляемых путей. Назначение хранилища не изменено.')
    if(paths.some(previous=>previous.path===item.path||previous.path.startsWith(item.path+'/')||item.path.startsWith(previous.path+'/')))throw new Error('Получены пересекающиеся управляемые пути. Назначение хранилища не изменено.')
    paths.push({path:item.path,kind:item.kind,...(item.exclusions===undefined?{}:{exclusions:[...item.exclusions]})})
  }
  return paths
}
