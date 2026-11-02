import type {RegistrationDirectoryListing} from './api'

// These checks choose a useful initial location; the executor remains the
// authority for filesystem access and rechecks the selected path at import.
function canonicalDirectory(path:string){
  return path.startsWith('/')&&path!=='/'&&!path.endsWith('/')&&!/[\u0000-\u001f\u007f]/.test(path)&&!path.split('/').slice(1).some(part=>!part||part==='.'||part==='..')
}

export function initialBrowseDirectory(value:string,roots:readonly string[]){
  const path=value.trim()
  return canonicalDirectory(path)&&roots.some(root=>canonicalDirectory(root)&&(path===root||path.startsWith(root+'/')))?path:''
}

export function selectableBrowseDirectory(listing:RegistrationDirectoryListing|null,requested:string,loading:boolean,roots:readonly string[]){
  if(loading||!listing||listing.directory!==requested||!listing.directory)return null
  return initialBrowseDirectory(listing.directory,roots)===listing.directory?listing.directory:null
}
