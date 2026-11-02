// Probe snapshots live only in component memory, alongside the editable token.
// Never persist or print them: equality includes credentials to reject stale replies.
export type GitProbeDraft = {url:string;ref:string;subdirectory:string;username:string;token:string;clearCredentials:boolean}
export type GitProbeSnapshot = GitProbeDraft & {serviceID:string;hasCredentials:boolean}
export type GitProbeBranch = {name:string;ref:string;commit:string}

export function gitProbeSnapshot(draft:GitProbeDraft,serviceID='',hasCredentials=false):GitProbeSnapshot {
  return {...draft,serviceID,hasCredentials}
}

export function sameGitProbeRepository(a:GitProbeSnapshot,b:GitProbeSnapshot){
  return a.url===b.url&&a.username===b.username&&a.token===b.token&&a.clearCredentials===b.clearCredentials&&a.serviceID===b.serviceID&&a.hasCredentials===b.hasCredentials
}

export function acceptsGitProbeReply(started:GitProbeSnapshot,current:GitProbeSnapshot,requestID:number,latestRequestID:number,active=true){
  return active&&requestID===latestRequestID&&sameGitProbeRepository(started,current)&&started.ref===current.ref&&started.subdirectory===current.subdirectory
}

export function gitProbeBranchRef(branches:readonly GitProbeBranch[],selected:string){
  if(!selected.startsWith('refs/heads/'))return null
  const name=selected.slice('refs/heads/'.length)
  if(!name||!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/.test(selected)||selected.includes('..')||selected.includes('//')||selected.includes('/.')||selected.endsWith('/')||selected.endsWith('.')||selected.endsWith('.lock'))return null
  return branches.some(branch=>branch.ref===selected&&branch.name===name)?selected:null
}

export function matchingGitProbeBranch(branches:readonly GitProbeBranch[],ref:string){
  return branches.find(branch=>(branch.ref===ref||branch.name===ref)&&gitProbeBranchRef(branches,branch.ref))?.ref||''
}
