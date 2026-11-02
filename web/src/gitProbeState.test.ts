/// <reference types="node" />
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {acceptsGitProbeReply,gitProbeBranchRef,gitProbeSnapshot,matchingGitProbeBranch,sameGitProbeRepository} from './gitProbeState.ts'

const draft={url:'https://github.com/example/game.git',ref:'HEAD',subdirectory:'app',username:'oauth2',token:'fixture-token',clearCredentials:false}
const snapshot=()=>gitProbeSnapshot(draft,'game',true)
const branches=[{name:'main',ref:'refs/heads/main',commit:'a'.repeat(40)},{name:'feature/next',ref:'refs/heads/feature/next',commit:'b'.repeat(40)}]

test('probe replies are valid only for the exact draft and credential context',()=>{
  const started=snapshot()
  assert.equal(acceptsGitProbeReply(started,snapshot(),3,3),true)
  for(const patch of [{url:'https://gitlab.com/example/game.git'},{username:'other'},{token:'replacement-fixture-token'},{clearCredentials:true},{ref:'refs/heads/main'},{subdirectory:'other'},{serviceID:'other-game'},{hasCredentials:false}]){
    assert.equal(acceptsGitProbeReply(started,{...snapshot(),...patch},3,3),false,Object.keys(patch)[0])
  }
})

test('editing back, a newer check and unmount cannot revive an old success',()=>{
  const started=snapshot()
  assert.equal(acceptsGitProbeReply(started,snapshot(),3,5),false)
  assert.equal(acceptsGitProbeReply(started,snapshot(),3,3,false),false)
})

test('branch advertisements can survive ref selection but not credential or repository changes',()=>{
  assert.equal(sameGitProbeRepository(snapshot(),{...snapshot(),ref:'refs/heads/main'}),true)
  assert.equal(sameGitProbeRepository(snapshot(),{...snapshot(),token:''}),false)
  assert.equal(sameGitProbeRepository(snapshot(),{...snapshot(),url:draft.url+'/other'}),false)
  assert.equal(sameGitProbeRepository(snapshot(),{...snapshot(),serviceID:'other'}),false)
})

test('interactive branch choice uses an advertised full branch ref',()=>{
  assert.equal(gitProbeBranchRef(branches,'refs/heads/main'),'refs/heads/main')
  assert.equal(gitProbeBranchRef(branches,'refs/heads/feature/next'),'refs/heads/feature/next')
  for(const selected of ['main','refs/tags/main','refs/heads/missing','refs/heads/../main','refs/heads/a.lock','refs/heads//main'])assert.equal(gitProbeBranchRef(branches,selected),null,selected)
  assert.equal(gitProbeBranchRef([{name:'wrong-name',ref:'refs/heads/main',commit:'a'.repeat(40)}],'refs/heads/main'),null)
  const uncommon=[{name:'_main',ref:'refs/heads/_main',commit:'a'.repeat(40)},{name:'-next',ref:'refs/heads/-next',commit:'a'.repeat(40)}]
  for(const branch of uncommon)assert.equal(gitProbeBranchRef(uncommon,branch.ref),branch.ref)
  const long='a'.repeat(250)
  assert.equal(gitProbeBranchRef([{name:long,ref:'refs/heads/'+long,commit:'a'.repeat(40)}],'refs/heads/'+long),null)
})

test('the branch menu reflects short or full refs without reinterpreting tags and commits',()=>{
  assert.equal(matchingGitProbeBranch(branches,'main'),'refs/heads/main')
  assert.equal(matchingGitProbeBranch(branches,'refs/heads/feature/next'),'refs/heads/feature/next')
  for(const ref of ['HEAD','refs/tags/main','a'.repeat(40),'missing'])assert.equal(matchingGitProbeBranch(branches,ref),'',ref)
})
