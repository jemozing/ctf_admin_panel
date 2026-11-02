import assert from 'node:assert/strict'
import test from 'node:test'
import type {DataPath,RegistrationService} from './api.ts'
import {classifyStorage,codeBindingEligible,codeBindingNames,codeTargetsSelected,managedPathsResult,storageUsage} from './registrationCodeMode.ts'

const bind:DataPath={name:'web-bind',kind:'bind',source:'/srv/games/filestorage',target:'/app',component:'web',significant:true,loss_accepted:false}
const fixture=():RegistrationService=>({id:'draft',schema_version:1,name:'Game',compose_project:'game',project_directory:bind.source,source_directory:'/srv/workspaces/draft',compose_files:['compose.yaml'],managed_paths:[],targets:['web','cleaner'],policy_revision:1,file_map_revision:1,containers:[],data_paths:[{...bind},{...bind,name:'cleaner-bind',component:'cleaner'}]})

test('code mode is opt-in for each exact bind and records possible data loss',()=>{
  const initial=fixture(),next=classifyStorage(initial,0,'code')
  assert.equal(storageUsage(initial.data_paths![0]),'significant')
  assert.deepEqual(codeBindingNames(initial),[])
  assert.equal(storageUsage(next.data_paths![0]),'code')
  assert.equal(next.data_paths![0].loss_accepted,true)
  assert.equal(next.data_paths![0].significant,false)
  assert.deepEqual(codeBindingNames(next),['web-bind'])
  assert.equal(next.data_paths![1].allow_code_updates,undefined)
})
test('changing back to stored or disposable data removes code-update permission',()=>{
  const code=classifyStorage(fixture(),0,'code')
  for(const usage of ['significant','disposable'] as const){
    const next=classifyStorage(code,0,usage),data=next.data_paths![0]
    assert.equal(data.allow_code_updates,false)
    assert.equal(storageUsage(data),usage)
    assert.deepEqual(codeBindingNames(next),[])
  }
})
test('all selected code-bind consumers must be update targets',()=>{
  const both=classifyStorage(classifyStorage(fixture(),0,'code'),1,'code')
  assert.equal(codeTargetsSelected(both),true)
  assert.equal(codeTargetsSelected({...both,targets:['web']}),false)
  assert.deepEqual(codeBindingNames(both),['cleaner-bind','web-bind'])
})
test('code mode rejects volumes, external paths and sibling-prefix paths',()=>{
  for(const data of [{...bind,kind:'named_volume'},{...bind,source:'/srv/games/filestorage-other'},{...bind,source:'/srv/other'}]){
    const service={...fixture(),data_paths:[data]}
    assert.equal(codeBindingEligible(data,service.project_directory),false)
    assert.throws(()=>classifyStorage(service,0,'code'))
  }
  assert.equal(codeBindingEligible({...bind,source:bind.source+'/src'},bind.source),true)
})
test('managed-path response is copied and malformed or overlapping responses fail closed',()=>{
  const input={managed_paths:[{path:'src',kind:'code',exclusions:['.env','uploads']},{path:'compose.yaml',kind:'configuration'}]}
  const paths=managedPathsResult(input)
  assert.deepEqual(paths,input.managed_paths)
  paths[0].exclusions!.push('other')
  assert.deepEqual(input.managed_paths[0].exclusions,['.env','uploads'])
  for(const value of [null,{}, {managed_paths:null},{managed_paths:[{path:'../outside',kind:'code'}]},{managed_paths:[{path:'/outside',kind:'code'}]},{managed_paths:[{path:'src',kind:'unknown'}]},{managed_paths:[{path:'src',kind:'code',exclusions:['../secret']}]},{managed_paths:[{path:'src',kind:'code'},{path:'src/main.py',kind:'code'}]}])assert.throws(()=>managedPathsResult(value))
  assert.deepEqual(managedPathsResult({managed_paths:[]}),[])
})
