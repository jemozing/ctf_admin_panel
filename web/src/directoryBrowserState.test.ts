/// <reference types="node" />
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {initialBrowseDirectory,selectableBrowseDirectory} from './directoryBrowserState.ts'

const roots=['/srv/game-services','/opt/ctf/projects']
const listing=(directory:string)=>({directory,parent:'',directories:[],compose_files:[],truncated:false})

test('folder browser starts inside an approved root and preserves literal filenames',()=>{
  assert.equal(initialBrowseDirectory(' /srv/game-services/bank ',roots),'/srv/game-services/bank')
  assert.equal(initialBrowseDirectory('/opt/ctf/projects',roots),'/opt/ctf/projects')
  assert.equal(initialBrowseDirectory('/srv/game-services/service with spaces',roots),'/srv/game-services/service with spaces')
  assert.equal(initialBrowseDirectory('/srv/game-services/<service>',roots),'/srv/game-services/<service>')
})

test('manual aliases, siblings and browser-computer paths fall back to the approved-root list',()=>{
  for(const path of ['', '/', '/etc', '/srv/game-services-old/bank', '/srv/game-services/../private', '/srv/game-services/./bank', '/srv/game-services//bank', '/srv/game-services/bank/', '"/srv/game-services/bank"', '~/bank', 'C:\\services\\bank', '/srv/game-services/bank\nother']){
    assert.equal(initialBrowseDirectory(path,roots),'',path)
  }
  assert.equal(initialBrowseDirectory('/srv/game-services/bank',[]),'')
})

test('an old folder response cannot select a previous location during navigation',()=>{
  const old=listing('/srv/game-services/first')
  assert.equal(selectableBrowseDirectory(old,'/srv/game-services/second',false,roots),null)
  assert.equal(selectableBrowseDirectory(old,old.directory,true,roots),null)
  assert.equal(selectableBrowseDirectory(null,old.directory,false,roots),null)
  assert.equal(selectableBrowseDirectory(old,old.directory,false,roots),old.directory)
})

test('root-list and out-of-scope responses cannot populate the service field',()=>{
  assert.equal(selectableBrowseDirectory(listing(''),'',false,roots),null)
  assert.equal(selectableBrowseDirectory(listing('/etc'),'/etc',false,roots),null)
  assert.equal(selectableBrowseDirectory(listing('/srv/game-services-old'),'/srv/game-services-old',false,roots),null)
  assert.equal(selectableBrowseDirectory(listing('/srv/game-services'),'/srv/game-services',false,roots),'/srv/game-services')
})
