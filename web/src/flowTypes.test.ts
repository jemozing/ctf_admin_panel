import assert from 'node:assert/strict'
import test from 'node:test'
import {boundedJSON,descriptorBase64,flowBytes,flowDetailRequest,flowQuery} from './flowTypes.ts'
import type {FlowMetadata,FlowPage} from './flowTypes.ts'
import {initialPacketFilters} from './packetTypes.ts'

test('flow detail retains the frozen query rather than current live filters',()=>{
 const flow={id:'flow-one'} as FlowMetadata
 const page={flows:[flow],query:{limit:50,from:'2026-10-30T00:00:00Z',until:'2026-10-30T00:01:00Z',cursor:'frozen',service_ids:['game-a']}} as FlowPage
 const request=flowDetailRequest(page,flow)
 assert.deepEqual(request.query,page.query)
 request.query.service_ids?.push('other')
 assert.deepEqual(page.query.service_ids,['game-a'])
 assert.throws(()=>flowDetailRequest(page,{id:'flow-other'} as FlowMetadata))
 assert.throws(()=>flowDetailRequest({...page,flows:[{id:'bad'} as FlowMetadata]},{id:'bad'} as FlowMetadata))
})
test('flow filters keep UTC scope, service set and both-direction conversation selection',()=>{
 const params=new URLSearchParams(flowQuery({...initialPacketFilters,services:['beta','alpha','beta'],protocol:'udp',direction:'ambiguous',from:'2026-10-30T00:00:00',until:'2026-10-30T00:01:00',destinationPort:'53'},'UTC'))
 assert.deepEqual(params.getAll('service_id'),['alpha','beta'])
 assert.equal(params.get('direction'),'ambiguous')
 assert.equal(params.get('protocol'),'udp')
 assert.equal(params.get('destination_port'),'53')
 assert.equal(params.get('until'),'2026-10-30T00:01:00.000Z')
 assert.equal(params.get('limit'),'50')
})
test('binary flow prefix is exact, bounded and never interpreted as markup',()=>{
 assert.deepEqual([...flowBytes('AP88c2NyaXB0Pg==')],[0,255,60,115,99,114,105,112,116,62])
 assert.throws(()=>flowBytes('%%%='))
 assert.throws(()=>flowBytes('YQ='))
 assert.throws(()=>flowBytes('AAAA',1))
 assert.throws(()=>flowBytes('A'.repeat(16),1))
})
test('descriptor upload is exact binary base64 with a strict two MiB bound',()=>{
 assert.equal(descriptorBase64(Uint8Array.from([0,255,1]).buffer),'AP8B')
 assert.throws(()=>descriptorBase64(new ArrayBuffer(0)))
 assert.throws(()=>descriptorBase64(new ArrayBuffer(2*1024*1024+1)))
})
test('protobuf JSON display is bounded and preserves escaped data as text',()=>{
 const result=boundedJSON({data:'<script>'+ 'x'.repeat(20000)},100)
 assert.equal(result.text.length,100)
 assert.equal(result.truncated,true)
 assert.equal(boundedJSON({ok:true}).truncated,false)
})
