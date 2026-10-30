/// <reference types="node" />
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {mergeLogRecords,highlightParts} from './logHistory.ts'
const record=(id:string,text=id,container_id='old')=>({id,text,container_id,component:'app',stream:'stdout',at:'2026-10-19T00:00:00Z'})
test('tail reconnects do not duplicate observations and recreated IDs remain distinct',()=>{
 const first=mergeLogRecords([], [record('a'),record('b')]).records
 assert.deepEqual(mergeLogRecords(first,[record('a'),record('b'),record('c','same','new')]).records.map(v=>v.id),['a','b','c'])
 assert.equal(mergeLogRecords(first,[record('c')],2).omitted,true)
 assert.deepEqual(mergeLogRecords([], [record('a','aaa'),record('b','bbb')],10,4).records.map(v=>v.id),['b'])
})
test('search highlighting treats HTML and regex-looking values as literal text',()=>{
 assert.deepEqual(highlightParts('<script>[a]</script>','[a]'),[{text:'<script>',match:false},{text:'[a]',match:true},{text:'</script>',match:false}])
 assert.equal(highlightParts('Error error','error').filter(v=>v.match).length,2)
})
