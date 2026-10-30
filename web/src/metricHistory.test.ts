/// <reference types="node" />
import assert from 'node:assert/strict'
import {test} from 'node:test'
import {duration,historyWindow,metricSegments,networkRates} from './metricHistory.ts'

const origin=Date.parse('2026-10-19T00:00:00Z')
const point=(seconds:number,value:number|null=1,identity='first')=>({at:new Date(origin+seconds*1000).toISOString(),value,identity})
const plot=(points:ReturnType<typeof point>[])=>metricSegments(points,origin,origin+60_000,10,5)

test('chart preserves missing samples, collection gaps, and replacement boundaries',()=>{
  assert.deepEqual(plot([point(0),point(5),point(10)]).map(segment=>segment.length),[3])
  assert.deepEqual(plot([point(0),point(5,null),point(10)]).map(segment=>segment.length),[1,1])
  assert.deepEqual(plot([point(0),point(5),point(20)]).map(segment=>segment.length),[2,1])
  assert.deepEqual(plot([point(0),point(5,1,'replacement')]).map(segment=>segment.length),[1,1])
  assert.deepEqual(plot([point(0),point(0),point(5)]).map(segment=>segment.length),[1,2])
})

test('zero is an observation, while invalid values are missing',()=>{
  assert.deepEqual(plot([point(0,0),point(5,0)]).map(segment=>segment.length),[2])
  assert.deepEqual(plot([point(0,NaN),point(5,Infinity),point(10,-1)]),[])
})

test('history window does not invent old measurements or include future observations',()=>{
  assert.equal(historyWindow([point(-901),point(-900),point(0),point(1)],15,origin).length,2)
  assert.equal(historyWindow([point(-3601),point(-3600),point(0),point(1)],60,origin).length,2)
})

test('network rate requires continuous observations and monotonic counters and uptime',()=>{
  const sample=(seconds:number,bytes:number|null,uptime=100+seconds)=>({at:point(seconds).at,source:'approved',uptime_seconds:uptime,network_rx_bytes:bytes,network_tx_bytes:bytes})
  assert.deepEqual(networkRates([sample(0,100),sample(5,150),sample(10,150)],'network_rx_bytes',5).map(point=>point.value),[null,10,0])
  assert.deepEqual(networkRates([sample(0,100),sample(5,50),sample(10,100,1),sample(30,150)],'network_rx_bytes',5).map(point=>point.value),[null,null,null,null])
  assert.deepEqual(networkRates([sample(0,null),sample(5,50),sample(10,null)],'network_rx_bytes',5).map(point=>point.value),[null,null,null])
})

test('uptime formats days and leaves missing evidence absent',()=>{
  assert.equal(duration(90061),'1 д 1 ч')
  assert.equal(duration(null),'—')
})
