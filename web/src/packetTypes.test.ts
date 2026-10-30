import assert from 'node:assert/strict'
import test from 'node:test'
import {initialPacketFilters,maxPacketBytes,maxPCAPBytes,packetAddress,packetBytes,packetCaptureSelection,packetCaptureState,packetDirection,packetExportRequest,packetFilterQuery,packetFlags,packetHex,packetQueryString} from './packetTypes.ts'
import type {PacketCaptureStatus,PacketCaptureTargets} from './packetTypes.ts'

test('packet filters keep multiple services and reserved IPv6/cursor text intact',()=>{
  const filters={...initialPacketFilters,services:['beta','alpha','beta'],component:'tcp/app',protocol:'tcp',ip:'2001:db8::/32',sourcePort:'443',destinationPort:'40000',direction:'ingress'}
  const query=packetFilterQuery(filters,'cursor+/=','UTC'),params=new URLSearchParams(packetQueryString(query))
  assert.deepEqual(params.getAll('service_id'),['alpha','beta'])
  assert.equal(params.get('component'),'tcp/app')
  assert.equal(params.get('ip'),'2001:db8::/32')
  assert.equal(params.get('cursor'),'cursor+/=')
  assert.equal(params.get('limit'),'50')
  assert.equal(params.get('source_port'),'443')
  assert.equal(params.get('destination_port'),'40000')
  assert.equal(params.get('direction'),'ingress')
  assert.equal('services' in query,false)
})

test('packet filters reject invalid ports and reversed dates before requests',()=>{
  for(const value of ['0','65536','1.5','-1','443&service_id=other'])assert.throws(()=>packetFilterQuery({...initialPacketFilters,sourcePort:value}),/Порт/)
  assert.throws(()=>packetFilterQuery({...initialPacketFilters,from:'not-a-date'}),/дату/)
  assert.throws(()=>packetFilterQuery({...initialPacketFilters,from:'2026-02-31T12:00'},undefined,'UTC'),/существующую/)
  assert.throws(()=>packetFilterQuery({...initialPacketFilters,from:'2026-10-30T12:01',until:'2026-10-30T12:00'},undefined,'UTC'),/Начало/)
  assert.equal(packetFilterQuery({...initialPacketFilters,from:'2026-10-30T12:00:01'},undefined,'UTC').from,'2026-10-30T12:00:01.000Z')
})

test('PCAP export requires a finite confirmed interval and independent byte/packet bounds',()=>{
  const filters={...initialPacketFilters,services:['game'],from:'2026-10-30T12:00',until:'2026-10-30T13:00'}
  assert.throws(()=>packetExportRequest(initialPacketFilters,1000,1048576,'UTC'),/начало и конец/)
  assert.throws(()=>packetExportRequest({...filters,until:'2026-10-30T13:00:01'},1000,1048576,'UTC'),/60 минут/)
  for(const count of [0,10001,NaN,1.5])assert.throws(()=>packetExportRequest(filters,count,1048576,'UTC'),/пакетов/)
  for(const size of [0,23,maxPCAPBytes+1,NaN])assert.throws(()=>packetExportRequest(filters,1000,size,'UTC'),/PCAP/)
  const exportRequest=packetExportRequest(filters,10000,maxPCAPBytes,'UTC')
  assert.deepEqual(exportRequest.query.service_ids,['game'])
  assert.equal(exportRequest.query.cursor,undefined)
  assert.equal(exportRequest.max_packets,10000)
  assert.equal(exportRequest.max_bytes,maxPCAPBytes)
})

test('binary packet display never decodes controls or interprets application bytes',()=>{
  const raw=packetBytes(Buffer.from([0,0xff,0x1b,0x3c,0x41,0x7f]).toString('base64'))
  assert.deepEqual(Array.from(raw),[0,255,27,60,65,127])
  assert.equal(packetHex(raw),'000000  00 ff 1b 3c 41 7f                                ...<A.')
  assert.equal(packetHex(raw).includes('\x1b'),false)
  assert.equal(packetBytes('%%%').length,0)
  assert.equal(packetBytes().length,0)
})

test('packet decoding and hex output stay bounded even for oversized server data',()=>{
  const data=Buffer.alloc(maxPacketBytes+10000,65).toString('base64')
  assert.equal(packetBytes(data).length,maxPacketBytes)
  const hex=packetHex(new Uint8Array(maxPacketBytes+10000).fill(65))
  assert.equal(hex.split('\n').length,Math.ceil(maxPacketBytes/16))
  assert.equal(hex.split('\n').at(-1)?.startsWith('00fff0'),true)
})

test('IPv6 endpoints, TCP flags and service-relative direction are unambiguous',()=>{
  assert.equal(packetAddress('2001:db8::1',443),'[2001:db8::1]:443')
  assert.equal(packetAddress('192.0.2.1',53),'192.0.2.1:53')
  assert.equal(packetFlags(0x12),'SYN · ACK')
  assert.equal(packetFlags(0),'—')
  assert.equal(packetDirection('ingress'),'К сервису')
  assert.equal(packetDirection('egress'),'От сервиса')
})

test('capture preview selection rejects stale targets and unapproved observation points',()=>{
  const targets:PacketCaptureTargets={allowed_interfaces:['br-approved'],unavailable:[],targets:[{id:'frozen-runtime-target',service_id:'game',service_name:'Game',component:'app',protocol:'udp',target_port:9000,interface:'br-approved',if_index:5,addresses:['172.20.0.2'],point:'container_bridge'}]}
  assert.equal(packetCaptureSelection(targets,['frozen-runtime-target'])[0].component,'app')
  assert.throws(()=>packetCaptureSelection(targets,['target-before-deploy']),/изменились/)
  assert.throws(()=>packetCaptureSelection(targets,['frozen-runtime-target','frozen-runtime-target']),/несколько раз/)
  assert.throws(()=>packetCaptureSelection({...targets,allowed_interfaces:[]},['frozen-runtime-target']),/разрешённой/)
  assert.throws(()=>packetCaptureSelection({...targets,targets:[{...targets.targets[0],point:'host' as 'container_bridge'}]},['frozen-runtime-target']),/разрешённой/)
})

test('enabled policy cannot imply active capture after lease loss or pause',()=>{
  const capture={available:true,enabled:true,running:false,paused:false,lease_expired:true} as PacketCaptureStatus
  assert.match(packetCaptureState({configured:true,capture}),/срок подтверждения.*истёк/)
  assert.match(packetCaptureState({configured:true,capture:{...capture,paused:true}}),/приостановлен/)
  assert.equal(packetCaptureState({configured:true,capture:{...capture,lease_expired:false,running:true}}),'Пассивный захват работает.')
  assert.match(packetCaptureState({configured:true,capture:{...capture,available:false}}),/недоступен/)
})

test('both selected endpoints keep an explicit ambiguous direction',()=>{
  assert.equal(packetDirection('ambiguous'),'Неоднозначно (оба конца выбраны)')
  const query=packetFilterQuery({...initialPacketFilters,direction:'ambiguous'})
  assert.equal(new URLSearchParams(packetQueryString(query)).get('direction'),'ambiguous')
})
