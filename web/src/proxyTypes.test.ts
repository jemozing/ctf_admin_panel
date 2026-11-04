import assert from 'node:assert/strict'
import test from 'node:test'
import {proxyCutoverApplicationEvidence,proxyCutoverGroupEvidence,proxyCutoverGroupRequest,proxyCutoverGroupTargets,proxyCutoverUpdateSettings,proxyCutoverListener,proxyCutoverRoutes,proxyListenAddress,proxyLoopbackListener,proxyRouteChanges,proxyRouteDraft,proxyRouteID,proxyRouteInput,proxyServiceRatePolicy,trafficBytes,trafficHex,trafficQuery,wafBlocks} from './proxyTypes.ts'
import type {ProxyCutoverContainer,ProxyCutoverDraftTarget,ProxyCutoverTargets,ProxyRoute,TrafficBody,TrafficFilters,WafPolicy} from './proxyTypes.ts'

const filters:TrafficFilters={services:[],route:'',from:'',until:'',ip:'',method:'',status:'',url:'',waf:''}
const body:TrafficBody={observed_bytes:0,captured_bytes:0,truncated:false}
const route:ProxyRoute={id:'route-test',service_id:'game',component:'web',listen:'0.0.0.0:18081',upstream:'http://127.0.0.1:18011',protocol:'http1',capture:{mode:'metadata',max_body_bytes:65536,redact_headers:[],redact_query_fields:[],redact_body_fields:[],body_patterns:[]},waf:{mode:'observe_only',rate_per_second:20,burst:40,violation_threshold:10,violation_window_seconds:60,ban_ttl_seconds:60,max_ip_states:4096,state_ttl_seconds:300,overflow_mode:'reject_new',exceptions:[]},limits:{max_concurrent:128,max_header_bytes:65536,read_header_timeout_seconds:5,upstream_response_header_timeout_seconds:30,idle_timeout_seconds:60,max_connection_seconds:300,max_body_bytes:0}}

test('simple rate policy replaces every WAF scope of its service and requires checker verification',()=>{
  const first=proxyRouteInput(route,[])
  const second={...first,id:'route-secondary',listen:'0.0.0.0:18082',waf:{...first.waf,route_specific:true}}
  const other={...first,id:'route-other',service_id:'other'}
  const rate:WafPolicy={...first.waf,mode:'rate_limit',rate_per_second:3}
  const limited=proxyRouteDraft([first,second,other],{...first,waf:rate})
  assert.deepEqual(limited,[{...first,waf:rate},{...second,waf:rate},other])
  assert.equal(proxyServiceRatePolicy(limited,'game'),rate)
  assert.equal(proxyServiceRatePolicy(limited,'other'),undefined)
  assert.equal(wafBlocks(rate.mode),true)
  assert.equal(wafBlocks(first.waf.mode),false)
  assert.deepEqual(proxyRouteDraft(limited,first),[first,{...second,waf:first.waf},other])
})

test('changes to an advanced shared WAF policy preserve per-route overrides',()=>{
  const first=proxyRouteInput(route,[])
  const shared={...first,id:'route-shared'}
  const separate={...first,id:'route-separate',waf:{...first.waf,route_specific:true}}
  const updated={...first,waf:{...first.waf,burst:17}}
  assert.deepEqual(proxyRouteDraft([first,shared,separate],updated),[updated,{...shared,waf:updated.waf},separate])
})

test('traffic query keeps repeated service filters and reserved URL text distinct',()=>{
  const query=new URLSearchParams(trafficQuery({...filters,services:['svc-b','svc-a','svc-a'],ip:'::ffff:192.0.2.1',method:'POST',status:'4xx',url:'/api/?token=x&service_id=wrong',waf:'blocked'},'opaque+/='))
  assert.deepEqual(query.getAll('service_id'),['svc-a','svc-b'])
  assert.equal(query.get('ip'),'::ffff:192.0.2.1')
  assert.equal(query.get('url'),'/api/?token=x&service_id=wrong')
  assert.equal(query.get('cursor'),'opaque+/=')
  assert.equal(query.get('limit'),'50')
})

test('UTC filter dates do not depend on the browser time zone',()=>{
  const query=new URLSearchParams(trafficQuery({...filters,from:'2026-10-30T01:05',until:'2026-10-30T02:05'},undefined,'UTC'))
  assert.equal(query.get('from'),'2026-10-30T01:05:00.000Z')
  assert.equal(query.get('until'),'2026-10-30T02:05:00.000Z')
})

test('unset filters produce a bounded global page without an empty service restriction',()=>{
  assert.equal(trafficQuery(filters),'limit=50')
  assert.equal(new URLSearchParams(trafficQuery({...filters,from:'not a date'})).has('from'),false)
})

test('recorded UTF-8 and base64 bodies preserve binary bytes for hex view',()=>{
  const text='Код <script>alert(1)</script>\u0000'
  assert.equal(new TextDecoder().decode(trafficBytes({...body,encoding:'utf8',data:text})),text)
  assert.deepEqual(Array.from(trafficBytes({...body,encoding:'base64',data:'AP9B'})),[0,255,65])
  assert.equal(trafficHex(Uint8Array.from([0,255,65])),`000000  00 ff 41                                         ..A`)
})

test('body display bounds decoded memory and handles corrupt base64 without throwing',()=>{
  const encoded=Buffer.alloc(100000,65).toString('base64')
  assert.equal(trafficBytes({...body,encoding:'base64',data:encoded}).length,65536)
  assert.equal(trafficBytes({...body,encoding:'utf8',data:'я'.repeat(100000)}).length,65536)
  assert.equal(trafficBytes({...body,encoding:'base64',data:'%invalid%'}).length,0)
})

test('editing a route selects its registered container port rather than its published host port',()=>{
  for(const private_binding of [true,false]){
    const input=proxyRouteInput(route,[{service_id:'game',service_name:'Game',component:'web',upstream_port:4444,upstream_address:'http://127.0.0.1:18011',private_binding}])
    assert.equal(input.upstream_port,4444)
    assert.equal('upstream' in input,false)
  }
  assert.equal(proxyRouteInput(route,[]).upstream_port,0)
  assert.equal(proxyListenAddress('::1',18081),'[::1]:18081')
})

test('direct publication observation requires a literal loopback listener',()=>{
  for(const address of ['127.0.0.1:19081','127.1.2.255:19081','[::1]:19081','[::ffff:127.1.2.3]:19081']){
    assert.equal(proxyLoopbackListener(address),true,address)
  }
  for(const address of ['localhost:19081','127.1:19081','127.0.0.256:19081','127.00.0.1:19081','0.0.0.0:19081','[::]:19081','[::ffff:192.0.2.1]:19081','[::1]:65536','[::1]:0']){
    assert.equal(proxyLoopbackListener(address),false,address)
  }
})

test('editing HTTPS preserves the exact profile and immutable certificate reference',()=>{
  const secure={...route,protocol:'https1' as const,host:'game.ctf.local',tls:{certificate_id:'game-cert-v2'}}
  const input=proxyRouteInput(secure,[{service_id:'game',service_name:'Game',component:'web',upstream_port:4444,upstream_address:route.upstream,private_binding:true}])
  assert.equal(input.protocol,'https1')
  assert.equal(input.host,'game.ctf.local')
  assert.deepEqual(input.tls,{certificate_id:'game-cert-v2'})
  assert.notEqual(input.tls,secure.tls)
  assert.equal(proxyRouteInput(route,[]).tls,undefined)
  assert.deepEqual(proxyRouteChanges([secure],[{...secure,tls:{certificate_id:'game-cert-v3'}}]).map(change=>change.kind),['changed'])
})

test('cutover covers every approved IPv4 and IPv6 binding with shared observe-only settings',()=>{
  const target={service_id:'game',service_name:'Game',component:'web',upstream_port:4444,original_bindings:['0.0.0.0:8080','[::]:8080']}
  const settings={...route,protocol:'https1' as const,tls:{certificate_id:'game-cert-v2'},host:'game.ctf.local',waf:{...route.waf,mode:'enforce' as const}}
  const routes=proxyCutoverRoutes(target,settings,'route-cutover-test')
  assert.deepEqual(routes.map(value=>value.listen),['0.0.0.0:8080','[::]:8080'])
  assert.deepEqual(routes.map(value=>value.upstream_port),[4444,4444])
  assert.ok(routes.every(value=>value.protocol==='https1'&&value.tls?.certificate_id==='game-cert-v2'&&value.waf.mode==='observe_only'))
  assert.ok(routes.every(value=>!('upstream' in value)&&!('initiator' in value)))
  assert.notEqual(routes[0].waf,routes[1].waf)
  assert.notEqual(routes[0].capture,settings.capture)
  assert.equal(proxyCutoverListener('[::1]:8080'),'[::1]:8080')
})

test('cutover cannot silently omit, duplicate, or reinterpret a published binding',()=>{
  const target={service_id:'game',service_name:'Game',component:'web',upstream_port:4444,original_bindings:[] as string[]}
  for(const bindings of [[],['8080/tcp'],['0.0.0.0:8080->4444/udp'],['0.0.0.0:65536'],['localhost:8080'],['0.0.0.0:08080'],['0.0.0.0:8080','0.0.0.0:8080']])assert.throws(()=>proxyCutoverRoutes({...target,original_bindings:bindings},route,'route-test'))
  assert.throws(()=>proxyCutoverRoutes({...target,upstream_port:0,original_bindings:['0.0.0.0:8080']},route,'route-test'))
})

test('missing application recovery requires an explicit flag and one approved baseline',()=>{
  const application:ProxyCutoverContainer={id:'current-app',name:'game-web',project:'game',component:'web',image_id:'sha256:current',state:'running',health:'healthy',ports:['127.0.0.1:20000->4444/tcp'],mounts:[]}
  const dependency={...application,id:'current-db',component:'db'}
  const normal={component:'web',containers:[application,dependency]}
  assert.equal(proxyCutoverApplicationEvidence(normal).canConfirm,true)
  assert.equal(proxyCutoverApplicationEvidence({...normal,containers:[dependency]}).canConfirm,false)
  assert.equal(proxyCutoverApplicationEvidence({...normal,containers:[dependency],recovery_baseline:[application]}).canConfirm,false)
  const recovery=proxyCutoverApplicationEvidence({...normal,containers:[dependency],application_missing:true,recovery_baseline:[application,dependency]})
  assert.equal(recovery.createMissing,true)
  assert.equal(recovery.canConfirm,true)
  assert.equal(recovery.current.length,0)
  assert.equal(recovery.baseline[0].id,'current-app')
  assert.equal(proxyCutoverApplicationEvidence({...normal,containers:[],application_missing:true,recovery_baseline:[dependency]}).canConfirm,false)
  assert.equal(proxyCutoverApplicationEvidence({...normal,containers:[],application_missing:true,recovery_baseline:[application,{...application,id:'ambiguous'}]}).canConfirm,false)
  assert.equal(proxyCutoverApplicationEvidence({...normal,containers:[application,{...application,id:'ambiguous'}]}).canConfirm,false)
})

test('route IDs work on HTTP origins without crypto.randomUUID',()=>{
  const descriptor=Object.getOwnPropertyDescriptor(globalThis,'crypto')
  let usedRandomValues=false
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues:(value:Uint8Array)=>{usedRandomValues=true;value.fill(171);return value}}})
  try{assert.equal(proxyRouteID(),'route-'+'ab'.repeat(16));assert.equal(usedRandomValues,true)}finally{if(descriptor)Object.defineProperty(globalThis,'crypto',descriptor);else Reflect.deleteProperty(globalThis,'crypto')}
})

test('review diff shows removed routes and changed WAF/capture policies as well as additions',()=>{
  const before=[{...route,id:'removed'},route]
  const updated={...route,waf:{...route.waf,mode:'enforce' as const},capture:{...route.capture,mode:'bounded_body' as const}}
  const changes=proxyRouteChanges(before,[updated,{...route,id:'added'}])
  assert.deepEqual(changes.map(value=>[value.id,value.kind]),[['added','added'],['removed','removed'],['route-test','changed']])
  assert.equal(changes[2].before?.waf.mode,'observe_only')
  assert.equal(changes[2].after?.capture.mode,'bounded_body')
  const reordered=Object.fromEntries(Object.entries(route).reverse()) as ProxyRoute
  assert.deepEqual(proxyRouteChanges([route],[reordered]),[])
})


const groupOptions:ProxyCutoverTargets={targets:[
  {service_id:'game',service_name:'Game',component:'api',upstream_port:8080,original_bindings:['0.0.0.0:18080','[::]:18080']},
  {service_id:'game',service_name:'Game',component:'api',upstream_port:8081,original_bindings:['0.0.0.0:18081']},
  {service_id:'game',service_name:'Game',component:'front',upstream_port:3000,original_bindings:['0.0.0.0:18082']}
],unavailable:[],allowed_listen_ips:['0.0.0.0','::'],listen_port_min:18000,listen_port_max:18100,backend_port_min:29080,backend_port_max:29111,max_components:8,max_targets:16,max_listeners:32}
const groupRows=():ProxyCutoverDraftTarget[]=>groupOptions.targets.map((target,index)=>({target:structuredClone(target),privatePort:29080+index,routeIDBase:`group-${index}`,route:{...proxyRouteInput(route,[]),component:target.component,upstream_port:target.upstream_port,waf:structuredClone(route.waf)},hosts:{}}))

test('group maps every component and container TCP port to a distinct private backend without legacy fields',()=>{
  const rows=groupRows()
  rows[0].route.protocol='https1';rows[0].route.tls={certificate_id:'api-cert'}
  rows[0].hosts={'0.0.0.0:18080':'api.example:18080','[::]:18080':'api-v6.example:18080'}
  const request=proxyCutoverGroupRequest({serviceID:'game',targets:rows},groupOptions)
  assert.deepEqual(request.targets,[{component:'api',upstream_port:8080,private_port:29080},{component:'api',upstream_port:8081,private_port:29081},{component:'front',upstream_port:3000,private_port:29082}])
  assert.equal(request.routes.length,4)
  assert.deepEqual(request.routes.map(route=>[route.component,route.upstream_port,route.listen]),[['api',8080,'0.0.0.0:18080'],['api',8080,'[::]:18080'],['api',8081,'0.0.0.0:18081'],['front',3000,'0.0.0.0:18082']])
  assert.deepEqual(request.routes.slice(0,2).map(route=>route.host),['api.example:18080','api-v6.example:18080'])
  for(const field of ['component','upstream_port','private_port','initiator'])assert.equal(field in request,false)
  assert.ok(request.routes.every(route=>route.waf.mode==='observe_only'))
})

test('group refuses missing targets, reused backends, cross-component listener duplication and budget overflow',()=>{
  const rows=groupRows()
  assert.throws(()=>proxyCutoverGroupRequest({serviceID:'game',targets:rows.slice(1)},groupOptions),/пропустить/)
  assert.throws(()=>proxyCutoverGroupRequest({serviceID:'game',targets:[rows[0],{...rows[1],privatePort:rows[0].privatePort},rows[2]]},groupOptions),/уникальный/)
  assert.throws(()=>proxyCutoverGroupRequest({serviceID:'game',targets:[...rows,rows[0]]},groupOptions),/полным/)
  assert.throws(()=>proxyCutoverGroupTargets({...groupOptions,max_components:1},'game'),/размер/)
  assert.throws(()=>proxyCutoverGroupTargets({...groupOptions,max_listeners:3},'game'),/размер/)
  assert.throws(()=>proxyCutoverGroupTargets({...groupOptions,targets:[groupOptions.targets[0],{...groupOptions.targets[2],original_bindings:['0.0.0.0:18080']}]},'game'),/повторяется/)
  rows[0].hosts['0.0.0.0:19000']='unknown.example'
  assert.throws(()=>proxyCutoverGroupRequest({serviceID:'game',targets:rows},groupOptions),/неподтверждённого/)
})

test('changing shared WAF propagates across group while explicit route scopes remain independent',()=>{
  const rows=groupRows();rows[2].route.waf.route_specific=true;rows[2].route.waf.rate_per_second=3
  const updated=proxyCutoverUpdateSettings(rows,0,{...rows[0].route,waf:{...rows[0].route.waf,rate_per_second:7,burst:14}})
  assert.equal(updated[0].route.waf.rate_per_second,7)
  assert.equal(updated[1].route.waf.rate_per_second,7)
  assert.equal(updated[2].route.waf.rate_per_second,3)
  assert.equal(rows[1].route.waf.rate_per_second,20)
  assert.notEqual(updated[0].route.waf,updated[1].route.waf)
  assert.doesNotThrow(()=>proxyCutoverGroupRequest({serviceID:'game',targets:updated},groupOptions))
  const conflicting=groupRows();conflicting[1].route.waf.rate_per_second=1
  assert.throws(()=>proxyCutoverGroupRequest({serviceID:'game',targets:conflicting},groupOptions),/одну политику WAF/)
})

test('group recovery requires explicit missing permission and a unique baseline for every absent app',()=>{
  const container=(component:string,id=component):ProxyCutoverContainer=>({id,name:component,project:'game',component,image_id:'sha256:'+component,state:'running',health:'healthy',ports:[],mounts:[]})
  const api=container('api'),front=container('front'),db=container('db')
  const preview={component:'',components:['api','front'],containers:[db],recovery_baseline:[api,front,db],missing_applications:['api','front']}
  const missing=proxyCutoverGroupEvidence(preview)
  assert.equal(missing.canConfirm,true)
  assert.ok(missing.items.every(item=>item.createMissing))
  assert.equal(missing.other[0].component,'db')
  assert.equal(proxyCutoverGroupEvidence({...preview,missing_applications:['api']}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({...preview,recovery_baseline:[api,front,container('front','duplicate')]}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({...preview,containers:[api,db]}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({...preview,components:['api','api']}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({...preview,missing_applications:['api','front','db']}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({...preview,components:['api'],targets:[{component:'front',upstream_port:80,private_port:29080,original_bindings:['0.0.0.0:8080'],private_binding:'127.0.0.1:29080'}]}).canConfirm,false)
  assert.equal(proxyCutoverGroupEvidence({component:'api',containers:[api,db]}).canConfirm,true)
  assert.equal(proxyCutoverGroupEvidence({component:'api',containers:[db],application_missing:true,recovery_baseline:[api]}).canConfirm,true)
})

test('HTTPS2 cutover keeps explicit certificate and opaque gRPC capture policy',()=>{
  const target={service_id:'game',service_name:'Game',component:'web',upstream_port:4444,original_bindings:['0.0.0.0:8080']}
  const settings={...route,protocol:'https2' as const,tls:{certificate_id:'h2-cert'},host:'game.ctf.local',capture:{...route.capture,mode:'grpc_body' as const}}
  const built=proxyCutoverRoutes(target,settings,'route-h2')
  assert.ok(built.every(value=>value.protocol==='https2'&&value.tls?.certificate_id==='h2-cert'&&value.capture.mode==='grpc_body'))
})
