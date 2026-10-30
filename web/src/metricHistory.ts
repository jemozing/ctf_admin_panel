export type MetricPoint = {at:string;value:number|null;identity?:string}
export type ChartPoint = {x:number;y:number}
type NetworkSample = {at:string;source:string;uptime_seconds:number|null;network_rx_bytes:number|null;network_tx_bytes:number|null}

export function historyWindow<T extends {at:string}>(history:readonly T[],minutes:number,now:number):T[]{
  const start=now-minutes*60_000
  return history.filter(sample=>{const at=Date.parse(sample.at);return Number.isFinite(at)&&at>=start&&at<=now})
}

// A missed observation, clock jump, or changed container must remain visible as
// a gap. Unknown measurements are never plotted as zero.
export function metricSegments(points:readonly MetricPoint[],start:number,end:number,maximum:number,intervalSeconds:number):ChartPoint[][]{
  const segments:ChartPoint[][]=[]
  let segment:ChartPoint[]=[],previousAt:number|undefined,previousIdentity:string|undefined
  const finish=()=>{if(segment.length)segments.push(segment);segment=[]}
  for(const point of points){
    const at=Date.parse(point.at)
    if(!Number.isFinite(at)||at<start||at>end||point.value===null||!Number.isFinite(point.value)||point.value<0){finish();previousAt=undefined;previousIdentity=undefined;continue}
    if(previousAt!==undefined&&(at<=previousAt||at-previousAt>Math.max(1,intervalSeconds)*1800||point.identity!==previousIdentity))finish()
    segment.push({x:10+(at-start)/Math.max(1,end-start)*580,y:90-point.value/maximum*76})
    previousAt=at;previousIdentity=point.identity
  }
  finish()
  return segments
}

export function duration(seconds:number|null){
  if(seconds===null||!Number.isFinite(seconds)||seconds<0)return '—'
  const minutes=Math.floor(seconds/60),hours=Math.floor(minutes/60),days=Math.floor(hours/24)
  return days?`${days} д ${hours%24} ч`:hours?`${hours} ч ${minutes%60} мин`:`${minutes} мин`
}

export function networkRates(history:readonly NetworkSample[],field:'network_rx_bytes'|'network_tx_bytes',interval:number):MetricPoint[]{
  return history.map((sample,index)=>{
    const previous=history[index-1],elapsed=previous?(Date.parse(sample.at)-Date.parse(previous.at))/1000:0,current=sample[field],before=previous?.[field]
    const continuous=previous&&elapsed>0&&elapsed<=interval*1.8&&sample.source===previous.source&&sample.uptime_seconds!==null&&previous.uptime_seconds!==null&&sample.uptime_seconds>=previous.uptime_seconds
    return {at:sample.at,identity:sample.source,value:continuous&&current!==null&&before!==null&&before!==undefined&&current>=before?(current-before)/elapsed:null}
  })
}
