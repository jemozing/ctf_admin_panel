import {packetFilterQuery,packetQueryString} from './packetTypes.ts'
import type {PacketFilters,PacketQuery} from './packetTypes.ts'

export type VersionBinding={service_id:string;component:string;release_id:string;source_digest:string}
export type FlowMetadata={missing_version_bindings?:boolean;id:string;protocol:string;collector_epoch:string;policy_revision:number;interface:string;if_index:number;observation_points:{interface:string;if_index:number}[];a:{ip:string;port:number};b:{ip:string;port:number};service_id?:string;component?:string;candidates?:{service_id:string;component:string}[];version_bindings?:VersionBinding[];first_at:string;last_at:string;packet_count:number;payload_bytes:number;midstream:boolean;incomplete:boolean;truncated:boolean;closed:boolean;reset:boolean;retransmissions:number;out_of_order:number;conflicting_overlaps:number;reasons:string[]}
export type FlowChunk={offset:number;data:string;packet_ids:string[]}
export type FlowDirection={from:string;start_sequence:number;syn_seen:boolean;fin_seen:boolean;chunks:FlowChunk[];gaps:{offset:number;length:number;reason:string}[];captured_bytes:number;wire_payload_bytes:number;retransmissions:number;out_of_order:number;conflicting_overlaps:number;midstream:boolean;truncated:boolean;incomplete:boolean}
export type FlowDatagram={payload_length_known:boolean;packet_wire_length:number;packet_id:string;from:string;at:string;data:string;wire_length:number;captured_length:number;truncated:boolean}
export type FlowDetail=FlowMetadata&{packet_ids:string[];directions:FlowDirection[];datagrams:FlowDatagram[]}
export type FlowPage={flows:FlowMetadata[];epoch:string;scanned_packets:number;scanned_bytes:number;truncated:boolean;gap:boolean;reasons:string[];query:PacketQuery;snapshot_cursor:string}
export type ProtocolHeader={name:string;value:string}
export type ProtocolMessage={index:number;compressed:boolean;encoding:string;wire_length:number;decoded_length:number;data?:string;type?:string;json?:unknown;error?:string}
export type ProtocolRPC={stream_id:number;path?:string;request_headers:ProtocolHeader[];response_headers:ProtocolHeader[];request_trailers:ProtocolHeader[];response_trailers:ProtocolHeader[];request_messages:ProtocolMessage[];response_messages:ProtocolMessage[];request_ended:boolean;response_ended:boolean;grpc_status?:number;grpc_message?:string;http_status?:number;reset_code?:number;client_streaming?:boolean;server_streaming?:boolean;is_grpc:boolean;incomplete:boolean;errors:string[]}
export type ProtocolResult={protocol:string;status:string;client_direction?:string;rpcs:ProtocolRPC[];frames:number;input_bytes:number;decoded_bytes:number;descriptor_digest?:string;incomplete:boolean;truncated:boolean;reasons:string[]}
export type DescriptorInfo={digest:string;binding:{service_id:string;release_id?:string;source_digest?:string};bytes:number;files:number;methods:{path:string;input_type:string;output_type:string;client_streaming:boolean;server_streaming:boolean}[]}
export type DescriptorView={method_count?:number;id:string;info:DescriptorInfo;created_at:string;confirmed:boolean}
export type DescriptorPreview={confirmed?:boolean;id:string;proposal_id:string;digest:string;info:DescriptorInfo;expires_at:string}
export const flowDisplayBytes=4096
export function flowQuery(filters:PacketFilters,zone:'browser'|'UTC'){return packetQueryString(packetFilterQuery(filters,undefined,zone))}
export function flowDetailRequest(page:FlowPage,flow:FlowMetadata){
  if(!page.flows.some(item=>item.id===flow.id)||!page.query||!flow.id.startsWith('flow-'))throw new Error('Поток больше не относится к выбранному снимку списка.')
  return {query:{...page.query,service_ids:page.query.service_ids?[...page.query.service_ids]:undefined},flow_id:flow.id}
}
export function flowBytes(value?:string,maxBytes=1<<20){
 if(!value)return new Uint8Array()
 if(value.length>Math.ceil(maxBytes/3)*4+4||value.length%4!==0||!/^[A-Za-z0-9+/]*={0,2}$/.test(value))throw new Error('Байты потока превышают допустимый размер или повреждены.')
 let raw:string;try{raw=atob(value)}catch{throw new Error('Повреждённая base64 запись потока.')}
 if(raw.length>maxBytes)throw new Error('Байты потока превышают допустимый размер.')
 return Uint8Array.from(raw,char=>char.charCodeAt(0))
}
export function descriptorBase64(value:ArrayBuffer){
 if(value.byteLength<1||value.byteLength>2*1024*1024)throw new Error('Размер descriptor set должен быть от 1 байта до 2 MiB.')
 const data=new Uint8Array(value);let raw=''
 for(let offset=0;offset<data.length;offset+=8192)raw+=String.fromCharCode(...data.subarray(offset,offset+8192))
 return btoa(raw)
}
export function boundedJSON(value:unknown,maxLength=16384){const text=JSON.stringify(value,null,2)??'';return {text:text.slice(0,maxLength),truncated:text.length>maxLength}}
export const flowReason=(value:string)=>({tcp_prefix_missing:'Начало TCP не наблюдалось',archive_window_incomplete:'Архивное окно неполное',tcp_gap_stopped_decode:'Разбор остановлен на первом пропуске',tls_payload_requires_explicit_termination_or_session_secrets:'TLS остаётся зашифрованным; требуется явно настроенная termination',http2_client_preface_missing:'Начало HTTP/2 не найдено; протокол не угадывается',descriptor_binding_mismatch:'Descriptor не соответствует записанному релизу/исходникам',descriptor_method_not_found:'Метода нет в выбранном descriptor',grpc_status_missing:'Финальный grpc-status не наблюдался',grpc_message_incomplete:'Сообщение gRPC сохранено не полностью',unsupported_grpc_encoding:'Сжатие сообщения не поддерживается',decoded_byte_limit:'Достигнут лимит декодирования',header_output_limit:'Достигнут лимит заголовков декодирования',protobuf_json_resource_limit_or_opaque_any:'Protobuf JSON ограничен по размеру; Any остаётся сырым payload',packet_version_binding_missing:'Для части байтов версия кода не подтверждена',capture_metadata_only:'Сохранялись только метаданные'} as Record<string,string>)[value]||value
