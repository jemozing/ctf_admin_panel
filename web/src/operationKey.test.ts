import assert from 'node:assert/strict'
import test from 'node:test'
import {createOperationKey} from './operationKey.ts'

test('operation keys work when randomUUID is unavailable on HTTP origins',()=>{
  const original=Object.getOwnPropertyDescriptor(globalThis,'crypto')
  const random=globalThis.crypto
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues:random.getRandomValues.bind(random)}})
  try{
    assert.equal('randomUUID' in crypto,false)
    const keys=Array.from({length:256},()=>createOperationKey())
    assert.equal(new Set(keys).size,keys.length)
    assert.ok(keys.every(key=>/^[a-f0-9]{32}$/.test(key)))
  }finally{
    if(original)Object.defineProperty(globalThis,'crypto',original)
    else Reflect.deleteProperty(globalThis,'crypto')
  }
})
