// randomUUID requires a secure context; getRandomValues also works over HTTP.
// This key deduplicates one operation request and is not an authentication token.
export function createOperationKey():string{
  return Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('')
}
