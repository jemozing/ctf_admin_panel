import type {ButtonHTMLAttributes,ReactNode} from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import {X,LoaderCircle} from 'lucide-react'

export function Button({variant='default',busy=false,className='',children,...props}:ButtonHTMLAttributes<HTMLButtonElement>&{variant?:'default'|'outline'|'ghost'|'danger';busy?:boolean}){
  return <button className={`button button-${variant} ${className}`} {...props} disabled={props.disabled||busy}>{busy&&<LoaderCircle size={15} className="spin"/>}{children}</button>
}
export function Badge({tone='neutral',children}:{tone?:'neutral'|'good'|'warn'|'bad';children:ReactNode}){return <span className={`badge badge-${tone}`}>{children}</span>}
export function Empty({icon,children}:{icon?:ReactNode;children:ReactNode}){return <div className="empty">{icon}{children}</div>}
export function Notice({children,variant='info'}:{children:ReactNode;variant?:'info'|'error'|'warning'}){return <div className={`notice notice-${variant}`} role={variant==='error'?'alert':undefined}>{children}</div>}
export function Modal({open,onClose,title,description,children,wide=false}:{open:boolean;onClose:()=>void;title:string;description?:string;children:ReactNode;wide?:boolean}){
  return <Dialog.Root open={open} onOpenChange={v=>!v&&onClose()}><Dialog.Portal><Dialog.Overlay className="dialog-overlay"/><Dialog.Content className={`dialog ${wide?'dialog-wide':''}`} aria-describedby={description?'dialog-description':undefined}>
    <div className="dialog-header"><div><Dialog.Title>{title}</Dialog.Title>{description&&<Dialog.Description id="dialog-description">{description}</Dialog.Description>}</div><Dialog.Close asChild><Button variant="ghost" aria-label="Закрыть"><X size={18}/></Button></Dialog.Close></div>{children}
  </Dialog.Content></Dialog.Portal></Dialog.Root>
}
