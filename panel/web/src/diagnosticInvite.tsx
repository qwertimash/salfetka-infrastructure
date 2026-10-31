import { useCallback, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { AccessIntents } from './accessIntent'
import { accessUsers } from './accessApi'
import type { AccessUser } from './accessApi'
import type { Page } from './api'
import { Notice, formatDate } from './components'
import { useResource } from './useResource'
import { uuid } from './constructorModel'

type Receipt = {code:string;tester_id:string;expires_at_ms:number}
export function DiagnosticInvite({api,intents}:{api:ApiClient;intents:AccessIntents}){
 const [cursor,setCursor]=useState(''),[user,setUser]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(),[receipt,setReceipt]=useState<Receipt>(),[copied,setCopied]=useState(false)
 const people=useResource(useCallback(async(signal:AbortSignal)=>accessUsers(await api.request<Page<AccessUser>>(`/access/users?limit=50${cursor?`&cursor=${encodeURIComponent(cursor)}`:''}`,{signal})),[api,cursor]))
 const create=async()=>{
  if(busy||!user)return
  const scope=`diagnostic-invite:${user}`,request=intents.get(scope)??intents.begin(scope,{path:'/diagnostics/invitations',method:'POST',body:{user_id:user},label:'Согласие на диагностику'})
  setBusy(true);setError(undefined);setCopied(false)
  try{
   const value=await api.request<Receipt>(request.path,{method:'POST',body:request.body,headers:{'Idempotency-Key':request.key}})
   if(!value||!/^([0-9a-f]{64})$/.test(value.code)||!uuid.test(value.tester_id)||!Number.isSafeInteger(value.expires_at_ms)||value.expires_at_ms<1)throw new ApiError('invalid_response')
   intents.finish(scope,request.key);setReceipt(value)
  }catch(e){intents.failed(scope,request.key,e);setError(e)}finally{setBusy(false)}
 }
 return <details className="invite-card"><summary>Подключить логи тестера</summary><p>Отправка начинается только после активации кода и отдельного согласия в приложении. Создание кода не включает сбор данных.</p>{people.error!=null&&<Notice error={people.error}/>}{error!=null&&<Notice error={error}/>}
 <label>Пользователь для диагностики<select value={user} disabled={busy||!!receipt} onChange={e=>setUser(e.target.value)}><option value="">Выберите пользователя</option>{people.data?.items.filter(p=>p.state==='active').map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
 {!receipt&&<div className="builder-actions"><button className="button secondary" disabled={!user||busy} onClick={()=>void create()}>{intents.get(`diagnostic-invite:${user}`)?'Повторить выдачу кода':'Создать код диагностики'}</button>{cursor&&<button className="button secondary" disabled={busy} onClick={()=>{setCursor('');setUser('')}}>Первые пользователи</button>}{people.data?.next_cursor&&<button className="button secondary" disabled={busy} onClick={()=>{setCursor(people.data!.next_cursor!);setUser('')}}>Другие пользователи</button>}</div>}
 {receipt&&<div data-private><label>Код диагностики<input value={receipt.code} readOnly onFocus={e=>e.target.select()}/></label><p>Действует до {formatDate(new Date(receipt.expires_at_ms).toISOString())}. Передайте код лично тестеру: в приложении откройте настройки диагностики, введите код и подтвердите согласие. Код не даёт доступ к VPN.</p><div className="builder-actions"><button className="button secondary" onClick={()=>void navigator.clipboard.writeText(receipt.code).then(()=>setCopied(true)).catch(()=>setError(new ApiError('clipboard_unavailable')))}>{copied?'Скопировано':'Копировать код'}</button><button className="button secondary" onClick={()=>setReceipt(undefined)}>Скрыть код</button></div></div>}
 </details>
}
