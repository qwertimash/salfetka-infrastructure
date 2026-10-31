import { useCallback, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { installation } from './vpnApi'
import type { VPNInstallation } from './vpnApi'
import { Notice, formatDate } from './components'
import { useResource } from './useResource'
type Version={revision:number;configuration:VPNInstallation;created_at:string}
export function NodeHistory({api,node}:{api:ApiClient;node:string}){
 const [open,setOpen]=useState(false)
 return <details onToggle={e=>setOpen(e.currentTarget.open)}><summary>Конфиги и история настроек</summary>{open&&<History api={api} node={node}/>}</details>
}
function History({api,node}:{api:ApiClient;node:string}){
 const [before,setBefore]=useState(0),[selected,setSelected]=useState<number>()
 const resource=useResource(useCallback(async(signal:AbortSignal)=>{
  const result=await api.request<{items:Version[]}>(`/servers/${node}/config-history${before?`?before=${before}`:''}`,{signal})
  if(!result||!Array.isArray(result.items)||result.items.length>50)throw new ApiError('invalid_response')
  let prior=before||Number.MAX_SAFE_INTEGER
  for(const row of result.items){if(!Number.isSafeInteger(row.revision)||row.revision<1||row.revision>=prior||!Number.isFinite(Date.parse(row.created_at)))throw new ApiError('invalid_response');installation(row.configuration,node);prior=row.revision}
  return result.items
 },[api,node,before]))
 const index=resource.data?.findIndex(v=>v.revision===selected)??-1,current=resource.data?.[index<0?0:index],previous=resource.data?.[(index<0?0:index)+1]
 return <div className="config-history"><p className="field-hint">Сохранённые параметры установки. Это история запросов панели; фактическое применение проверяется по отдельному отчёту движка. Версии до обновления панели здесь отсутствуют.</p>{resource.error!=null&&<Notice error={resource.error}/>}
 {resource.data?.length===0&&<p>Сохранённых версий пока нет.</p>}
 <div className="builder-actions">{resource.data?.map(v=><button className="button secondary small" key={v.revision} aria-pressed={v===current} onClick={()=>setSelected(v.revision)}>№{v.revision} · {formatDate(v.created_at)}</button>)}</div>
 {current&&<><h4>Настройка №{current.revision}</h4><pre className="config-preview" data-private>{JSON.stringify(current.configuration,null,2)}</pre>{previous&&<details><summary>Сравнить с №{previous.revision}</summary><p>Предыдущие параметры:</p><pre className="config-preview" data-private>{JSON.stringify(previous.configuration,null,2)}</pre></details>}</>}
 <div className="builder-actions">{before>0&&<button className="button secondary" onClick={()=>{setBefore(0);setSelected(undefined)}}>Последние версии</button>}{resource.data?.length===50&&<button className="button secondary" onClick={()=>{setBefore(resource.data!.at(-1)!.revision);setSelected(undefined)}}>Более ранние версии</button>}</div></div>
}
