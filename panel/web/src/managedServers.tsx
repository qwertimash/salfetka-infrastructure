import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { NodeIntents } from './nodeIntent'
import { enrollment, node, type Node, type Enrollment } from './nodeApi'
import { Nodes } from './nodes'
import { Empty, Notice, PageHeading, Freshness } from './components'
import { Modal } from './modal'
import { useResource } from './useResource'
import { NodeInstallCode } from './nodeInstallCode'
import type { AccessRequest } from './accessIntent'

export type ConnectionSpec = {template:string;version:number;host:string;listen_ip:string;port:number;server_name:string;service_name?:string;path?:string;reality_target?:string;reality_public_key?:string;reality_short_id?:string}
type Template = {id:string;name:string;version:number;network:string;default_port:number;tls_certificate:boolean}
type Connection = {id:string;name:string;revision:number;runtime_state:string;error_code?:string;vpn:{node_revision:number;installation_id:string;group_id:string;enabled:boolean;endpoint:{connection:ConnectionSpec;trusted_ca_pem?:string}};traffic:{state:string}}
type Server = {node:Node|null;legacy:boolean;connections:Connection[]}
const group='00000000-0000-4000-8000-000000000001'
const status:Record<string,string>={pending:'Ожидает ноду',listening:'Порт запущен',disabled:'Отключено',failed:'Ошибка применения'}
function download(name:string,body:unknown){const url=URL.createObjectURL(new Blob([JSON.stringify(body,null,2)+'\n'],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
function validate(value:Server){if(!value||!Array.isArray(value.connections)||typeof value.legacy!=='boolean')throw new ApiError('invalid_response');if(value.node)node(value.node);for(const c of value.connections){if(!c.id||!c.vpn?.endpoint?.connection||!Number.isSafeInteger(c.revision)||!status[c.runtime_state])throw new ApiError('invalid_response')}return value}

export function ManagedServerView({api,intents,canWrite,id,name,address='',domain=''}:{api:ApiClient;intents:NodeIntents;canWrite:boolean;id:string;name:string;address?:string;domain?:string}){
 const resource=useResource(useCallback(async(signal:AbortSignal)=>validate(await api.request<Server>(`/managed/servers/${id}`,{signal})),[api,id]),5000)
 const [adding,setAdding]=useState(false),[editing,setEditing]=useState<Connection>(),[error,setError]=useState<unknown>(),[busy,setBusy]=useState(false),[secret,setSecret]=useState<Enrollment>(),[revoking,setRevoking]=useState<{id:string;revision:number}>()
 const alive=useRef(true);useEffect(()=>{alive.current=true;return()=>{alive.current=false}},[])
 const data=resource.data,n=data?.node
 const scope=`managed-server:${id}`
 const run=async(request:AccessRequest)=>{
  if(!canWrite||intents.busy.has(scope))return
  const pending=intents.get(scope)??intents.begin(scope,request);intents.busy.add(scope);setBusy(true);setError(undefined)
  try{const result=await api.request(pending.path,{method:pending.method,body:pending.body,headers:{'Idempotency-Key':pending.key,...(pending.revision?{'If-Match':`"${pending.revision}"`}:{})}})
   if(pending.path.endsWith('/enrollment')&&n){const e=enrollment(result as {node:Node;enrollment:Enrollment},n.id);intents.saveSecret(e);if(alive.current)setSecret(e)}
   if(pending.path.endsWith('/revoke')){
    const revoked=node(result as Node,pending.path.split('/')[2]);if(revoked.state!=='revoked')throw new ApiError('invalid_response')
    intents.forgetSecret(revoked.id);if(alive.current){setSecret(undefined);setRevoking(undefined)}
   }
   intents.finish(scope,pending.key);if(alive.current)resource.refresh()
  }catch(e){intents.failed(scope,pending.key,e);if(alive.current){setError(e);if(e instanceof ApiError&&e.status===412)resource.refresh()}}finally{intents.busy.delete(scope);if(alive.current)setBusy(false)}
 }
 if(data?.legacy)return <><p className="section-description">На этом сервере используются прежние отдельные агенты. Автоматический перенос не выполняется.</p><Nodes api={api} canWrite={canWrite} intents={intents} serverID={id} serverName={name}/></>
 const saved=secret??(n?intents.secret(n.id):undefined),pending=intents.get(scope)
 return <><PageHeading eyebrow="ОДНА НОДА · НЕСКОЛЬКО ПОДКЛЮЧЕНИЙ" title={name} action={canWrite&&n&&n.state!=='revoked'&&<button className="button primary" onClick={()=>setAdding(true)}>Добавить подключения</button>}>Установите ноду один раз. Подключения, порты и конфиги меняются здесь; состав пользовательских подписок — в разделе «Подписки».</PageHeading>
 <Freshness resource={resource}/>{resource.error!=null&&<Notice error={resource.error}/>} {error!=null&&!revoking&&<Notice error={error}/>}
 {canWrite&&pending&&!revoking&&<button disabled={busy} className="button secondary" onClick={()=>void run(pending)}>Повторить: {pending.label}</button>}
 {data&&!n&&<section className="card managed-card"><h3>1. Подключите сервер</h3><p>Одна регистрация и одна служба для всех подключений на этой машине.</p>{canWrite&&<button disabled={busy||!!pending} className="button primary" onClick={()=>void run({path:`/managed/servers/${id}/node`,method:'POST',body:{},label:'Зарегистрировать ноду'})}>Зарегистрировать ноду</button>}</section>}
 {n&&<section className="card managed-card"><div className="access-section-heading"><h3>Нода сервера</h3><span className={`badge ${n.contact_state==='fresh'?'good':'neutral'}`}>{n.state==='revoked'?'Доступ отозван':n.contact_state==='fresh'?'На связи':n.state==='pending'?'Нужна установка':'Нет свежего отчёта'}</span></div><p>{n.inventory?`${n.inventory.platform} · ${n.inventory.arch} · ${n.inventory.version}`:'Получите приглашение и выберите «Нода» в установщике на сервере.'}</p>{canWrite&&n.state==='pending'&&<button disabled={busy||!!pending} className="button secondary" onClick={()=>void run({path:`/nodes/${n.id}/enrollment`,method:'POST',body:{},revision:n.revision,label:'Приглашение ноды'})}>Создать приглашение</button>}{canWrite&&n.state!=='revoked'&&<button disabled={busy||!!pending||resource.loading||!!resource.error} className="button secondary" onClick={()=>{setError(undefined);setRevoking({id:n.id,revision:n.revision})}}>Отозвать доступ ноды</button>}{saved&&n.state==='pending'&&Date.parse(saved.expires_at)>Date.now()&&<div className="notice"><NodeInstallCode api={api} invitation={saved}/><p>Код установки действует 10 минут — только для первого подключения. Установленная нода не отключится по истечении этого времени. Передайте код только на этот сервер.</p><label>Node ID<input readOnly value={saved.node_id}/></label><label>Одноразовый токен<input readOnly type="password" value={saved.token} autoComplete="off"/></label><button className="button secondary" onClick={()=>download(`node-${n.id}-enrollment.json`,saved)}>Скачать приглашение</button></div>}</section>}
 {data&&n&&n.state!=='revoked'&&data.connections.length===0&&<Empty title="2. Выберите способы подключения">TCP Reality, Hysteria2, gRPC и XHTTP можно добавить сразу. Мастер предложит порты и запросит нужные сертификаты.</Empty>}
 <div className="server-cards">{data?.connections.map(c=><section key={c.id} className="card managed-card"><div className="access-section-heading"><h3>{c.name}</h3><span className={`badge ${c.runtime_state==='failed'?'bad':'neutral'}`}>{status[c.runtime_state]}</span></div><p>{c.vpn.endpoint.connection.host}:{c.vpn.endpoint.connection.port} · {c.vpn.endpoint.connection.template==='hysteria2'?'UDP':'TCP'}</p><p className="field-hint">Версия {c.revision}. {c.traffic.state==='applied'?'Нода подтвердила политику доступа.':'Подтверждение политики доступа ожидается.'} Внешняя доступность проверяется отдельно.</p>{c.error_code&&<p role="alert">Не удалось применить подключение. Проверьте порт, сертификат и журнал ноды.</p>}{canWrite&&<button className="button secondary" onClick={()=>setEditing(c)}>Настроить</button>}</section>)}</div>
 {canWrite&&revoking&&<Modal title="Отозвать доступ ноды?" close={()=>{if(!busy)setRevoking(undefined)}}>
 <p>Нода и все подключения этого сервера потеряют доступ к панели. Соединения завершатся после обработки отзыва агентом или истечения разрешения на работу. Отзыв нельзя отменить.</p>
 {error!=null&&<Notice error={error}/>}{n&&n.revision!==revoking.revision&&<Notice kind="info">Запись изменилась после открытия подтверждения. Закройте окно и проверьте актуальное состояние перед новым действием.</Notice>}
 <div className="form-actions"><button className="button secondary" disabled={busy} onClick={()=>setRevoking(undefined)}>Отмена</button><button className="button primary" disabled={busy} onClick={()=>void run({path:`/nodes/${revoking.id}/revoke`,method:'POST',body:{},revision:revoking.revision,label:'Отозвать доступ ноды'})}>{pending?'Повторить отзыв ноды':'Подтвердить отзыв ноды'}</button></div>
 </Modal>}
 {adding&&n&&<Modal title="Подключения из шаблонов" close={()=>setAdding(false)}><TemplateForm api={api} intents={intents} node={n} address={address} domain={domain} done={()=>{setAdding(false);resource.refresh()}}/></Modal>}
 {editing&&<Modal title={`Настройки · ${editing.name}`} close={()=>setEditing(undefined)}><ConnectionEditor api={api} intents={intents} value={editing} done={()=>{setEditing(undefined);resource.refresh()}}/></Modal>}
 </>
}
function useSave(api:ApiClient,intents:NodeIntents,scope:string,done:()=>void){
 const[busy,setBusy]=useState(false),[error,setError]=useState<unknown>();const alive=useRef(true);useEffect(()=>{alive.current=true;return()=>{alive.current=false}},[])
 const save=async(request:AccessRequest)=>{if(intents.busy.has(scope))return;const p=intents.get(scope)??intents.begin(scope,request);intents.busy.add(scope);setBusy(true);setError(undefined)
  try{await api.request(p.path,{method:p.method,body:p.body,headers:{'Idempotency-Key':p.key,...(p.revision?{'If-Match':`"${p.revision}"`}:{})}});intents.finish(scope,p.key);if(alive.current)done()}
  catch(e){intents.failed(scope,p.key,e);if(alive.current)setError(e)}finally{intents.busy.delete(scope);if(alive.current)setBusy(false)}
 };return {save,busy,error,pending:intents.get(scope)}
}
function TLSFields({cert,keyValue,onCert,onKey}:{cert:string;keyValue:string;onCert:(s:string)=>void;onKey:(s:string)=>void}){
 return <details open><summary>TLS-сертификат для выбранного домена</summary><p className="field-hint">PEM-сертификат с цепочкой и его приватный ключ. Ключ хранится зашифрованным и передаётся только ноде.</p><label>Сертификат PEM<textarea required value={cert} onChange={e=>onCert(e.target.value)} rows={3} autoComplete="off" spellCheck={false}/></label><label>Приватный ключ PEM<textarea required value={keyValue} onChange={e=>onKey(e.target.value)} rows={3} autoComplete="off" spellCheck={false}/></label></details>
}
function TemplateForm({api,intents,node:n,address,domain,done}:{api:ApiClient;intents:NodeIntents;node:Node;address:string;domain:string;done:()=>void}){
 const templates=useResource(useCallback((signal:AbortSignal)=>api.request<{items:Template[]}>('/managed/templates',{signal}),[api]),0)
 const[chosen,setChosen]=useState<string[]>([]),[ports,setPorts]=useState<Record<string,string>>({}),[host,setHost]=useState(address),[sni,setSni]=useState(domain),[listen,setListen]=useState('0.0.0.0'),[target,setTarget]=useState(''),[realitySNI,setRealitySNI]=useState(domain),[cert,setCert]=useState(''),[key,setKey]=useState('')
 const {save,busy,error,pending}=useSave(api,intents,`managed-create:${n.id}`,done)
 const needTLS=templates.data?.items.some(t=>chosen.includes(t.id)&&t.tls_certificate)
 const submit=()=>void save({path:`/managed/nodes/${n.id}/connections`,method:'POST',revision:n.revision,label:'Создать подключения',body:{connections:templates.data?.items.filter(t=>chosen.includes(t.id)).map(t=>({name:t.name,group_id:group,enabled:true,configuration:{public:{template:t.id,version:t.version,host:host.trim(),listen_ip:listen,port:ports[t.id]?Number(ports[t.id]):0,server_name:t.id==='vless-tcp-reality'?realitySNI.trim():sni.trim(),...(t.id==='vless-tcp-reality'?{reality_target:target.trim()}:{}),...(t.id==='vless-grpc-tls'?{service_name:'vpn'}:{}),...(t.id==='vless-xhttp-tls'?{path:'/vpn'}:{})},private:t.tls_certificate?{certificate_pem:cert,key_pem:key}:{}}}))}})
 return <form onSubmit={e=>{e.preventDefault();submit()}}>{error!=null&&<Notice error={error}/>} {templates.error!=null&&<Notice error={templates.error}/>}<fieldset disabled={busy||!!pending}>
 <p>Отметьте нужные протоколы. Пустой порт — автоматический выбор свободного порта из каталога панели; нода дополнительно проверит его при запуске.</p>
 {templates.data?.items.map(t=><div className="managed-template-row" key={t.id}><label className="managed-template-choice"><input type="checkbox" checked={chosen.includes(t.id)} onChange={e=>setChosen(e.target.checked?[...chosen,t.id]:chosen.filter(x=>x!==t.id))}/>{t.name} · {t.network.toUpperCase()}</label>{chosen.includes(t.id)&&<label className="managed-template-port">Порт {t.name}<input type="number" min={1} max={65535} placeholder={`Авто, от ${t.default_port}`} value={ports[t.id]??''} onChange={e=>setPorts({...ports,[t.id]:e.target.value})}/></label>}</div>)}
 <label>Публичный адрес сервера<input required value={host} onChange={e=>setHost(e.target.value)} placeholder="vpn.example.com или IP"/></label>{needTLS&&<label>Домен TLS-сертификата<input required value={sni} onChange={e=>setSni(e.target.value)} placeholder="vpn.example.com"/></label>}
 {chosen.includes('vless-tcp-reality')&&<><label>Reality SNI<input required value={realitySNI} onChange={e=>setRealitySNI(e.target.value)} placeholder="Имя сертификата целевого сервера"/></label><label>Reality: целевой TLS-сервер<input required value={target} onChange={e=>setTarget(e.target.value)} placeholder="target.example.com:443"/></label></>}
 {needTLS&&<TLSFields cert={cert} keyValue={key} onCert={setCert} onKey={setKey}/>}
 <details><summary>Дополнительные параметры</summary><label>Адрес прослушивания<input required value={listen} onChange={e=>setListen(e.target.value)}/></label><p>Ключи Reality создаются автоматически. gRPC service: vpn; XHTTP path: /vpn. После создания их можно изменить в настройках подключения.</p></details>
 </fieldset><p className="field-hint">Создание применит конфиги на ноде. Firewall не изменяется. Добавление пользователям — после включения подключений в подписку и публикации.</p><button type={pending?'button':'submit'} onClick={pending?submit:undefined} disabled={busy||(!pending&&!chosen.length)} className="button primary">{pending?'Повторить тот же запрос':'Создать и применить'}</button></form>
}
function ConnectionEditor({api,intents,value:c,done}:{api:ApiClient;intents:NodeIntents;value:Connection;done:()=>void}){
 const[spec,setSpec]=useState({...c.vpn.endpoint.connection}),[name,setName]=useState(c.name),[enabled,setEnabled]=useState(c.vpn.enabled),[replace,setReplace]=useState(false),[cert,setCert]=useState(''),[key,setKey]=useState('')
 const history=useResource(useCallback((signal:AbortSignal)=>api.request<{revision:number;public:ConnectionSpec;created_at:string}[]>(`/managed/connections/${c.id}/history`,{signal}),[api,c.id]),0)
 const{save,busy,error,pending}=useSave(api,intents,`managed-edit:${c.id}`,done)
 const request=(body:unknown):AccessRequest=>({path:`/managed/connections/${c.id}`,method:'POST',revision:c.vpn.node_revision,label:'Применить настройки',body})
 const submit=()=>void save(request({request:{name,enabled,group_id:c.vpn.group_id,trusted_ca_pem:c.vpn.endpoint.trusted_ca_pem??'',configuration:{public:spec,private:replace?{certificate_pem:cert,key_pem:key}:{}}},replace_private:replace}))
 const field=(key:keyof ConnectionSpec,label:string)=> <label>{label}<input required value={String(spec[key]??'')} onChange={e=>setSpec({...spec,[key]:e.target.value})}/></label>
 return <form onSubmit={e=>{e.preventDefault();submit()}}>{error!=null&&<Notice error={error}/>}<fieldset disabled={busy||!!pending}><label>Название<input required minLength={2} maxLength={80} value={name} onChange={e=>setName(e.target.value)}/></label><label><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/>Включено</label>{field('host','Публичный адрес')}{field('listen_ip','Адрес прослушивания')}<label>Порт<input type="number" required min={1} max={65535} value={spec.port} onChange={e=>setSpec({...spec,port:Number(e.target.value)})}/></label>{field('server_name','TLS / SNI')}{spec.template==='vless-tcp-reality'&&field('reality_target','Reality target')}{spec.template==='vless-grpc-tls'&&field('service_name','gRPC service')}{spec.template==='vless-xhttp-tls'&&field('path','XHTTP path')}{spec.template!=='vless-tcp-reality'&&<><label><input type="checkbox" checked={replace} onChange={e=>setReplace(e.target.checked)}/>Заменить сертификат и ключ</label>{replace&&<TLSFields cert={cert} keyValue={key} onCert={setCert} onKey={setKey}/>}</>}
 </fieldset><p className="notice">Применение перезапустит только это подключение и оборвёт его текущие сессии. Остальные подключения продолжат работать. Затем опубликуйте обновлённые подписки.</p><button className="button primary" type={pending?'button':'submit'} onClick={pending?submit:undefined} disabled={busy}>{pending?'Повторить тот же запрос':'Применить настройки'}</button>
 <details><summary>Параметры подключения · JSON</summary><pre>{JSON.stringify(spec,null,2)}</pre><p>Приватные ключи не выводятся.</p></details><details><summary>История и откат</summary>{history.error!=null&&<Notice error={history.error}/>}<p>Откат создаёт новую версию конфига. Отозванный доступ пользователей не восстанавливается.</p>{history.data?.map(v=><div className="access-actions" key={v.revision}><span>Версия {v.revision} · {new Date(v.created_at).toLocaleString()}</span>{v.revision!==c.revision&&<button type="button" className="button secondary small" disabled={busy||!!pending} onClick={()=>void save(request({rollback_revision:v.revision,replace_private:false,request:{}}))}>Применить версию {v.revision}</button>}</div>)}</details></form>
}
