import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiClient, ApiError } from './api'
import { NodeIntents } from './nodeIntent'
import { Empty, Notice, PageHeading, Freshness } from './components'
import { Modal } from './modal'
import { Nodes } from './nodes'
import { ManagedServerView } from './managedServers'
import { useResource } from './useResource'
import { uuid } from './constructorModel'
import { validateServer, serverFields, serverErrorField, type ServerField, type ServerErrors, type ServerValues } from './serverValidation'

type Server = { id: string; name: string; address?:string; domain?:string; connections: number; created_at: string }
function server(s: Server) { if (!s || !uuid.test(s.id) || typeof s.name !== 'string' || !Number.isSafeInteger(s.connections) || s.connections < 0) throw new ApiError('invalid_response'); return s }
export function Servers({ api, canWrite, intents }: { api: ApiClient; canWrite: boolean; intents: NodeIntents }) {
 const [selected, setSelected] = useState<Server>(), [unassigned, setUnassigned] = useState(false), [adding, setAdding] = useState(Boolean(intents.get('server-create'))), [after, setAfter] = useState('')
 const resource = useResource(useCallback(async (signal: AbortSignal) => {
  const page = await api.request<{items:Server[];next_cursor:string}>(`/servers${after ? `?after=${after}` : ''}`,{signal})
  if (!page || !Array.isArray(page.items) || typeof page.next_cursor !== 'string' || page.next_cursor && !uuid.test(page.next_cursor)) throw new ApiError('invalid_response')
  page.items.forEach(server); return page
 },[api,after]),15000)
 if (selected || unassigned) return <><button className="button secondary" onClick={() => { setSelected(undefined); setUnassigned(false); resource.refresh() }}>← Все серверы</button>{selected?<ManagedServerView key={selected.id} api={api} canWrite={canWrite} intents={intents} id={selected.id} name={selected.name} address={selected.address??''} domain={selected.domain??''}/>:<Nodes api={api} canWrite={canWrite} intents={intents} serverID="unassigned" serverName="Прежние подключения"/>}</>
 return <><PageHeading eyebrow="ИНФРАСТРУКТУРА" title="Серверы" action={canWrite && <button className="button primary" onClick={() => setAdding(true)}>Добавить сервер</button>}>Сервер — ваша машина. Внутри создаются отдельные подключения VPN и обходов, которые можно включать в разные подписки.</PageHeading><Freshness resource={resource} />{resource.error != null && <Notice error={resource.error} />}
 <div className="server-cards">{resource.data?.items.map(s => <button className="card server-card" key={s.id} onClick={() => setSelected(s)}><strong>{s.name}</strong>{s.domain&&<span>{s.domain}</span>}{s.address&&<span>{s.address}</span>}<span>{s.connections} подключений</span><small>Открыть подключения →</small></button>)}</div>
 {resource.data?.items.length === 0 && <Empty title="Добавьте первый сервер">Зарегистрируйте одну ноду, затем выберите шаблоны Reality, Hysteria2, gRPC и XHTTP.</Empty>}
 <div className="builder-actions">{after && <button className="button secondary" onClick={() => setAfter('')}>Первые серверы</button>}{resource.data?.next_cursor && <button className="button secondary" onClick={() => setAfter(resource.data!.next_cursor)}>Другие серверы</button>}<button className="button secondary" onClick={() => setUnassigned(true)}>Прежние подключения</button></div>
 {adding && <Modal title="Новый сервер" close={() => setAdding(false)}><ServerForm api={api} intents={intents} done={s => {setAdding(false);setSelected(s);resource.refresh()}} /></Modal>}
 </>
}
function ServerForm({api,intents,done}:{api:ApiClient;intents:NodeIntents;done:(s:Server)=>void}){
 const scope='server-create',pending=intents.get(scope)
 const [values,setValues]=useState<ServerValues>(()=>{
  const body=pending?.body as Partial<ServerValues>|undefined
  return {name:typeof body?.name==='string'?body.name:'',address:typeof body?.address==='string'?body.address:'',domain:typeof body?.domain==='string'?body.domain:''}
 })
 const [errors,setErrors]=useState<ServerErrors>({}),[touched,setTouched]=useState<Partial<Record<ServerField,boolean>>>({}),[error,setError]=useState<unknown>(),[busy,setBusy]=useState(false)
 const inputs=useRef<Partial<Record<ServerField,HTMLInputElement|null>>>({})
 const alive=useRef(true);useEffect(()=>{alive.current=true;return()=>{alive.current=false}},[])
 const change=(field:ServerField,value:string)=>{
  const next={...values,[field]:value};setValues(next);setError(undefined)
  setErrors(old=>({...old,[field]:touched[field]?validateServer(next)[field]:undefined}))
 }
 const blur=(field:ServerField)=>{
  setTouched(old=>({...old,[field]:true}));setErrors(old=>({...old,[field]:validateServer(values)[field]}))
 }
 const save=async()=>{
  if(intents.busy.has(scope))return
  if(!pending){
   const invalid=validateServer(values);setErrors(invalid);setTouched({name:true,address:true,domain:true});setError(undefined)
   const first=serverFields.find(field=>invalid[field])
   if(first){inputs.current[first]?.focus();return}
  }
  const request=pending??intents.begin(scope,{path:'/servers',method:'POST',body:{name:values.name.trim(),address:values.address.trim(),domain:values.domain.trim()},label:'Новый сервер'})
  intents.busy.add(scope);setBusy(true);setError(undefined)
  try{const result=server(await api.request<Server>(request.path,{method:'POST',body:request.body,headers:{'Idempotency-Key':request.key}}));intents.finish(scope,request.key);if(alive.current)done(result)}
  catch(e){
   intents.failed(scope,request.key,e)
   if(alive.current){
    const field=serverErrorField(e)
    if(field && !intents.get(scope)){
     setTouched(old=>({...old,[field]:true}));setErrors(old=>({...old,[field]:(e as ApiError).message}))
    }else setError(e)
   }
  }finally{intents.busy.delete(scope);if(alive.current)setBusy(false)}
 }
 const field=(key:ServerField,label:string,placeholder?:string)=><div className="server-form-field"><label htmlFor={`server-${key}`}>{label}</label><input id={`server-${key}`} ref={el=>{inputs.current[key]=el}} required value={values[key]} disabled={busy||!!pending} onChange={e=>change(key,e.target.value)} onBlur={()=>blur(key)} placeholder={placeholder} autoComplete="off" autoCapitalize={key==='name'?undefined:'none'} spellCheck={false} aria-invalid={Boolean(errors[key])} aria-describedby={errors[key]?`server-${key}-error`:key==='domain'?'server-domain-help':undefined}/>{errors[key]&&<p className="field-error" id={`server-${key}-error`} role="alert">{errors[key]}</p>}</div>
 return <form noValidate onSubmit={e=>{e.preventDefault();void save()}}><p>После создания зарегистрируйте одну ноду и установите её на сервер. Все подключения затем настраиваются из панели; SSH-пароль здесь не нужен.</p>{error!=null&&<Notice error={error}/>}
 {field('name','Название сервера')}{field('address','IP сервера','203.0.113.10 или IPv6')}{field('domain','Поддомен сервера','pol.example.com')}
 <p className="field-hint" id="server-domain-help">Создайте DNS-запись A для IPv4 или AAAA для IPv6, указывающую на этот сервер. Введите только имя, без https:// и порта. Сохранение ещё не означает готовность DNS и сертификата.</p><p className="field-hint">Адрес, по которому приложение будет подключаться к этой машине. Сохраняется один раз для всех подключений.</p><button type={pending?'button':'submit'} className="button primary" disabled={busy} onClick={pending?()=>void save():undefined}>{pending?'Повторить создание':'Создать сервер'}</button></form>
}
