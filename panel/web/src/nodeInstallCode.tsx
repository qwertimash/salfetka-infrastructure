import {useCallback,useState} from 'react'
import {ApiClient,ApiError} from './api'
import type {Enrollment} from './nodeApi'
import {useResource} from './useResource'
import {Notice} from './components'
type Info={schema:number;panel_url:string;ca_pem:string;signer_pem:string}
export function installCode(info:Info,invitation:Enrollment){
 if(info.schema!==1||!info.panel_url.startsWith('https://')||!info.ca_pem.startsWith('-----BEGIN CERTIFICATE-----')||!info.signer_pem.startsWith('-----BEGIN PUBLIC KEY-----'))throw new ApiError('invalid_response')
 const bytes=new TextEncoder().encode(JSON.stringify({...info,node_id:invitation.node_id,token:invitation.token,expires_at:invitation.expires_at}))
 return 'SN1.'+btoa(Array.from(bytes,b=>String.fromCharCode(b)).join('')).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')
}
export function NodeInstallCode({api,invitation}:{api:ApiClient;invitation:Enrollment}){
 const info=useResource(useCallback(async(signal:AbortSignal)=>installCode(await api.request<Info>('/managed/install-info',{signal}),invitation),[api,invitation]),0)
 const[copied,setCopied]=useState(false),[show,setShow]=useState(false),[error,setError]=useState<unknown>()
 return <section><h4>Установка без JSON-файлов</h4><p>В проверенном пакете ноды запустите <code>python3 node-wizard.py</code> и вставьте код по запросу. В нём уже есть адрес панели и данные доверия.</p>{info.error!=null&&<><Notice error={info.error}/><p>Команда установки недоступна, пока не настроен прямой TLS/mTLS-вход ноды. Не отключайте проверку сертификата.</p></>}{info.data&&<><button type="button" className="button primary" onClick={async()=>{try{await navigator.clipboard.writeText(info.data!);setCopied(true)}catch{setShow(true);setError(new Error('Не удалось скопировать. Скопируйте код из поля ниже.'))}}}>{copied?'Код скопирован':'Скопировать код установки'}</button><button type="button" className="button secondary" onClick={()=>setShow(!show)}>{show?'Скрыть код':'Показать код'}</button>{show&&<label>Код установки<textarea readOnly value={info.data} rows={4} autoComplete="off" spellCheck={false}/></label>}</>}{error!=null&&<p role="alert">Не удалось скопировать автоматически. Выделите код вручную.</p>}<p className="field-hint">Это секрет одноразовой установки. Он не сохраняется в адресной строке или локальном хранилище браузера.</p></section>
}
