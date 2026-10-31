import {fireEvent,render,screen,waitFor} from '@testing-library/react'
import {expect,it,vi} from 'vitest'
import {ApiClient,ApiError} from './api'
import {ManagedServerView} from './managedServers'
import {NodeIntents} from './nodeIntent'
const id='11111111-1111-4111-8111-111111111111'
const n={id,name:'Fixture node',state:'pending',revision:2,serial:null,certificate_expires_at:null,last_seen_at:null,inventory:null,contact_state:'unknown',engine_state:'not_configured',created_at:'2030-01-01T00:00:00Z',updated_at:'2030-01-01T00:00:00Z'}
const templates=[{id:'vless-tcp-reality',name:'TCP Reality',version:1,network:'tcp',default_port:443,tls_certificate:false},{id:'vless-grpc-tls',name:'gRPC',version:1,network:'tcp',default_port:8443,tls_certificate:true}]
it('creates a template batch with distinct SNI, ports and one node identity; retry preserves request',async()=>{
 const api=new ApiClient();let failed=false
 const calls=vi.spyOn(api,'request').mockImplementation(async(path,opt)=>{
  if(opt?.method==='POST'){if(!failed){failed=true;throw new ApiError('network_error')}return {} as never}
  if(path==='/managed/templates')return {items:templates} as never
  return {node:n,legacy:false,connections:[]} as never
 })
 render(<ManagedServerView api={api} intents={new NodeIntents()} canWrite id={id} name="Test machine" address="203.0.113.10" domain="pol.example.com"/>);
 fireEvent.click(await screen.findByRole('button',{name:'Добавить подключения'}))
 fireEvent.click(await screen.findByLabelText('TCP Reality · TCP'));fireEvent.click(screen.getByLabelText('gRPC · TCP'))
 expect((screen.getByLabelText('Публичный адрес сервера') as HTMLInputElement).value).toBe('203.0.113.10')
 expect((screen.getByLabelText('Домен TLS-сертификата') as HTMLInputElement).value).toBe('pol.example.com')
 expect((screen.getByLabelText('Reality SNI') as HTMLInputElement).value).toBe('pol.example.com')
 for(const[label,value] of [['Публичный адрес сервера','vpn.example.com'],['Домен TLS-сертификата','vpn.example.com'],['Reality SNI','target.example.com'],['Reality: целевой TLS-сервер','target.example.com:443'],['Сертификат PEM','synthetic-cert'],['Приватный ключ PEM','synthetic-key'],['Порт gRPC','8445']])fireEvent.change(screen.getByLabelText(label),{target:{value}})
 fireEvent.click(screen.getByRole('button',{name:'Создать и применить'}));await screen.findByText(/Нет связи с панелью/)
 fireEvent.click(screen.getByRole('button',{name:'Повторить тот же запрос'}))
 await waitFor(()=>expect(calls.mock.calls.filter(c=>c[1]?.method==='POST')).toHaveLength(2))
 const writes=calls.mock.calls.filter(c=>c[1]?.method==='POST');expect(writes[0]).toEqual(writes[1]);expect(writes[0][0]).toBe(`/managed/nodes/${id}/connections`)
 const body=writes[0][1]!.body as {connections:{configuration:{public:Record<string,unknown>;private:Record<string,string>}}[]}
 expect(body.connections).toHaveLength(2);expect(body.connections[0].configuration.public.server_name).toBe('target.example.com');expect(body.connections[0].configuration.private).toEqual({});expect(body.connections[1].configuration.public.port).toBe(8445);expect(body.connections[1].configuration.public.server_name).toBe('vpn.example.com')
})
it('read-only role cannot register or provision a node',async()=>{
 const api=new ApiClient(),calls=vi.spyOn(api,'request').mockResolvedValue({node:null,legacy:false,connections:[]})
 render(<ManagedServerView api={api} intents={new NodeIntents()} canWrite={false} id={id} name="Fixture"/>);await screen.findByText('1. Подключите сервер')
 expect(screen.queryByRole('button',{name:'Зарегистрировать ноду'})).toBeNull();expect(calls.mock.calls.some(c=>c[1]?.method==='POST')).toBe(false)
})
it('confirms physical revoke and retains exact request across lost response and navigation',async()=>{
 const api=new ApiClient(),intents=new NodeIntents();let current={...n,state:'active'},attempt=0
 intents.saveSecret({node_id:id,token:'synthetic-only',expires_at:'2030-01-01T00:00:00Z'})
 const calls=vi.spyOn(api,'request').mockImplementation(async(path,opt)=>{
  if(opt?.method==='POST'){current={...current,state:'revoked',revision:3};if(++attempt===1)throw new ApiError('network_error');return current as never}
  return {node:current,legacy:false,connections:[]} as never
 })
 const ui=()=> <ManagedServerView api={api} intents={intents} canWrite id={id} name="Test machine"/>
 const view=render(ui());fireEvent.click(await screen.findByRole('button',{name:'Отозвать доступ ноды'}))
 expect(calls.mock.calls.some(([,o])=>o?.method==='POST')).toBe(false)
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));expect(calls.mock.calls.some(([,o])=>o?.method==='POST')).toBe(false)
 fireEvent.click(screen.getByRole('button',{name:'Отозвать доступ ноды'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить отзыв ноды'}))
 await screen.findByRole('button',{name:'Повторить отзыв ноды'});view.unmount();render(ui())
 fireEvent.click(await screen.findByRole('button',{name:'Повторить: Отозвать доступ ноды'}))
 await waitFor(()=>expect(intents.get(`managed-server:${id}`)).toBeUndefined())
 const writes=calls.mock.calls.filter(([,o])=>o?.method==='POST');expect(writes).toHaveLength(2);expect(writes[0]).toEqual(writes[1])
 expect(writes[0][0]).toBe(`/nodes/${id}/revoke`);expect(writes[0][1]?.headers?.['If-Match']).toBe('"2"')
 expect(intents.secret(id)).toBeUndefined();expect(screen.queryByRole('button',{name:'Отозвать доступ ноды'})).toBeNull();expect(screen.queryByText('2. Выберите способы подключения')).toBeNull()
})
it('keeps the confirmed revision on conflict until the operator reopens confirmation',async()=>{
 const api=new ApiClient();let current={...n,state:'active'}
 const calls=vi.spyOn(api,'request').mockImplementation(async(path,opt)=>{
  if(opt?.method==='POST'){current={...current,revision:3};throw new ApiError('revision_conflict',412)}
  return {node:current,legacy:false,connections:[]} as never
 })
 render(<ManagedServerView api={api} intents={new NodeIntents()} canWrite id={id} name="Test machine"/>);
 fireEvent.click(await screen.findByRole('button',{name:'Отозвать доступ ноды'}));fireEvent.click(screen.getByRole('button',{name:'Подтвердить отзыв ноды'}))
 await screen.findByText(/Запись изменилась после открытия подтверждения/)
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить отзыв ноды'}))
 await waitFor(()=>expect(calls.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(2))
 expect(calls.mock.calls.filter(([,o])=>o?.method==='POST').map(([,o])=>o?.headers?.['If-Match'])).toEqual(['"2"','"2"'])
 fireEvent.click(screen.getByRole('button',{name:'Отмена'}));fireEvent.click(await screen.findByRole('button',{name:'Отозвать доступ ноды'}))
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить отзыв ноды'}))
 await waitFor(()=>expect(calls.mock.calls.filter(([,o])=>o?.method==='POST').at(-1)?.[1]?.headers?.['If-Match']).toBe('"3"'))
})
it('read-only role cannot revoke an active node or retry a retained mutation',async()=>{
 const api=new ApiClient(),intents=new NodeIntents();intents.begin(`managed-server:${id}`,{path:`/nodes/${id}/revoke`,method:'POST',body:{},revision:2,label:'Отозвать доступ ноды'})
 const calls=vi.spyOn(api,'request').mockResolvedValue({node:{...n,state:'active'},legacy:false,connections:[]})
 render(<ManagedServerView api={api} intents={intents} canWrite={false} id={id} name="Test machine"/>);await screen.findByText('Нода сервера')
 expect(screen.queryByRole('button',{name:/Отозвать|Повторить/})).toBeNull();expect(calls.mock.calls.some(([,o])=>o?.method==='POST')).toBe(false)
})
