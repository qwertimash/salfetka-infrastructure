import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { Servers } from './servers'
import { ApiClient, ApiError } from './api'
import { NodeIntents } from './nodeIntent'
const id='11111111-1111-4111-8111-111111111111'
const server={id,name:'Local machine',address:'203.0.113.10',domain:'pol.example.com',connections:0,created_at:'2030-01-01T00:00:00Z'}
it('creates a physical server through API and opens only its connections',async()=>{
 const api=new ApiClient(),calls=vi.spyOn(api,'request').mockImplementation(async(path,options)=>{
  if(options?.method==='POST')return server as never
  if(path.startsWith('/managed/'))return {node:null,legacy:false,connections:[]} as never
  return {items:[],next_cursor:''} as never
 })
 render(<Servers api={api} canWrite intents={new NodeIntents()}/>);
 fireEvent.click(screen.getByRole('button',{name:'Добавить сервер'}));fireEvent.change(screen.getByLabelText('Название сервера'),{target:{value:'Local machine'}})
 fireEvent.change(screen.getByLabelText('IP сервера'),{target:{value:'203.0.113.10'}});fireEvent.change(screen.getByLabelText('Поддомен сервера'),{target:{value:'pol.example.com'}});fireEvent.click(screen.getByRole('button',{name:'Создать сервер'}));await screen.findByText('Local machine')
 await waitFor(()=>expect(calls.mock.calls.some(c=>c[0]===`/managed/servers/${id}`)).toBe(true))
 const writes=calls.mock.calls.filter(c=>c[1]?.method==='POST');expect(writes).toHaveLength(1);expect(writes[0][0]).toBe('/servers');expect(writes[0][1]?.body).toEqual({name:'Local machine',address:'203.0.113.10',domain:'pol.example.com'})
})
it('read-only role can inspect previous connections but cannot create servers',async()=>{
 const api=new ApiClient(),calls=vi.spyOn(api,'request').mockResolvedValue({items:[],next_cursor:''})
 render(<Servers api={api} canWrite={false} intents={new NodeIntents()}/>);await screen.findByText('Добавьте первый сервер')
 expect(screen.queryByRole('button',{name:'Добавить сервер'})).toBeNull()
 fireEvent.click(screen.getByRole('button',{name:'Прежние подключения'}));await waitFor(()=>expect(calls.mock.calls.some(c=>c[0]==='/servers/unassigned/connections')).toBe(true))
 expect(calls.mock.calls.some(c=>c[1]?.method==='POST')).toBe(false)
})
it('highlights the bad IP on blur, blocks submission, focuses it and clears after correction',async()=>{
 const api=new ApiClient(),calls=vi.spyOn(api,'request').mockResolvedValue({items:[],next_cursor:''})
 render(<Servers api={api} canWrite intents={new NodeIntents()}/>);
 fireEvent.click(screen.getByRole('button',{name:'Добавить сервер'}))
 fireEvent.change(screen.getByLabelText('Название сервера'),{target:{value:'Польша'}})
 fireEvent.change(screen.getByLabelText('Поддомен сервера'),{target:{value:'pol.example.com'}})
 const ip=screen.getByLabelText('IP сервера')
 fireEvent.change(ip,{target:{value:'228.22.232.21'}});fireEvent.blur(ip)
 expect(ip.getAttribute('aria-invalid')).toBe('true');expect(screen.getByRole('alert').textContent).toContain('multicast')
 expect(screen.getByLabelText('Поддомен сервера').getAttribute('aria-invalid')).toBe('false')
 fireEvent.click(screen.getByRole('button',{name:'Создать сервер'}))
 expect(document.activeElement).toBe(ip);expect(calls.mock.calls.some(c=>c[1]?.method==='POST')).toBe(false)
 fireEvent.change(ip,{target:{value:'203.0.113.10'}})
 expect(ip.getAttribute('aria-invalid')).toBe('false');expect(screen.queryByRole('alert')).toBeNull()
})
it('attaches a server validation error to its field and permits correction without losing other values',async()=>{
 const api=new ApiClient(),calls=vi.spyOn(api,'request').mockImplementation(async(path,options)=>{
  if(options?.method==='POST')throw new ApiError('server_domain_invalid',400)
  return {items:[],next_cursor:''} as never
 })
 render(<Servers api={api} canWrite intents={new NodeIntents()}/>);
 fireEvent.click(screen.getByRole('button',{name:'Добавить сервер'}))
 for(const [label,value] of [['Название сервера','Польша'],['IP сервера','203.0.113.10'],['Поддомен сервера','pol.example.com']])fireEvent.change(screen.getByLabelText(label),{target:{value}})
 fireEvent.click(screen.getByRole('button',{name:'Создать сервер'}));await screen.findByRole('alert')
 const domain=screen.getByLabelText('Поддомен сервера') as HTMLInputElement
 expect(domain.getAttribute('aria-invalid')).toBe('true');expect(domain.disabled).toBe(false)
 expect((screen.getByLabelText('IP сервера') as HTMLInputElement).value).toBe('203.0.113.10')
 fireEvent.change(domain,{target:{value:'new.example.com'}})
 expect(domain.getAttribute('aria-invalid')).toBe('false');expect(calls.mock.calls.filter(c=>c[1]?.method==='POST')).toHaveLength(1)
})
