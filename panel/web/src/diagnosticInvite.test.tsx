import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { DiagnosticInvite } from './diagnosticInvite'
import { ApiClient } from './api'
import { AccessIntents } from './accessIntent'
const id='11111111-1111-4111-8111-111111111111'
it('keeps diagnostic consent separate and retries the same account request',async()=>{
 const api=new ApiClient(),intents=new AccessIntents();let writes=0
 const call=vi.spyOn(api,'request').mockImplementation(async(path,options)=>{
  if(options?.method==='POST'){writes++;if(writes===1)throw new Error('lost');return {code:'a'.repeat(64),tester_id:id,expires_at_ms:Date.now()+86400000} as never}
  return {items:[{id,name:'Tester',state:'active',revision:1}],next_cursor:null} as never
 })
 const view=render(<DiagnosticInvite api={api} intents={intents}/>);await screen.findByRole('option',{name:'Tester'})
 expect(writes).toBe(0)
 fireEvent.change(screen.getByLabelText('Пользователь для диагностики'),{target:{value:id}});fireEvent.click(screen.getByRole('button',{name:'Создать код диагностики',hidden:true}));await screen.findByRole('alert')
 view.unmount();render(<DiagnosticInvite api={api} intents={intents}/>);await screen.findByRole('option',{name:'Tester'})
 fireEvent.change(screen.getByLabelText('Пользователь для диагностики'),{target:{value:id}});fireEvent.click(screen.getByRole('button',{name:'Повторить выдачу кода',hidden:true}));await screen.findByLabelText('Код диагностики')
 const requests=call.mock.calls.filter(c=>c[1]?.method==='POST');expect(requests[0]).toEqual(requests[1]);expect(requests[0][0]).toBe('/diagnostics/invitations')
 expect(call.mock.calls.some(c=>c[0].includes('/devices')||c[0].includes('/consent'))).toBe(false)
 expect(localStorage.length+sessionStorage.length).toBe(0)
})
