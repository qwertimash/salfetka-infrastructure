import { fireEvent, render, screen, within, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ApiClient } from './api'
import { Antifraud, canReadAntifraud } from './antifraud'
const a = { account_id: 'A', plan: 'trial', candidate_bytes: 20e9, download_lower_bytes: 21e9, download_upper_bytes: null, coverage_complete: false, quality_reasons: ['unobserved_tail'], notification_state: 'none', policy: { revision: 1, incident_id: 7, limited: true, until_ms: Date.now()+86400000, state: 'pending_apply', required_nodes: ['de','pl'], confirmed_nodes: ['de'], failed_nodes: [] }, incident: { id: 7, triggered_at: Date.now(), threshold_bytes: 20e9, evidence_bytes: 20e9 } }
const page = { items: [a, {...a,account_id:'B',policy:{...a.policy,revision:0,limited:false,incident_id:null,until_ms:null,state:'clear'},incident:null}], next_cursor:'', generated_at_ms:Date.now(), coverage_scope:'declared_client_ingress_meters_only', aggregate_bps:1000000 }
const json=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status})
afterEach(()=>vi.unstubAllGlobals())
it('distinguishes decision from enforcement and sends only the selected incident',async()=>{
 const fetcher=vi.fn(async(_url:string,options?:RequestInit)=>options?.method==='POST'?json({released:true}):json(page));vi.stubGlobal('fetch',fetcher)
 render(<Antifraud api={new ApiClient()} owner />)
 const row=await screen.findByRole('article',{name:'Аккаунт A'})
 expect(within(row).getByText('Ожидаем применения')).toBeTruthy()
 expect(within(row).getByText(/Подтвердили: 1 из 2/)).toBeTruthy()
 fireEvent.click(within(row).getByRole('button',{name:'Снять ограничение с A'}))
 expect(fetcher.mock.calls.filter(([,o])=>o?.method==='POST').length).toBe(0)
 fireEvent.click(screen.getByRole('button',{name:'Подтвердить снятие'}))
 await screen.findByText(/Команда принята/)
 const posts=fetcher.mock.calls.filter(([,o])=>o?.method==='POST')
 expect(posts.length).toBe(1);expect(JSON.parse(posts[0][1]!.body as string)).toEqual({account_id:'A',incident_id:7})
 expect(within(screen.getByRole('article',{name:'Аккаунт B'})).getByText('Без ограничения')).toBeTruthy()
})
it('retains stale rows on a failed refresh and disables release',async()=>{
 let offline=false;vi.stubGlobal('fetch',vi.fn(async()=>offline?json({error:{code:'antifraud_unavailable'}},503):json(page)))
 render(<Antifraud api={new ApiClient()} owner />)
 await screen.findByRole('article',{name:'Аккаунт A'});offline=true
 fireEvent.click(screen.getByRole('button',{name:'Обновить'}))
 await screen.findByText(/Состояние ограничений неизвестно/)
 expect(screen.getByRole('article',{name:'Аккаунт A'})).toBeTruthy()
 expect((screen.getByRole('button',{name:'Снять ограничение с A'}) as HTMLButtonElement).disabled).toBe(true)
})
it('read-only role sees evidence but cannot release; malformed policy is not shown clear',async()=>{
 let broken=false;vi.stubGlobal('fetch',vi.fn(async()=>json(broken?{...page,items:[{...a,policy:{}}]}:page)))
 render(<Antifraud api={new ApiClient()} owner={false} />)
 await screen.findByRole('article',{name:'Аккаунт A'})
 expect(screen.queryByRole('button',{name:'Снять ограничение с A'})).toBeNull()
 broken=true;fireEvent.click(screen.getByRole('button',{name:'Обновить'}))
 await screen.findByText(/Свежесть данных не подтверждена/)
 expect(screen.getByText('Ожидаем применения')).toBeTruthy()
 for(const r of ['owner','support','auditor'] as const)expect(canReadAntifraud(r)).toBe(true)
 for(const r of ['access_operator','infrastructure_operator'] as const)expect(canReadAntifraud(r)).toBe(false)
})
it('pagination is bounded and never changes the selected account on retry',async()=>{
 const fetcher=vi.fn(async(url:string)=>json(url.includes('after=')?{...page,items:[]}:{...page,next_cursor:'B'}));vi.stubGlobal('fetch',fetcher)
 render(<Antifraud api={new ApiClient()} owner />)
 fireEvent.click(await screen.findByRole('button',{name:'Следующие аккаунты'}))
 await screen.findByText('Аккаунты не найдены')
 expect(screen.queryByRole('article',{name:'Аккаунт A'})).toBeNull()
 await waitFor(()=>expect(fetcher.mock.calls.some(([url])=>url.includes('after=B'))).toBe(true))
})
