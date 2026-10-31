import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { ApiClient } from './api'
import { Diagnostics, canReadDiagnostics } from './diagnostics'
const id='11111111-1111-4111-8111-111111111111', command='22222222-2222-4222-8222-222222222222'
const overview={testers:[{id,name:'Тестер A',devices:[{id:'device',platform:'ios',revoked:0,provider_freshness:'no_fresh_data',latest_metadata:{app_version:'0.2.32',build_number:35}}]}],generated_at_ms:Date.now()}
const event={event_id:'event',kind:'ping_trace',process:'app',process_run_id:'run',sequence:12,occurred_at_ms:1000,received_at_ms:2000,device_id:'device',command_id:command,build_number:35,payload:{stage:'admissionTimeout',error_code:'timeout',tls_started:0}}
const detail={tester:{id,name:'Тестер A'},devices:overview.testers[0].devices,events:[event],next_cursor:'1000|'+id,raw_retention_days:14,fact_retention_days:90,evidence:{sequence_gaps:1},process_observations:{},memory:{samples:[],truncated:false}}
const json=(v:unknown,status=200)=>new Response(JSON.stringify(v),{status})
afterEach(()=>vi.unstubAllGlobals())
it('renders events, unknown freshness, safe payload and cursor without leaking credentials',async()=>{
 const urls:string[]=[];vi.stubGlobal('fetch',vi.fn(async(url:string)=>{urls.push(url);return json(url.endsWith('/testers')?overview:{...detail,events:[{...event,payload:{...event.payload,stage:'<img src=x onerror=alert(1)>'}}]})}))
 const view=render(<Diagnostics api={new ApiClient()} />)
 fireEvent.click(await screen.findByRole('button',{name:'Тестер A'}))
 await screen.findByRole('article', { name: 'Проверка подключения' });expect(screen.getByText('Нет свежих данных туннеля')).toBeTruthy()
 expect(view.container.querySelector('img')).toBeNull();expect(screen.getByText(/Получено:/)).toBeTruthy()
 fireEvent.change(screen.getByLabelText('ID попытки, сеанса или процесса'),{target:{value:'missing'}})
 expect(screen.queryByRole('article', { name: 'Проверка подключения' })).toBeNull()
 fireEvent.change(screen.getByLabelText('ID попытки, сеанса или процесса'),{target:{value:command}})
 expect(screen.getByRole('article', { name: 'Проверка подключения' })).toBeTruthy()
 fireEvent.click(screen.getByRole('button',{name:'Более ранние события'}))
 await screen.findByText('Открыта история. Автообновление этой страницы остановлено.')
 await waitFor(()=>expect(urls.some(u=>u.includes('before='))).toBe(true))
 expect(localStorage.length+sessionStorage.length).toBe(0)
})
it('shows collector failure and can recover to an empty list',async()=>{
 let failed=true;vi.stubGlobal('fetch',vi.fn(async()=>failed?json({error:{code:'diagnostics_unavailable'}},503):json({testers:[],generated_at_ms:Date.now()})))
 render(<Diagnostics api={new ApiClient()} />)
 await screen.findByText(/Нет связи со сборщиком диагностики/)
 failed=false;fireEvent.click(screen.getByRole('button',{name:'Обновить список'}))
 await screen.findByText(/Тестеры не найдены/)
})
it('grants log read only to the intended roles',()=>{
 for(const r of ['owner','support','auditor','infrastructure_operator'] as const)expect(canReadDiagnostics(r)).toBe(true)
 expect(canReadDiagnostics('access_operator')).toBe(false)
})
it('keeps the last events visibly stale when automatic refresh loses the collector',async()=>{
 let offline=false
 vi.stubGlobal('fetch',vi.fn(async(url:string)=>offline?json({error:{code:'diagnostics_unavailable'}},503):json(url.endsWith('/testers')?overview:detail)))
 render(<Diagnostics api={new ApiClient()} />)
 fireEvent.click(await screen.findByRole('button',{name:'Тестер A'}))
 await screen.findByRole('article',{name:'Проверка подключения'})
 offline=true
 await screen.findByText('Журнал не обновлён. Показана предыдущая загруженная страница.',{}, {timeout:7000})
 expect(screen.getByRole('article',{name:'Проверка подключения'})).toBeTruthy()
 expect(screen.getByText(/Свежесть данных не подтверждена/)).toBeTruthy()
},10000)

it('retains events when paused and after a failed manual retry; filters reset without another fetch',async()=>{
 let failed=false
 const fetcher=vi.fn(async(url:string)=>failed?json({error:{code:'diagnostics_unavailable'}},503):json(url.endsWith('/testers')?overview:detail))
 vi.stubGlobal('fetch',fetcher)
 render(<Diagnostics api={new ApiClient()} />)
 fireEvent.click(await screen.findByRole('button',{name:'Тестер A'}))
 await screen.findByRole('article',{name:'Проверка подключения'})
 fireEvent.click(screen.getByLabelText('Автообновление каждые 5 секунд'))
 expect(screen.getByRole('article',{name:'Проверка подключения'})).toBeTruthy()
 expect(screen.getByText(/Обновление на паузе/)).toBeTruthy()
 fireEvent.change(screen.getByLabelText('ID попытки, сеанса или процесса'),{target:{value:'missing'}})
 expect(screen.queryByRole('article')).toBeNull()
 const before=fetcher.mock.calls.length
 fireEvent.click(screen.getByRole('button',{name:'Сбросить фильтры'}))
 expect(screen.getByRole('article',{name:'Проверка подключения'})).toBeTruthy()
 expect(fetcher.mock.calls.length).toBe(before)
 failed=true;fireEvent.click(screen.getByRole('button',{name:'Последние события'}))
 await screen.findByText('Журнал не обновлён. Показана предыдущая загруженная страница.')
 expect(screen.getByRole('article',{name:'Проверка подключения'})).toBeTruthy()
})
