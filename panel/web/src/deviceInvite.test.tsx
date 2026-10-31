import { fireEvent, render, screen } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { DeviceInvite } from './deviceInvite'
import { ApiClient } from './api'
import { AccessIntents } from './accessIntent'
const assignment = '11111111-1111-4111-8111-111111111111'
it('requires an explicit action and preserves an unknown invite request across remount', async () => {
 const api = new ApiClient(), intents = new AccessIntents()
 const call = vi.spyOn(api, 'request').mockRejectedValueOnce(new Error('lost synthetic response')).mockResolvedValue({url:`https://example.invalid/i/${'a'.repeat(43)}`, expires_at:'2030-01-01T00:00:00Z'})
 const ui = () => <DeviceInvite api={api} assignment={assignment} generation={1} intents={intents} />
 const view = render(ui()); expect(call).not.toHaveBeenCalled()
 fireEvent.click(screen.getByRole('button',{name:'Создать приглашение для приложения'})); await screen.findByRole('button',{name:'Повторить выдачу приглашения'})
 const first = call.mock.calls[0]; view.unmount(); render(ui())
 fireEvent.click(screen.getByRole('button',{name:'Повторить выдачу приглашения'})); await screen.findByLabelText('Приглашение для приложения')
 expect(call.mock.calls[1]).toEqual(first); expect(first[1]?.body).toEqual({assignment_id:assignment})
 expect(localStorage.length+sessionStorage.length).toBe(0)
 fireEvent.click(screen.getByRole('button',{name:'Скрыть приглашение'})); expect(screen.queryByLabelText('Приглашение для приложения')).toBeNull()
})
it('rejects a response with an unsafe link', async () => {
 const api = new ApiClient(); vi.spyOn(api,'request').mockResolvedValue({url:'http://example.invalid/i/a',expires_at:'2030-01-01T00:00:00Z'})
 render(<DeviceInvite api={api} assignment={assignment} generation={1} intents={new AccessIntents()} />)
 fireEvent.click(screen.getByRole('button',{name:'Создать приглашение для приложения'})); await screen.findByRole('alert')
 expect(screen.queryByLabelText('Приглашение для приложения')).toBeNull()
})
