import {expect,it} from 'vitest'
import {installCode} from './nodeInstallCode'
it('encodes authenticated trust and one-use invitation without dropping fields',()=>{
 const info={schema:1,panel_url:'https://panel.example.com',ca_pem:'-----BEGIN CERTIFICATE-----\nfixture',signer_pem:'-----BEGIN PUBLIC KEY-----\nfixture'}
 const invitation={node_id:'11111111-1111-4111-8111-111111111111',token:'secret',expires_at:'2030-01-01T00:00:00Z'}
 const code=installCode(info,invitation)
 expect(code.startsWith('SN1.')).toBe(true)
 expect(JSON.parse(atob(code.slice(4).replaceAll('-','+').replaceAll('_','/')))).toEqual({...info,...invitation})
 expect(()=>installCode({...info,panel_url:'http://panel.example.com'},invitation)).toThrow()
})
