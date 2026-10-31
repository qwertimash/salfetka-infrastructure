import {expect,it} from 'vitest'
import {validateServer} from './serverValidation'
const valid={name:'Польша',address:'203.0.113.10',domain:'pol.example.com'}
it('accepts IPv4, IPv6 and mapped unicast with canonicalizable domain',()=>{
 for(const address of ['203.0.113.10','2001:db8::1','::ffff:203.0.113.10','2001:db8:0:1:2:3:4:5']) expect(validateServer({...valid,address,domain:'Pol.Example.COM.'})).toEqual({})
})
it('identifies multicast including mapped IPv4, unspecified addresses and malformed IPs',()=>{
 for(const address of ['228.22.232.21','239.255.255.255','ff02::1','::ffff:228.22.232.21','::ffff:e416:e815']) expect(validateServer({...valid,address}).address).toMatch(/multicast/)
 for(const address of ['0.0.0.0','::','::ffff:0.0.0.0']) expect(validateServer({...valid,address}).address).toMatch(/прослушивания/)
 for(const address of ['','256.1.1.1','001.2.3.4','https://1.2.3.4','1.2.3.4:443','1.2.3.4/24','fe80::1%eth0','[::1]','1:2:3','::ffff:001.2.3.4']) expect(validateServer({...valid,address}).address).toMatch(/IPv4 или IPv6/)
})
it('validates all fields without changing the input',()=>{
 const input={name:'x',address:'228.22.232.21',domain:'https://pol.example.com'}
 expect(Object.keys(validateServer(input))).toEqual(['name','address','domain'])
 expect(input.domain).toBe('https://pol.example.com')
 for(const domain of ['','localhost','203.0.113.10','pol.example.com:443','*.example.com','a..example.com','-a.example.com','a_.example.com','пример.рф']) expect(validateServer({...valid,domain}).domain).toBeTruthy()
})
