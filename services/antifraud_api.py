"""Opt-in controller HTTP API. mTLS nodes; separate admin/notifier credentials.

The caller configures TLS before publishing. No endpoint accepts user-supplied
account-plan mapping, Telegram recipients, raw credentials or arbitrary commands.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from dataclasses import dataclass

from aiohttp import web

from services.antifraud import Controller
from services.antifraud_budget import Budget
from services.traffic_observation import ObservationError, fields, identifier, integer


@dataclass(frozen=True)
class Principal:
    role: str
    name: str


class Authenticator:
    def __init__(self, *, admin_sha256, notifier_sha256, lab_loopback=False):
        for value in (admin_sha256, notifier_sha256):
            if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('invalid_auth_configuration')
        if hmac.compare_digest(admin_sha256,notifier_sha256):
            raise ValueError('roles_require_distinct_credentials')
        self.secrets={'admin':admin_sha256,'notifier':notifier_sha256}
        self.lab_loopback=lab_loopback

    def __call__(self, request):
        peer=request.transport.get_extra_info('peername') if request.transport else None
        if not request.secure and not (self.lab_loopback and peer and peer[0] in ('127.0.0.1','::1')):
            raise web.HTTPForbidden(text='secure_transport_required')
        ssl=request.transport.get_extra_info('ssl_object') if request.transport else None
        cert=ssl.getpeercert() if ssl else None
        identities=[v.removeprefix('urn:salfetka:antifraud:node:') for k,v in (cert or {}).get('subjectAltName',[]) if k=='URI' and v.startswith('urn:salfetka:antifraud:node:')]
        if identities:
            if len(identities)!=1:
                raise web.HTTPForbidden(text='invalid_node_identity')
            identifier(identities[0])
            return Principal('node',identities[0])
        auth=request.headers.get('Authorization','')
        if len(request.headers.getall('Authorization',[])) != 1 or not auth.startswith('Bearer ') or len(auth)>512:
            raise web.HTTPUnauthorized(text='authentication_required')
        digest=hashlib.sha256(auth[7:].encode()).hexdigest()
        for role,expected in self.secrets.items():
            if hmac.compare_digest(digest,expected):
                return Principal(role,role)
        raise web.HTTPUnauthorized(text='authentication_required')


def create_app(database, authenticate, *, clock=None):
    clock=clock or (lambda:time.time_ns()//1_000_000)
    # A new Controller per request avoids sharing transaction state across tasks.
    # All database operations below are bounded synchronous transactions.
    @web.middleware
    async def guarded(request, handler):
        try:
            request['principal']=authenticate(request)
            response=await handler(request)
            response.headers['Cache-Control']='no-store'
            return response
        except ObservationError as exc:
            return web.json_response({'error':str(exc)},status=409,headers={'Cache-Control':'no-store'})
        except sqlite3.Error:
            return web.json_response({'error':'storage_unavailable'},status=503)
        except (ValueError,TypeError,KeyError,json.JSONDecodeError):
            return web.json_response({'error':'invalid_request'},status=400)

    app=web.Application(middlewares=[guarded],client_max_size=2*1024*1024)
    def role(request,wanted):
        p=request['principal']
        if p.role!=wanted:raise web.HTTPForbidden(text='role_forbidden')
        return p.name
    async def body(request,required,optional=()):
        def unique(pairs):
            out={}
            for k,v in pairs:
                if k in out:raise ObservationError('duplicate_json_field')
                out[k]=v
            return out
        data=json.loads(await request.text(),object_pairs_hook=unique)
        fields(data,required,optional)
        return data
    async def report(request):
        role(request,'admin')
        with Controller(database) as c:return web.json_response(c.tick(clock()))
    async def accounts(request):
        role(request,'admin')
        if any(k!='after' for k in request.query) or len(request.query.getall('after',[]))>1:
            raise ObservationError('invalid_page')
        with Controller(database) as c:
            return web.json_response(c.account_page(clock(),after=request.query.get('after','')))
    async def release(request):
        actor=role(request,'admin');data=await body(request,['account_id','incident_id'],['actor'])
        if 'actor' in data:
            actor=identifier(data['actor'])
        with Controller(database) as c:
            changed=c.release(data['account_id'],data['incident_id'],clock(),actor=actor)
            return web.json_response({'released':changed})
    async def session(request):
        node=role(request,'node');data=await body(request,[],['previous','proposed'])
        with Controller(database) as c:return web.json_response({'session':Budget(c).open_session(node,previous=data.get('previous'),proposed=data.get('proposed'))})
    async def commands(request):
        node=role(request,'node')
        with Controller(database) as c:return web.json_response({'commands':c.commands(node,clock())})
    async def receipt(request):
        node=role(request,'node');data=await body(request,['account_id','revision','limited','applied','sequence','session'],['error_code'])
        if not isinstance(data['session'],str) or len(data['session'])!=48:
            raise ObservationError('invalid_node_session')
        with Controller(database) as c:
            result=c.acknowledge(node,data['account_id'],data['revision'],limited=data['limited'],applied=data['applied'],sequence=data['sequence'],session=data['session'],error_code=data.get('error_code'),at=clock())
            return web.json_response(result)
    async def reserve(request):
        node=role(request,'node');data=await body(request,['session','account_id','sequence','bytes','direction'])
        with Controller(database) as c:
            result=Budget(c).reserve(node,data['session'],data['account_id'],data['sequence'],data['bytes'],data['direction'])
            return web.json_response(result)
    async def usage(request):
        node=role(request,'node');data=await body(request,['samples'])
        if not isinstance(data['samples'],list) or not 1<=len(data['samples'])<=10000:
            raise ObservationError('invalid_samples')
        with Controller(database) as c:
            allowed={r[0] for r in c.db.execute('SELECT id FROM meters WHERE node_id=?',(node,))}
            if not allowed:raise ObservationError('unknown_node')
            for sample in data['samples']:
                if not isinstance(sample,dict) or sample.get('meter') not in allowed:
                    raise ObservationError('unbound_meter')
            result=c.observe(data['samples'],clock())
            return web.json_response({'import':result['import']})
    async def claim(request):
        role(request,'notifier');await body(request,[])
        with Controller(database) as c:return web.json_response({'notification':c.claim_notification(clock())})
    async def finish(request):
        role(request,'notifier');data=await body(request,['incident_id','claim_token','outcome'],['message_id','retry_after_ms'])
        with Controller(database) as c:
            c.finish_notification(data['incident_id'],data['claim_token'],data['outcome'],clock(),message_id=data.get('message_id'),retry_after_ms=data.get('retry_after_ms',30000))
            return web.json_response({'recorded':True})
    async def validate_notification(request):
        role(request,'notifier');data=await body(request,['incident_id','claim_token'])
        with Controller(database) as c:
            return web.json_response({'current':c.notification_current(data['incident_id'],data['claim_token'],clock())})
    app.router.add_get('/admin/report',report)
    app.router.add_get('/admin/accounts',accounts)
    app.router.add_post('/admin/release',release)
    app.router.add_post('/agent/session',session)
    app.router.add_get('/agent/commands',commands)
    app.router.add_post('/agent/receipt',receipt)
    app.router.add_post('/agent/reserve',reserve)
    app.router.add_post('/agent/usage',usage)
    app.router.add_post('/notifications/claim',claim)
    app.router.add_post('/notifications/finish',finish)
    app.router.add_post('/notifications/validate',validate_notification)
    return app
