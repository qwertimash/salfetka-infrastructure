#!/usr/bin/env python3
"""Build private catalog v1 without silently dropping unsupported VPN entries."""
import argparse
import base64
import collections
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import parse_qsl, unquote, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / 'mobile/private'
ARTIFACTS = ROOT / 'mobile/artifacts/subscriptions'
MAX_BYTES = 524288
ID = re.compile(r'[A-Za-z0-9_-]{1,64}')


class SubscriptionError(ValueError):
    """Only a fixed category, never an input value."""


def require(condition, code):
    if not condition:
        raise SubscriptionError(code)


def strict_json(data, max_bytes=MAX_BYTES):
    require(0 < len(data) <= max_bytes, 'input_size')
    def pairs(items):
        obj = {}
        for key, value in items:
            require(key not in obj, 'duplicate_json_key')
            obj[key] = value
        return obj
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(SubscriptionError('nonfinite_json')))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise SubscriptionError('invalid_json') from None


def moment(value):
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(result.tzinfo is not None, 'expiry_timezone_missing')
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise SubscriptionError('invalid_expiry') from None


def valid_text(value, maximum=4096):
    return (isinstance(value, str) and len(value) <= maximum and
            all(ord(c) >= 32 and ord(c) != 127 for c in value))


def validate_openflux(settings):
    """Published bypass profiles must be encrypted single-carrier configs."""
    allowed = {'transport','document_url','encryption_secret','codec','max_token','max_uid'}
    require(isinstance(settings,dict) and set(settings) <= allowed, 'openflux_keys')
    require(all(valid_text(value,16384) for value in settings.values()), 'openflux_values')
    secret = settings.get('encryption_secret','')
    try:
        require(len(json.dumps(settings,ensure_ascii=False,separators=(',',':')).encode()) <= 16384, 'openflux_size')
        chars = len(secret.encode('utf-16-le')) // 2
    except UnicodeError:
        raise SubscriptionError('openflux_secret') from None
    require(chars >= 16 and secret.strip() == secret, 'openflux_secret')
    require(settings.get('codec','') in {'','batched','legacy'}, 'openflux_codec')
    carrier = settings.get('transport','')
    reference = settings.get('document_url','')
    if carrier in {'yandex','vyandex','boards','mailru'}:
        try:
            url = urlsplit(reference)
            require(url.scheme == 'https' and url.hostname and not url.username and not url.password and not url.fragment, 'openflux_url')
        except ValueError:
            raise SubscriptionError('openflux_url') from None
    elif carrier == 'cupsonline':
        require(bool(reference.strip()), 'openflux_room')
    elif carrier == 'oneme':
        require(bool(settings.get('max_token','').strip()) and not reference, 'openflux_oneme')
        uid = settings.get('max_uid','')
        require(not uid or (len(uid) <= 20 and re.fullmatch(r'[+]?[0-9]+',uid) and 0 < int(uid) <= 2**63-1), 'openflux_uid')
    else:
        # direct belongs in local diagnostics, never an advertised bypass.
        raise SubscriptionError('openflux_carrier')
    require(carrier == 'oneme' or not (settings.get('max_token','') or settings.get('max_uid','')), 'openflux_oneme_fields')


def host(value):
    require(valid_text(value, 253) and value and not any(c in value for c in '/@?#'), 'invalid_host')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        try:
            labels = value.encode('idna').decode().rstrip('.').split('.')
            require(all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in labels), 'invalid_host')
        except UnicodeError:
            raise SubscriptionError('invalid_host') from None


def safe_options(value, depth=0):
    require(depth <= 64, 'settings_depth')
    if isinstance(value, dict):
        for key, child in value.items():
            lower = key.lower()
            require(lower not in {'certificatefile', 'keyfile', 'cafile', 'dialerproxy', 'proxysettings', 'sockopt'}, 'unsafe_xray_option')
            if lower in {'allowinsecure', 'allowinsecureifpinnedpeercertificate'}:
                require(child is False, 'tls_verification_disabled')
            safe_options(child, depth + 1)
    elif isinstance(value, list):
        for item in value:
            safe_options(item, depth + 1)


def validate_xray(settings):
    require(isinstance(settings, dict) and set(settings) == {'outbound'}, 'xray_wrapper')
    outbound = settings['outbound']
    require(isinstance(outbound, dict) and set(outbound) <= {'protocol', 'settings', 'streamSettings', 'tag'}, 'xray_outbound_keys')
    require(outbound.get('protocol') in {'vless','hysteria'}, 'unsupported_vpn_protocol')
    stream = outbound.get('streamSettings')
    require(isinstance(stream, dict) and stream.get('security') in {'tls', 'reality'}, 'xray_security_required')
    require(stream.get('network') in {'tcp', 'raw', 'grpc', 'xhttp', 'ws', 'httpupgrade','hysteria'}, 'unsupported_transport')
    safe_options(outbound)
    require(isinstance(outbound.get('settings'),dict), 'xray_settings')
    if outbound['protocol'] == 'hysteria':
        s=outbound['settings']
        require(set(s)=={'version','address','port'} and type(s['version']) is int and s['version']==2, 'hysteria_version')
        host(s['address'])
        require(type(s['port']) is int and 1 <= s['port'] <= 65535, 'invalid_port')
        require(stream['security']=='tls' and stream['network']=='hysteria', 'hysteria_tls_transport_required')
        require(set(stream) <= {'network','security','tlsSettings','hysteriaSettings','finalmask'}, 'hysteria_stream_keys')
        h=stream.get('hysteriaSettings')
        require(isinstance(h,dict) and set(h)=={'version','auth'} and type(h['version']) is int and h['version']==2 and valid_text(h['auth'],8192) and h['auth'], 'hysteria_auth')
        require(isinstance(stream.get('tlsSettings'),dict) and stream['tlsSettings'].get('allowInsecure') is False, 'tls_verification_required')
        if 'finalmask' in stream:
            validate_hysteria_mask(stream['finalmask'])
        return
    require(stream['network'] != 'hysteria','protocol_transport_mismatch')
    servers = outbound['settings'].get('vnext')
    require(isinstance(servers, list) and len(servers) == 1, 'single_vless_server_required')
    server = servers[0]
    host(server.get('address'))
    require(type(server.get('port')) is int and 1 <= server['port'] <= 65535, 'invalid_port')
    users = server.get('users')
    require(isinstance(users, list) and len(users) == 1, 'single_vless_user_required')
    try:
        uuid.UUID(users[0]['id'])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise SubscriptionError('invalid_vless_identity') from None
    require(users[0].get('encryption') == 'none', 'unsupported_vless_encryption')


def flag_country(fragment):
    flags = re.findall('[\U0001f1e6-\U0001f1ff]{2}', fragment)
    require(len(flags) == 1, 'country_metadata_missing_or_ambiguous')
    return ''.join(chr(ord(c) - 0x1f1e6 + ord('A')) for c in flags[0])


def validate_hysteria_mask(mask):
    require(isinstance(mask,dict) and set(mask)=={'quicParams'}, 'unsupported_hysteria_mask')
    q=mask['quicParams']
    require(isinstance(q,dict) and set(q)<={'debug','congestion'} and q.get('debug',False) is False and q.get('congestion','reno') in {'reno','bbr'}, 'unsupported_hysteria_quic_parameters')


def hysteria2_settings(link):
    require(valid_text(link,16384) and not re.search(r'%(?![0-9A-Fa-f]{2})',link), 'invalid_hysteria_link')
    try:
        uri=urlsplit(link)
        require(uri.scheme in {'hysteria2','hy2'} and '@' in uri.netloc and uri.path in {'','/'}, 'invalid_hysteria_link')
        hostname,port=uri.hostname,443 if uri.port is None else uri.port
        host(hostname)
        auth=unquote(uri.netloc.rsplit('@',1)[0])
        require(valid_text(auth,8192) and auth, 'hysteria_auth')
        pairs=parse_qsl(uri.query,keep_blank_values=True,strict_parsing=True,max_num_fields=16) if uri.query else []
    except (ValueError,TypeError,AttributeError):
        raise SubscriptionError('invalid_hysteria_link') from None
    query={}
    for key,value in pairs:
        require(key not in query and valid_text(value), 'invalid_hysteria_parameter')
        query[key]=value
    require(set(query)<={'sni','insecure','allowInsecure','alpn','fm'}, 'unsupported_hysteria_parameter')
    require(query.get('insecure','0') in {'0','false'} and query.get('allowInsecure','0') in {'0','false'}, 'tls_verification_disabled')
    server_name=query.get('sni',hostname);host(server_name)
    alpn=query.get('alpn','h3').split(',')
    require(alpn==['h3'],'unsupported_hysteria_alpn')
    stream={'network':'hysteria','security':'tls','tlsSettings':{'serverName':server_name,'alpn':alpn,'allowInsecure':False},'hysteriaSettings':{'version':2,'auth':auth}}
    if 'fm' in query:
        mask=strict_json(query['fm'].encode());validate_hysteria_mask(mask)
        stream['finalmask']=mask
    settings={'outbound':{'protocol':'hysteria','settings':{'version':2,'address':hostname,'port':port},'streamSettings':stream}}
    validate_xray(settings)
    return settings,flag_country(unquote(uri.fragment))


def vless_settings(link):
    require(valid_text(link, 16384) and not re.search(r'%(?![0-9A-Fa-f]{2})', link), 'invalid_vless_link')
    try:
        uri = urlsplit(link)
        require(uri.scheme == 'vless' and uri.username is not None and uri.password is None and uri.path in {'', '/'}, 'invalid_vless_link')
        identity = str(uuid.UUID(unquote(uri.username)))
        hostname, port = uri.hostname, uri.port
        host(hostname)
        require(port is not None and 1 <= port <= 65535, 'invalid_port')
        pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True, max_num_fields=64) if uri.query else []
    except (ValueError, TypeError, AttributeError):
        raise SubscriptionError('invalid_vless_link') from None
    query = {}
    for key, value in pairs:
        require(key not in query, 'duplicate_vless_parameter')
        require(valid_text(value), 'invalid_vless_parameter')
        query[key] = value
    require(set(query) <= {'encryption','flow','security','type','sni','fp','pbk','sid','spx','alpn','allowInsecure','headerType','host','path','serviceName','mode','authority'}, 'unsupported_vless_parameter')
    require(query.get('encryption', 'none') == 'none', 'unsupported_vless_encryption')
    require(query.get('allowInsecure', '0') in {'0','false'}, 'tls_verification_disabled')
    security = query.get('security')
    network = query.get('type', 'tcp')
    require(security in {'tls', 'reality'}, 'xray_security_required')
    require(network in {'tcp','raw','grpc','xhttp','ws','httpupgrade'}, 'unsupported_transport')
    flow = query.get('flow', '')
    require(flow in {'','xtls-rprx-vision'}, 'unsupported_vless_flow')
    require(not flow or network in {'tcp','raw'}, 'flow_transport_mismatch')
    require(query.get('headerType', 'none') == 'none', 'unsupported_header_type')
    user = {'id': identity, 'encryption': 'none'}
    if flow:
        user['flow'] = flow
    stream = {'network': network, 'security': security}
    server_name = query.get('sni', hostname)
    host(server_name)
    fingerprint = query.get('fp')
    require(fingerprint is None or re.fullmatch(r'[A-Za-z0-9_-]{1,64}', fingerprint), 'invalid_fingerprint')
    if security == 'reality':
        require(fingerprint and 'pbk' in query and re.fullmatch(r'[A-Za-z0-9_-]{43}',query['pbk']), 'invalid_reality_public_key')
        short_id = query.get('sid', '')
        require(re.fullmatch(r'(?:[0-9A-Fa-f]{2}){0,8}', short_id), 'invalid_reality_short_id')
        stream['realitySettings'] = {'serverName': server_name, 'fingerprint': fingerprint, 'publicKey': query['pbk'], 'shortId': short_id}
        if 'spx' in query:
            require(query['spx'].startswith('/'), 'invalid_reality_spider_path')
            stream['realitySettings']['spiderX'] = query['spx']
        require('alpn' not in query, 'unsupported_reality_alpn')
    else:
        require(not set(query) & {'pbk','sid','spx'}, 'security_parameter_mismatch')
        stream['tlsSettings'] = {'serverName': server_name, 'allowInsecure': False}
        if fingerprint:
            stream['tlsSettings']['fingerprint'] = fingerprint
        if 'alpn' in query:
            alpn = query['alpn'].split(',')
            require(all(x in {'h2','http/1.1'} for x in alpn) and len(alpn) <= 2, 'unsupported_alpn')
            stream['tlsSettings']['alpn'] = alpn
    if network == 'grpc':
        require(not set(query) & {'path','host'}, 'transport_parameter_mismatch')
        require(query.get('mode', 'gun') in {'gun','multi'}, 'unsupported_grpc_mode')
        stream['grpcSettings'] = {'serviceName': query.get('serviceName',''), 'multiMode': query.get('mode') == 'multi'}
        if 'authority' in query:
            stream['grpcSettings']['authority'] = query['authority']
    elif network == 'xhttp':
        require(not set(query) & {'serviceName','authority'}, 'transport_parameter_mismatch')
        mode = query.get('mode', 'auto')
        require(mode in {'auto','packet-up','stream-up','stream-one'}, 'unsupported_xhttp_mode')
        path = query.get('path','/')
        require(path.startswith('/'), 'invalid_transport_path')
        stream['xhttpSettings'] = {'path': path, 'mode': mode}
        if 'host' in query:
            stream['xhttpSettings']['host'] = query['host']
    elif network in {'ws','httpupgrade'}:
        require(not set(query) & {'serviceName','authority','mode'}, 'transport_parameter_mismatch')
        path = query.get('path','/')
        require(path.startswith('/'), 'invalid_transport_path')
        key = 'wsSettings' if network == 'ws' else 'httpupgradeSettings'
        stream[key] = {'path': path}
        if 'host' in query:
            if network == 'ws':
                stream[key]['headers'] = {'Host': query['host']}
            else:
                stream[key]['host'] = query['host']
    else:
        require(not set(query) & {'path','host','serviceName','authority','mode'}, 'transport_parameter_mismatch')
    result = {'outbound': {'protocol':'vless','settings':{'vnext':[{'address':hostname,'port':port,'users':[user]}]},'streamSettings':stream}}
    validate_xray(result)
    return result, flag_country(unquote(uri.fragment))


def validate_catalog(catalog, now):
    require(isinstance(catalog,dict) and set(catalog) == {'schema_version','catalog_id','revision','expires_at','profiles','dns_servers','probe'}, 'catalog_keys')
    require(type(catalog['schema_version']) is int and catalog['schema_version'] == 1, 'catalog_version')
    require(isinstance(catalog['catalog_id'],str) and ID.fullmatch(catalog['catalog_id']), 'catalog_identity')
    require(type(catalog['revision']) is int and catalog['revision'] >= 1, 'catalog_revision')
    require(moment(catalog['expires_at']) > now, 'catalog_expired')
    dns = catalog['dns_servers']
    require(isinstance(dns,list) and 1 <= len(dns) <= 3, 'dns_count')
    for item in dns:
        try:
            require(ipaddress.ip_address(item).version == 4, 'ipv4_required')
        except ValueError:
            raise SubscriptionError('ipv4_required') from None
    probe = catalog['probe']
    require(isinstance(probe,dict) and set(probe) == {'url','ipv4','expected_status','body_sha256'}, 'probe_keys')
    uri = urlsplit(probe['url'])
    require(uri.scheme=='https' and uri.hostname and not uri.username and not uri.password and not uri.query and not uri.fragment, 'probe_https_required')
    require(ipaddress.ip_address(probe['ipv4']).version == 4, 'probe_ipv4_required')
    require(type(probe['expected_status']) is int and 200 <= probe['expected_status'] <= 299, 'probe_status')
    require(isinstance(probe['body_sha256'],str) and re.fullmatch(r'[0-9a-fA-F]{64}',probe['body_sha256']), 'probe_digest')
    profiles = catalog['profiles']
    require(isinstance(profiles,list) and 1 <= len(profiles) <= 32, 'profile_count')
    ids = set()
    for p in profiles:
        require(isinstance(p,dict) and set(p) == {'id','name','mode','exit_country','engine','settings'}, 'profile_keys')
        require(isinstance(p['id'],str) and ID.fullmatch(p['id']) and p['id'] not in ids, 'profile_identity')
        ids.add(p['id'])
        require(valid_text(p['name'],64) and p['name'].strip(), 'profile_name')
        require(isinstance(p['exit_country'],str) and re.fullmatch('[A-Z]{2}',p['exit_country']), 'profile_country')
        if p['mode'] == 'vpn':
            require(p['engine'] == 'xray', 'profile_engine')
            validate_xray(p['settings'])
        else:
            require(p['mode'] == 'bypass' and p['engine'] in {'olcrtc','openflux'}, 'profile_engine')
            if p['engine'] == 'openflux':
                validate_openflux(p['settings'])
                continue
            s = p['settings']
            require(isinstance(s,dict) and {'provider','transport','room','key_hex','bootstrap_dns'} <= set(s) <= {'provider','transport','room','key_hex','bootstrap_dns','channel_id','provider_token','device_id','dtls_profile','account_session'}, 'olcrtc_keys')
            if 'account_session' in s:
                require(type(s['account_session']) is bool and (not s['account_session'] or (s['provider'] == 'jitsi' and s['transport'] == 'vp8channel')), 'olcrtc_account_session')
            require(s['provider'] in {'jitsi','telemost','wbstream','salutejazz','vkcalls'}, 'olcrtc_provider')
            require(s['transport'] in {'datachannel','vp8channel','seichannel'}, 'olcrtc_transport')
            require(re.fullmatch('[0-9A-Fa-f]{64}',s['key_hex']), 'olcrtc_key')
            room = urlsplit(s['room'])
            require(room.scheme == 'https' and room.hostname and not room.username and not room.password, 'olcrtc_room')
            address, port = s['bootstrap_dns'].rsplit(':',1)
            require(ipaddress.ip_address(address.strip('[]')) and 1 <= int(port) <= 65535, 'olcrtc_dns')


def decode_vless_payload(data):
    require(0 < len(data) <= MAX_BYTES, 'input_size')
    try:
        text = data.decode('utf-8-sig').strip()
        if '://' not in text:
            text = base64.b64decode(text.encode(), validate=True).decode('utf-8').strip()
        links = [x.strip() for x in text.splitlines() if x.strip()]
        require(1 <= len(links) <= 64, 'source_count')
        return links
    except (UnicodeError, ValueError):
        raise SubscriptionError('invalid_subscription_payload') from None


def build_catalog(de, source, now, ttl_hours=24, review_subset=False, openflux=None):
    validate_catalog(de, now)
    require(all(p['mode']=='bypass' and p['engine']=='olcrtc' for p in de['profiles']), 'DE_source_not_bypass_only')
    if openflux is not None:
        validate_catalog(openflux, now)
        require(all(p['mode']=='bypass' and p['engine']=='openflux' for p in openflux['profiles']), 'OpenFlux_source_not_bypass_only')
    require(1 <= ttl_hours <= 168, 'ttl_policy')
    owner = source.get('owner_source', source)
    checks = owner.get('canonical_checks')
    if checks is not None:
        require(all(checks.get(k) is True for k in ['local_admin','unique_active_subscription','remote_owner','independent_remote']), 'owner_identity_unverified')
    require(moment(owner['expires_at']) > now, 'VPN_source_expired')
    entries = owner.get('links', owner.get('profiles'))
    require(isinstance(entries,list) and 1 <= len(entries) <= 64, 'VPN_source_count')
    profiles, failures, protocols = [], collections.Counter(), collections.Counter()
    for index, entry in enumerate(entries, 1):
        try:
            if isinstance(entry,str):
                scheme = entry.split(':',1)[0].lower()
                protocols[scheme if scheme in {'vless','hysteria2','hy2','ss','trojan'} else 'other'] += 1
                require(scheme in {'vless','hysteria2','hy2'},'unsupported_vpn_protocol')
                settings, country = vless_settings(entry) if scheme=='vless' else hysteria2_settings(entry)
            else:
                protocols['xray-json'] += 1
                require(isinstance(entry,dict) and set(entry)=={'exit_country','settings'}, 'xray_source_keys')
                settings, country = entry['settings'], entry['exit_country']
                validate_xray(settings)
                require(isinstance(country,str) and re.fullmatch('[A-Z]{2}',country), 'profile_country')
            profiles.append({'id':f'vpn-{index}','name':f'VPN {country} · {index}','mode':'vpn','exit_country':country,'engine':'xray','settings':settings})
        except (SubscriptionError, ValueError, TypeError, KeyError, AttributeError) as error:
            code = str(error) if type(error) is SubscriptionError else 'invalid_profile_settings'
            failures[code] += 1
    receipt = {'status':'BLOCKED_FULL_SOURCE' if failures else 'LOCAL_ALL_SOURCE_CATALOG',
        'source_vpn_count':len(entries),'source_bypass_count':len(de['profiles']),
        'source_protocol_counts':dict(protocols),'supported_vpn_count':len(profiles),
        'rejected_vpn_count':sum(failures.values()),'rejection_counts':dict(failures),
        'all_source_profiles_included':not failures,'publication_ready':not failures,
        'source_expiry_match':checks.get('expiry_match') if checks else 'UNKNOWN',
        'remote_mutations':False,'https_publication':'NOT_RUN'}
    if failures and not review_subset:
        return None, receipt
    require(profiles, 'no_supported_vpn_profiles')
    bypass = copy.deepcopy(de['profiles'])
    if openflux is not None:
        bypass.extend(copy.deepcopy(openflux['profiles']))
    for index, p in enumerate(bypass, 1):
        p['id'] = f'bypass-{index}'
        if p['exit_country'] == 'DE':
            p['name'] = 'Германия #1' if p['engine'] == 'olcrtc' else 'Германия #2'
        else:
            p['name'] = f'{p["engine"]} {p["exit_country"]} · {index}'
    expiry = min(moment(de['expires_at']),moment(owner['expires_at']),now+timedelta(hours=ttl_hours))
    if openflux is not None:
        expiry = min(expiry,moment(openflux['expires_at']))
    catalog = {'schema_version':1,'catalog_id':'owner-'+secrets.token_hex(8),'revision':1,
        'expires_at':expiry.isoformat().replace('+00:00','Z'),'profiles':profiles+bypass,
        'dns_servers':copy.deepcopy(de['dns_servers']),'probe':copy.deepcopy(de['probe'])}
    validate_catalog(catalog, now)
    encoded = json.dumps(catalog,ensure_ascii=False,separators=(',',':')).encode()
    require(len(encoded) <= MAX_BYTES,'output_size')
    receipt.update({'output_profile_count':len(catalog['profiles']),'output_mode_counts':{'vpn':len(profiles),'bypass':len(bypass)},
        'output_bytes':len(encoded),'effective_expiry_future':True,'expiry_policy':'minimum of DE/source/TTL',
        'source_bypass_count':len(bypass),
        'source_openflux_count':len(openflux['profiles']) if openflux is not None else 0,
        'DE_settings_preserved':all(a['settings']==b['settings'] for a,b in zip(de['profiles'],bypass)),
        'output_sha256':hashlib.sha256(encoded).hexdigest()})
    if failures:
        receipt['status']='REVIEW_ONLY_NOT_PUBLISHABLE'
        receipt['publication_ready']=False
    return encoded, receipt


def restricted_read(path):
    require(not path.is_symlink() and path.resolve().is_relative_to(PRIVATE.resolve()),'input_outside_private')
    require(path.is_file() and path.stat().st_size <= MAX_BYTES,'input_size')
    return path.read_bytes()


def private_write(path, data):
    require(path.resolve().is_relative_to(PRIVATE.resolve()) or path.resolve().is_relative_to(ARTIFACTS.resolve()), 'output_outside_ignored_scope')
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--de-catalog',type=Path,required=True)
    parser.add_argument('--vpn-source',type=Path,required=True)
    parser.add_argument('--openflux-catalog',type=Path,help='Optional verified private OpenFlux lab catalog')
    parser.add_argument('--source-format',choices=['owner-json','vless','xray-json'],default='owner-json')
    parser.add_argument('--source-expiry')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--ttl-hours',type=int,default=24)
    parser.add_argument('--review-supported-subset',action='store_true',help='Explicitly nonpublishable review only; keeps rejection counts')
    args=parser.parse_args()
    de=strict_json(restricted_read(args.de_catalog)); raw=restricted_read(args.vpn_source)
    source = strict_json(raw) if args.source_format!='vless' else {'links':decode_vless_payload(raw),'expires_at':args.source_expiry}
    flux = strict_json(restricted_read(args.openflux_catalog)) if args.openflux_catalog else None
    payload,receipt=build_catalog(de,source,datetime.now(timezone.utc),args.ttl_hours,args.review_supported_subset,flux)
    private_write(args.receipt,json.dumps(receipt,indent=2).encode())
    if payload is not None:
        private_write(args.output,payload)
    print(json.dumps({k:v for k,v in receipt.items() if k!='output_sha256'},sort_keys=True))
    return 0 if receipt['publication_ready'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('{"status":"CATALOG_BUILD_FAILED_NO_PRIVATE_OUTPUT"}')
        sys.exit(1)
