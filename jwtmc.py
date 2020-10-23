#!/usr/bin/env python3

import asyncio
import random
import sys
import json
import time
from jwcrypto import jwt, jwk
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK, JWKSet

# init
# 1. C -> S: {"msgtype": "ctr_init", "nonce": 12345} (signed by C)
# 2. S -> C: {"msgtype": "ctr_init_ok", "key": 1234, "nonce": 12345, "ctr": 42} (signed by S)

# access
# 1. C -> S: {"msgtype": "ctr_access", "nonce0": 12346, "key": 1234, "inc": 1}
# 2. S -> C: {"msgtype": "ctr_access_ack0", "nonce0": 12346, "nonce1": 23456}
# 3. C -> S: {"msgtype": "ctr_access_ack1", "nonce0": 12346, "nonce1": 23456}
# 4. S -> C: {"msgtype": "ctr_access_ok", "nonce0": 12346, "nonce1": 23456, "ctr": 43}

# time
# 1. C -> S: {"msgtype": "time_query", "nonce": 12347}
# 2. S -> C: {"msgtype": "time_answer", "nonce": 12347, "time": 1601286372.123} (seconds from epoch)

# error: {"msgtype": "error", "info": "invalid_signature"/"invalid_request"/"nonce_mismatch"}

class MCData:
    """モノトニックカウンタサーバに保存されるデータ"""
    def __init__(self):
        self.ctr = dict()
        self.known_keys = JWKSet()

    def add_new(self, v, pubkey):
        k = random.randrange(2 ** 32)
        while k in self.ctr:
            k = random.randramge(2 ** 32)

        self.ctr[k] = [v, pubkey]
        self.known_keys.add(pubkey)
        return k

    def increment(self, key, inc = 1):
        if inc < 0:
            raise ValueError('tried to subtract')
        if key in self.ctr:
            self.ctr[key][0] = self.ctr[key][0] + inc
            return self.ctr[key][0]
        else:
            raise KeyError('no key')

    def pubkey(self, key):
        return self.ctr[key][1]

# メッセージは改行区切りのJWT
async def read(reader, key = None):
    s = (await reader.readline()).decode('utf-8').strip()
    r = JWT(jwt = s, key = key)
    return r

async def write(writer, claims, signing_key):
    print(f'write: {claims}')
    msg = JWT(header = {'alg': 'RS256'}, claims = claims)
    msg.make_signed_token(signing_key)
    writer.write((msg.serialize() + '\n').encode('utf-8'))
    await writer.drain()

class MCServer:
    def __init__(self, port=7777):
        self.port = port
        self.data = MCData()
        with open('server_private.pem', mode='rb') as f:
            self.privkey = JWK.from_pem(f.read())

    async def handle_client(self, reader, writer):
        try:
            req = await read(reader)
            # FIXME: カプセル化……
            # jwcryptoではJWTの署名を検証する前にペイロードにアクセスする良い方法がない
            req.token.objects['valid'] = True
            reqclaims = json.loads(req.token.payload.decode('utf-8'))
            print(f"got claims: {reqclaims}")

            reqtype = reqclaims['msgtype']
            print(f"msgtype: {reqtype}")
            if reqtype == 'ctr_init': # カウンタの初期化
                nonce = reqclaims['nonce']
                client_pubkey = JWK.from_json(reqclaims['pubkey'])

                vinit = 42 # TODO: 適切な初期値
                key = self.data.add_new(vinit, client_pubkey)

                await write(writer, {'msgtype': 'ctr_init_ok', 'nonce': nonce, 'key': key, 'ctr': vinit}, self.privkey)

            elif reqtype == 'ctr_access': # カウンタに0以上加算して結果を返す
                nonce0 = reqclaims['nonce0']
                key = reqclaims['key']
                inc = reqclaims['inc']

                # key がわからないと対応する公開鍵もわからない
                client_pubkey = self.data.pubkey(key)

                # reqのロード時に検証できなかったのでここで検証
                try:
                    req.token.verify(client_pubkey)
                except InvalidJWSSignature:
                    await write(writer, {'msgtype': 'error', 'info': 'invalid_signature'}, self.privkey)
                    return

                nonce1 = random.randrange(2 ** 32)
                await write(writer, {'msgtype': 'ctr_access_ack0', 'nonce0': nonce0, 'nonce1': nonce1}, self.privkey)

                req1 = await read(reader, client_pubkey)
                print(f'req1: {req1.claims}')
                # TODO: 署名検証の例外処理
                req1claims = json.loads(req1.claims)
                print(f'got claims: {req1claims}')

                if req1claims['msgtype'] != 'ctr_access_ack1':
                    await write(writer, {'msgtype': 'error', 'info': 'invalid_request'}, self.privkey)
                    return
                if req1claims['nonce0'] != nonce0 or req1claims['nonce1'] != nonce1:
                    await write(writer, {'msgtype': 'error', 'info': 'nonce_mismatch'}, self.privkey)
                    return

                v = self.data.increment(key, inc)
                await write(writer, {'msgtype': 'ctr_access_ok', 'nonce0': nonce0, 'nonce1': nonce1, 'ctr': v}, self.privkey)

            elif reqtype == 'time_query': # 時刻のクエリ
                # クエリの署名検証はしない
                nonce = reqclaims["nonce"]
                t = time.time()

                await write(writer, {'msgtype': 'time_answer', 'time': t, 'nonce': nonce}, self.privkey)

            else: # 不明なリクエスト
                await write(writer, {'msgtype': 'error', 'info': 'invalid_request'}, self.privkey)

        #except KeyError:
        #    await write(writer, {'msgtype': 'error', 'info': 'key_error'}, self.privkey)

        except ValueError:
            await write(writer, {'msgtype': 'error', 'info': 'value_error'}, self.privkey)

        #except InvalidJWSSignature:
        #    await write(writer, {'msgtype': 'error', 'info': 'invalid_signature'}, self.privkey)

        finally:
            writer.close()
            await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(self.handle_client, port=self.port)
        print(f'serving on {[s.getsockname() for s in server.sockets]}')

        async with server:
            await server.serve_forever()

class MCClient:
    def __init__(self, host='localhost', port=7777, key = None):
        self.host = host
        self.port = port
        self.key = key
        with open('client_private.pem', mode='rb') as f:
            self.privkey = JWK.from_pem(f.read())
        with open('server_public.pem', mode='rb') as f:
            self.server_pubkey = JWK.from_pem(f.read())

    async def init_ctr(self):
        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)
            nonce = random.randrange(2 ** 32)
            pubkey = self.privkey.export_public()
            await write(writer, {'msgtype': 'ctr_init', 'nonce': nonce, 'pubkey': pubkey}, self.privkey)
            res = await read(reader, self.server_pubkey)
            resclaims = json.loads(res.claims)
            if resclaims['msgtype'] == 'ctr_init_ok':
                if resclaims['nonce'] != nonce:
                    print('init_ctr: nonce mismatch')
                    raise Exception('nonce mismatch')
                self.key = resclaims['key']
                print(f'got key = {self.key}')
            else:
                print(f'init_ctr failed: {resclaims}')

        except Exception:
            pass

        finally:
            writer.close()
            await writer.wait_closed()

    async def access(self, inc = 0):
        if self.key is None:
            print('key not set')
            return

        try:
            reader, writer = await asyncio.open_connection(self.host, self.port)

            nonce0 = random.randrange(2 ** 32)
            await write(writer, {'msgtype': 'ctr_access', 'nonce0': nonce0, 'key': self.key, 'inc': inc}, self.privkey)

            res = await read(reader, self.server_pubkey)
            resclaims = json.loads(res.claims)
            if resclaims['msgtype'] != 'ctr_access_ack0':
                print(f'access failed: {res.claims}')
                raise Exception('access failed')
            if resclaims['nonce0'] != nonce0:
                print('nonce mismatch')
                raise Exception('nonce mismatch')
            nonce1 = resclaims['nonce1']

            await write(writer, {'msgtype': 'ctr_access_ack1', 'nonce0': nonce0, 'nonce1': nonce1}, self.privkey)

            res = await read(reader, self.server_pubkey)
            resclaims = json.loads(res.claims)
            if resclaims['msgtype'] != 'ctr_access_ok':
                print(f'access failed: {res.claims}')
                raise Exception('access failed')
            if resclaims['nonce0'] != nonce0 or resclaims['nonce1'] != nonce1:
                print(f'access: nonce mismatch')
                raise Exception('nonce mismatch')
            print(f"access ok, v = {resclaims['v']}")

        except Exception:
            pass

        finally:
            writer.close()
            await writer.wait_closed()

    async def query_time(self):
        reader, writer = await asyncio.open_connection(self.host, self.port)

        nonce = random.randrange(2 ** 32)
        await write(writer, {'msgtype': 'time_query', 'nonce': nonce}, self.privkey)

        res = await read(reader, self.server_pubkey)
        resclaims = json.loads(res.claims)
        if resclaims['msgtype'] != 'time_answer':
            print(f'access failed: {res.claims}')
            return
        if resclaims['nonce'] != nonce:
            print('nonce mismatch')
            return

        writer.close()
        await writer.wait_closed()

        return resclaims['time']

    def set_key(self, key):
        self.key = key

USAGE = """Usage: {name} (serve|client-cli)
"""
CLI_HELP = """commands:
init_ctr
access inc
set_key key
query_time
help
"""

async def main(argv):
    async def cli(line):
        sline = line.split()
        if line == 'init_ctr':
            await client.init_ctr()
        elif len(sline) == 2 and sline[0] == 'access':
            await client.access(int(sline[1]))
        elif len(sline) == 2 and sline[0] == 'set_key':
            client.set_key(int(sline[1]))
        elif len(sline) == 1 and sline[0] == 'query_time':
            print(await client.query_time())
        elif line == 'help':
            print(CLI_HELP, end='')
        else:
            print(CLI_HELP, end='')

    usage = USAGE.format(name=argv[0])
    if (len(argv) == 2 and argv[1] == 'serve'):
        server = MCServer()
        await server.run()
    elif (len(argv) >= 2 and argv[1] == 'client-cli'):
        client = MCClient()
        if len(argv) == 2:
            while True:
                print('jwtmc> ', end='')
                await cli(input())
        else:
            await cli(' '.join(argv[2:]))
    else:
        print(usage, end='')

if __name__ == '__main__':
    sys.exit(asyncio.run(main(sys.argv)))

