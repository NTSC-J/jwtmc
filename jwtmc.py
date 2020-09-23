#!/usr/bin/env python3

import asyncio
import random
import sys
import json
from jwcrypto import jwt, jwk
from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK, JWKSet

# init
# 1. C -> S: {"type": "init_ctr", "nonce": 12345} (signed by C)
# 2. S -> C: {"type": "init_ctr_ok", "key": 1234, "nonce": 12345, "v": 42} (signed by S)

# access
# 1. C -> S: {"type": "access", "nonce0": 12346, "key": 1234, "inc": 1}
# 2. S -> C: {"type": "access_ack0", "nonce0": 12346, "nonce1": 23456}
# 3. C -> S: {"type": "access_ack1", "nonce0": 12346, "nonce1": 23456}
# 4. S -> C: {"type": "access_ok", "nonce0": 12346, "nonce1": 23456, "v": 43}

# error: {"type": "error", "info": "invalid_signature"/"invalid_request"/"nonce_mismatch"}

class MCData:
    """モノトニックカウンタサーバに保存されるデータ"""
    def __init__(self):
        self.ctr = dict()
        self.known_keys = JWKSet()

    def add_new(self, v, pubkey):
        k = random.randrange(2 ** 64)
        while k in self.ctr:
            k = random.randramge(2 ** 64)

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

class MCServer:
    def __init__(self, port=7777):
        self.port = port
        self.data = MCData()
        with open('server_private.pem', mode='rb') as f:
            self.privkey = JWK.from_pem(f.read())

    async def handle_client(self, reader, writer):
        reqline = (await reader.readline()).decode('utf-8').strip() # メッセージは改行で終端
        print(f'reqline: {reqline}')
        req = JWT(jwt = reqline)
        # FIXME: カプセル化……
        req.token.objects['valid'] = True
        reqclaims = json.loads(req.token.payload.decode('utf-8'))

        print(f'reqclaims: {reqclaims}')
        reqtype = reqclaims['type']
        if reqtype == 'init_ctr': # カウンタの初期化
            nonce = reqclaims['nonce']
            client_pubkey = JWK.from_json(reqclaims['pubkey'])

            vinit = 42 # TODO: 適切な初期値
            key = self.data.add_new(vinit, client_pubkey)

            res = self._msg({'type': 'init_ctr_ok', 'nonce': nonce, 'key': key, 'ctr': vinit})
            writer.write(res)
            await writer.drain()
        elif reqtype == 'access': # カウンタに0以上加算して結果を返す
            nonce0 = reqclaims['nonce0']
            key = reqclaims['key']
            inc = reqclaims['inc']

            client_pubkey = self.data.pubkey(key)

            try:
                req.token.verify(client_pubkey)
            except InvalidJWSSignature:
                res = self._msg({'type': 'error', 'info': 'invalid_signature'})
                writer.write(res)
                await writer.drain()
                return

            nonce1 = random.randrange(2 ** 64)
            res = self._msg({'type': 'access_ack0', 'nonce0': nonce0, 'nonce1': nonce1})
            writer.write(res)
            await writer.drain()

            reqline1 = (await reader.readline()).decode('utf-8').strip()
            req1 = JWT(jwt = reqline1, key = client_pubkey)
            # TODO: 署名検証の例外処理
            req1claims = json.loads(req1.claims)

            if req1claims['type'] != 'access_ack1':
                res = self._msg({'type': 'error', 'info': 'invalid_request'})
                writer.write(res)
                await writer.drain()
                return
            if req1claims['nonce0'] != nonce0 or req1claims['nonce1'] != nonce1:
                res = self._msg({'type': 'error', 'info': 'nonce_mismatch'})
                writer.write(res)
                await writer.drain()
                return

            v = self.data.increment(key, inc)
            res = self._msg({'type': 'access_ok', 'nonce0': nonce0, 'nonce1': nonce1, 'v': v})
            writer.write(res)
            await writer.drain()
        else:
            res = self._msg({'type': 'error', 'info': 'invalid_request'})
            writer.write(res)
            await writer.drain()

        writer.close()
        await writer.wait_closed()

    async def run(self):
        server = await asyncio.start_server(self.handle_client, port=self.port)
        print(f'serving on {[s.getsockname() for s in server.sockets]}')

        async with server:
            await server.serve_forever()

    def _msg(self, claims):
        msg = JWT(header = {'alg': 'RS256'}, claims = claims)
        msg.make_signed_token(self.privkey)
        return (msg.serialize() + '\n').encode('utf-8')

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
        print('init_ctr')
        reader, writer = await asyncio.open_connection(self.host, self.port)
        nonce = random.randrange(2 ** 64)
        pubkey = self.privkey.export_public()
        req = self._msg({'type': 'init_ctr', 'nonce': nonce, 'pubkey': pubkey})
        writer.write(req)
        await writer.drain()
        res = JWT(jwt = (await reader.readline()).decode('utf-8').strip(), key = self.server_pubkey)
        resclaims = json.loads(res.claims)
        if resclaims['type'] == 'init_ctr_ok':
            if resclaims['nonce'] != nonce:
                print('init_ctr: nonce mismatch')
                await close()
                return
            # TODO: verify res signature
            self.key = resclaims['key']
            print(f'got key = {self.key}')
        else:
            print(f'init_ctr failed: {resclaims}')

        async def close():
            writer.close()
            await writer.wait_closed()

        await close()

    async def access(self, inc = 0):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        nonce0 = random.randrange(2 ** 64)
        req = self._msg({'type': 'access', 'nonce0': nonce0, 'key': self.key, 'inc': inc})
        writer.write(req)
        await writer.drain()

        res = JWT(jwt = (await reader.readline()).decode('utf-8').strip(), key = self.server_pubkey)
        resclaims = json.loads(res.claims)
        if resclaims['type'] != 'access_ack0':
            print(f'access failed: {res.claims}')
            close()
            return
        if resclaims['nonce0'] != nonce0:
            print('nonce mismatch')
            close()
            return
        nonce1 = resclaims['nonce1']

        req = self._msg({'type': 'access_ack1', 'nonce0': nonce0, 'nonce1': nonce1})
        writer.write(req)
        await writer.drain()

        res = JWT(jwt = (await reader.readline()).decode('utf-8').strip(), key = self.server_pubkey)
        resclaims = json.loads(res.claims)
        if resclaims['type'] != 'access_ok':
            print(f'access failed: {res.claims}')
            await close()
            return
        if resclaims['nonce0'] != nonce0 or resclaims['nonce1'] != nonce1:
            print(f'access: nonce mismatch')
            await close()
            return
        # TODO: verify res signature
        print(f"access ok, v = {resclaims['v']}")

        async def close():
            writer.close()
            await writer.wait_closed()

        await close()

    def _msg(self, claims):
        print(f'claims = {claims}')
        msg = JWT(header = {'alg': 'RS256'}, claims = claims)
        msg.make_signed_token(self.privkey)
        return (msg.serialize() + '\n').encode('utf-8')

USAGE = """Usage: {name} (serve|client-cli)
"""
CLI_HELP = """commands:
init_ctr
access [inc]
help
"""

async def main(argv):
    async def cli(line):
        sline = line.split()
        if line == 'init_ctr':
            await client.init_ctr()
        elif len(sline) == 2 and sline[0] == 'access':
            await client.access(int(sline[1]))
        elif line == 'help':
            print(CLI_HELP)
        else:
            print(CLI_HELP)

    usage = USAGE.format(name=argv[0])
    if (len(argv) == 2 and argv[1] == 'serve'):
        server = MCServer()
        await server.run()
    elif (len(argv) >= 2 and argv[1] == 'client-cli'):
        client = MCClient()
        if len(argv) == 2:
            while True:
                print('jwtmc>', end='')
                await cli(input())
        else:
            await cli(' '.join(argv[2:]))
    else:
        print(usage)

if __name__ == '__main__':
    sys.exit(asyncio.run(main(sys.argv)))

