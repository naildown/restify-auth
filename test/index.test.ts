/* eslint-disable func-names, prefer-arrow-callback, object-shorthand */

import fs from 'fs';
import assert from 'assert';
import { Request, Response } from 'restify';
import jwt from 'jsonwebtoken';
import { describe, it } from 'mocha';
import { AuthOptions, pickOriginPayload, restifyAuth } from '../index';

const sleep = (timeToDelay: number) => new Promise(
  (resolve) => {
    setTimeout(resolve, timeToDelay);
  },
);
const secret = 'wQIhAP3BdSSg6affft1NF+7MgF0SXPAXgDBdcMDtO+G+M0MJAiEA7DQbCGZIApJ5';
const payload = { user: 'test' };
const priKey = '-----BEGIN RSA PRIVATE KEY-----\n'
  + 'MIIBOgIBAAJBAOoh/hVKkRH4DJNvaJAFXEyLG+BmQWLBAykOtp2F+nBR6svdWDrS\n'
  + 'H54VVDKqkRIFyHhZhsm6QUScTAyxNH2Bu1ECAwEAAQJAT5ekr4o8zNX9OHWsHyGj\n'
  + 'YeX8YQmB+tdQgrmcvOoZ2+pmjnOHVzKaApf/ctSbFfznxuo9xEOhN72i5kdTEaBp\n'
  + 'wQIhAP3BdSSg6affft1NF+7MgF0SXPAXgDBdcMDtO+G+M0MJAiEA7DQbCGZIApJ5\n'
  + 'n1iGSEsDiDIs12288Ft1AdtOAn9JYAkCICCMLdBS62Vi30zXVJiGlnhZoJ4TBZgu\n'
  + 'hAXa5/FeigixAiB2fFDPLteSir19xF9f5lk4Ocsqqb6sZ4RTURpZwFYjWQIhAPN8\n'
  + 'ssw9XDEkTWaWLbVJovY8ks7N8NVjmDmRiUqJI0s5\n'
  + '-----END RSA PRIVATE KEY-----\n';
const pubKey = '-----BEGIN PUBLIC KEY-----\n'
  + 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOoh/hVKkRH4DJNvaJAFXEyLG+BmQWLB\n'
  + 'AykOtp2F+nBR6svdWDrSH54VVDKqkRIFyHhZhsm6QUScTAyxNH2Bu1ECAwEAAQ==\n'
  + '-----END PUBLIC KEY-----\n';

describe('Test restify-auth:', function () {
  this.timeout(6000);
  it('should obtain a valid token via restify-auth.sign()', async function () {
    const mw = restifyAuth({ secret });
    const token = await mw.sign(payload);
    const decoded = jwt.verify(token.split(' ')[1], secret);

    assert.deepEqual(pickOriginPayload(decoded), payload);
  });

  it('should pass when the request has a valid token', async function () {
    const mw = restifyAuth({ secret });
    const token = await mw.sign(payload);
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
    assert.deepEqual(pickOriginPayload(req.auth), payload);
  });

  it('should pass when the request is ignored', async function () {
    const mw = restifyAuth({ secret, ignored: ['/test1', '/test2|post,delete'] });
    const req1 = { header: (key) => '', path: () => '/test1', method: 'GET' } as Request;
    const req2 = { header: (key) => '', path: () => '/test1', method: 'POST' } as Request;
    const req3 = { header: (key) => '', path: () => '/test2', method: 'POST' } as Request;
    const req4 = { header: (key) => '', path: () => '/test2', method: 'GET' } as Request;
    const req5 = { header: (key) => '', path: () => '/test3', method: 'GET' } as Request;

    await mw.authorizer(req1, {} as Response, (err) => assert.ifError(err));
    await mw.authorizer(req2, {} as Response, (err) => assert.ifError(err));
    await mw.authorizer(req3, {} as Response, (err) => assert.ifError(err));
    await mw.authorizer(req4, {} as Response, (err) => {
      assert.equal(err.message, 'token is required');
    });
    await mw.authorizer(req5, {} as Response, (err) => {
      assert.equal(err.message, 'token is required');
    });
  });

  it('should refresh the token when it is in the refresh range', async function () {
    // this.timeout(6000);
    const mw = restifyAuth({ secret, expiresIn: 4, refreshRange: 0.75 });
    const token = await mw.sign(payload);
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;
    const res = {
      header: (name: string, value: string) => {
        assert.equal(name, 'authorization');
        const decoded = jwt.verify(value.split(' ')[1], secret) as jwt.JwtPayload;
        assert.deepEqual(pickOriginPayload(decoded), payload);
        assert.equal(decoded.iat! - Math.floor(Date.now() / 1000), 0);
      },
    } as Response;

    await sleep(1500);
    await mw.authorizer(req, res, (err) => {
      assert.ifError(err);
    });
  });

  it('should not refresh token when refresh handler returns false', async function () {
    // this.timeout(6000);
    const mw = restifyAuth({
      secret,
      expiresIn: 4,
      refreshRange: 0.75,
      refreshHandler: async () => ({ success: false }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key) => token,
      path: () => '/test',
      method: 'GET',
    } as Request;
    const res = {
      headers: {},
      header: function (name: string, value: string) {
        this.headers[name] = value;
      },
    } as Response;

    await sleep(1500);
    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
    assert.deepEqual(res.headers, {});
  });

  it('should work with asymmetric algorithm', async function () {
    const mw = restifyAuth({
      secret: pubKey,
      algorithm: 'RS256',
    });
    const token = `Bearer ${jwt.sign(payload, priKey, { algorithm: 'RS256' })}`;
    const req = {
      header: (key) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
    assert.deepEqual(pickOriginPayload(req.auth), payload);
  });

  it('should work with custom functions to get secret', async function () {
    const mw = restifyAuth({
      secret: async () => pubKey,
      algorithm: 'RS256',
    });
    const token = `Bearer ${jwt.sign(payload, priKey, { algorithm: 'RS256' })}`;
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
    assert.deepEqual(pickOriginPayload(req.auth), payload);
  });

  it('should work with signOptions and verifyOptions', async function () {
    const mw = restifyAuth({
      secret,
      algorithm: 'RS256',
      expiresIn: 60,
      signOptions: {
        expiresIn: '1h',
        issuer: 'jwt',
        subject: 'test',
        algorithm: 'HS512',
      },
      verifyOptions: {
        complete: true,
        issuer: 'jwt',
        subject: 'test',
        algorithms: ['HS512'],
      },
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });

    const auth = req.auth as jwt.Jwt;
    const authHeader = auth.header;
    const authPayload = auth.payload as jwt.JwtPayload;
    assert.equal(authHeader.alg, 'HS512');
    assert.equal((authPayload.exp! - authPayload.iat!), 3600);
    assert.equal(authPayload.iss, 'jwt');
    assert.equal(authPayload.sub, 'test');
  });

  it('should work with custom getToken functions', async function () {
    const mw = restifyAuth({
      secret,
      getToken: async (req) => req.query.token,
    });
    const token = await mw.sign(payload);
    const req = {
      path: () => '/test',
      query: { token },
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
  });

  it('should work with custom verify functions', async function () {
    const mw = restifyAuth({
      secret,
      verifyHandler: async (req) => ({ success: req.query.verify }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      query: { verify: true },
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.ifError(err);
    });
  });

  it('should work with custom refresh functions', async function () {
    // this.timeout(6000);
    const refreshPayload = { user: 'test', refreshed: true };
    const mw = restifyAuth({
      secret,
      expiresIn: 4,
      refreshRange: 0.75,
      refreshHandler: (req) => ({
        success: req.query.refresh,
        payload: refreshPayload,
      }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      query: { refresh: true },
      method: 'GET',
    } as Request;
    const res = {
      header: (name: string, value: string) => {
        assert.equal(name, 'authorization');
        const decoded = jwt.verify(value.split(' ')[1], secret) as jwt.JwtPayload;
        assert.equal((decoded.exp! - decoded.iat!), 4);
        assert.deepEqual(pickOriginPayload(decoded), refreshPayload);
      },
    } as Response;

    await sleep(1500);
    await mw.authorizer(req, res, (err) => {
      assert.ifError(err);
    });
  });

  it('should throw error when the secret is missing', async function () {
    try {
      const mw = restifyAuth({} as AuthOptions);
    } catch (err) {
      assert.equal((<Error>err).message, 'restify-auth: "secret" is missing');
    }
  });

  it('should throw error when the token is expired', async function () {
    const mw = restifyAuth({ secret, expiresIn: 1 });
    const token = await mw.sign(payload);
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await sleep(1500);
    await mw.authorizer(req, {} as Response, (err) => {
      assert.equal(err.name, 'UnauthorizedError');
      assert.equal(err.code, 'Unauthorized');
      assert.equal(err.message, 'token has expired');
    });
  });

  it('should throw error when the token format is incorrect', async function () {
    const mw = restifyAuth({ secret });
    const req = {
      header: (key: string) => jwt.sign(payload, secret),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.equal(err.message, 'bad token format');
    });
  });

  it('should throw error when the token is not Bearer', async function () {
    const mw = restifyAuth({ secret });
    const req = {
      header: (key: string) => `Basic ${jwt.sign(payload, secret)}`,
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.equal(err.message, 'bad token scheme');
    });
  });

  it('should throw error when the token is invalid', async function () {
    const mw = restifyAuth({ secret });
    const req = {
      header: (key: string) => 'Bearer aaaaa.bbbbb.ccccc',
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert(err.message.includes('jwt -'));
    });
  });

  it('should throw error when the secret is wrong', async function () {
    const mw = restifyAuth({ secret });
    const token = `Bearer ${jwt.sign(payload, '1234')}`;
    const req = {
      header: (key: string) => (key === 'authorization' ? token : ''),
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert(err.message.includes('jwt -'));
    });
  });

  it('should throw error when the token is empty', async function () {
    const mw = restifyAuth({ secret });
    const req = {
      header: (key) => '',
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.equal(err.message, 'token is required');
    });
  });

  it('should throw error when verify handler returns false', async function () {
    const mw = restifyAuth({
      secret,
      verifyHandler: async () => ({ success: false }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key) => token,
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert.equal(err.message, 'token has revoked');
    });
  });

  it('should throw error when verify handler throws error', async function () {
    const mw = restifyAuth({
      secret,
      verifyHandler: async () => ({
        success: (await fs.promises.readFile('asdfasdf')).includes('abc'),
      }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key) => token,
      path: () => '/test',
      method: 'GET',
    } as Request;

    await mw.authorizer(req, {} as Response, (err) => {
      assert(err.message.includes('no such file or directory'));
    });
  });

  it('should throw error when refresh handler throws error', async function () {
    // this.timeout(6000);
    const mw = restifyAuth({
      secret,
      expiresIn: 4,
      refreshRange: 0.75,
      refreshHandler: async () => ({
        success: (await fs.promises.readFile('asdfasdf')).includes('abc'),
      }),
    });
    const token = await mw.sign(payload);
    const req = {
      header: (key) => token,
      path: () => '/test',
      method: 'GET',
    } as Request;

    await sleep(1500);
    await mw.authorizer(req, {} as Response, (err) => {
      assert(err.message.includes('no such file or directory'));
    });
  });
});
