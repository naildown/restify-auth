# Restify-auth
A Restify authorization middleware based on the [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken) module.

## Options

`restifyAuth(options)`

Options has the following parameters:
- **secret**: jwt.Secret. Defines JWT signature secret or a funciton to retrieve it.
- **algorithm?**: jwt.Algorithm. Defines JWT algorithm, default to "HS256".
- **expiresIn?**: string || number. Defines expiration time of token, default to "1h" (1 hour).
  Expressed in seconds or a string describing a time span [zeit/ms](https://github.com/vercel/ms).
  Eg: 60, "2 days", "10h", "7d". A numeric value is interpreted as a seconds count. If you use a string be sure you provide the time units (days, hours, etc), otherwise milliseconds unit is used by default ("120" is equal to "120ms").
- **refreshRange?**: number. Defines a time range when to refresh the token, is a number in [0, 1].
    For example, expiresIn is '5 days' and resreshRange is 0.6, token will be refreshed when the client accesses server in the last 3 days (5 * 0.6).
    With this options, if the user has a valid token and accesses the server within a valid time, then the user can always log in without a password.
    Defaults to 0, the token will not refresh automatically. 
- **signOptions?**: jwt.SignOptions. Use this option to pass full JWT signing options when needed. It will override the `secret`, `algorithm` and `expiresIn`.
- **verifyOptions?**: jwt.VerifyOptions. Use this option to pass full JWT verifying options when needed. It will override the `secret`, `algorithm` and `expiresIn`.
- **authHeader?**: string. Defines header name where the token is placed, default to "authorization".
- **requestProperty**?: string. Defines property name in request where the JWT payload is placed, default to "auth".
- **getToken?**: function. Define a function to get the token from somewhere else instead of `authHeader`.
- **ignored?**: string[]. Defines ignored request list. If the request is in this list, token validation will be ignored. Usually the login path needs to be added to here.
- **verifyHandler?**: function. Define a function to perform additional token validation. The default function will return True.
- **refreshHandler?**: function. Define a function to perform additional token validation and return the new payload for signing token. The default function will return True and the origin payload.


## Installtion

```
npm i -S restify-auth
```

## Usage
### Basic usage (default algorithm is HS256).
```
import { restifyAuth } from 'restify-auth';

server.get(
  '/test', 
  restifyAuth({ secret: 'test-secret' }).authorizer,
  (req, res, next) => res.send('Authorized!'),
)
```

### Use authorization middleware.
1. restify server code.
```
import { createServer, plugins } from 'restify';
import { restifyAuth } from 'restify-auth';

const server = createServer({
  name: 'test-server',
  version: '1.0.0',
});

// set restify-auth
const auth = restifyAuth({
  secret: 'test-secret', // "secret" is required
  ignored: ['/login|post'], // do not verify token when login
});

server.use(plugins.queryParser());
server.use(plugins.bodyParser());

// use restify-auth middleware
server.use(auth.authorizer);

server.get('/getauth', (req, res, next) => {
  res.send(req.auth); // if token is valid, the payload is stored to Request.auth.
});

// Defines login handler to sign token.
server.post('/login', async (req, res, next) => {
  const user = req.body.user || '';

  if (user === 'tester') {
    const token = await auth.sign({ user }); // use restifyAuth.sign() to sign a new token

    res.header('authorization', token);
    res.send({ success: true });
  } else {
    res.send({ success: false });
  }
});

server.listen(9001, '127.0.0.1', () => {
  console.log('%s listening at %s', server.name, server.url);
});
```

2. Login with correct user, the server will send the token.
```
$ curl -i -s -X POST -d user=tester -l "http://127.0.0.1:9001/login"
HTTP/1.1 200 OK    
Server: test-server
authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdGVyIiwiaWF0IjoxNjU2NTc4NzkxLCJleHAiOjE2NTY1ODIzOTF9.y_RoXlBaBiznQ8-furj4fA1-EPHCTaZaCc6MSuBsb70   
Content-Type: application/json
Content-Length: 16
Date: Thu, 30 Jun 2022 08:46:31 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"success":true}
```

3. Access with correct token, authorization is passed.
```
$ curl -H "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdGVyIiwiaWF0IjoxNjU2NTc4NzkxLCJleHAiOjE2NTY1ODIzOTF9.y_RoXlBaBiznQ8-furj4fA1-EPHCTaZaCc6MSuBsb70" "http://127.0.0.1:9001/getauth"
{"user":"tester","iat":1656578791,"exp":1656582391}
```

4. Access with invalid token or without token, authorization is failed.
```
$ curl -H "authorization: Bearer 111.222.333" http://127.0.0.1:9001/getauth
{"code":"Unauthorized","message":"jwt - invalid token."}
```
```
$ curl -i http://127.0.0.1:9001/getauth
HTTP/1.1 401 Unauthorized
Server: test-server
Content-Type: application/json
Content-Length: 53
Date: Thu, 30 Jun 2022 09:46:08 GMT
Connection: keep-alive
Keep-Alive: timeout=5

{"code":"Unauthorized","message":"token is required"}
```

### Set expiration and refresh range

```
const auth = restifyAuth({
  secret: 'test-secret',
  expiresIn: '15m',   // token will be expired in 15 minutes.
})
```
```
const auth = restifyAuth({
  secret: 'test-secret',
  expiresIn: '10d',  // token will be expired in 10 days
  refreshRange: 0.6,
  // when the user accesses server with a valid token at:
  //   day 1 to day 4, authorization is passed;
  //   day 5 to day 10, authorization is passed and a new issued token is sent to the client;
  //   after day 11, authorization will be failed if the token has not been updated;
})
```

### Use full jwt sign/verify options
- Refer to [jsonwebtoken#usage](https://www.npmjs.com/package/jsonwebtoken#usage)
```
const auth = restifyAuth({
  secret: 'test-secret',
  signOptions: {
    algorithm: 'HS256',
    expiresIn: '10h',
    issuer: 'server'
    audience: 'client01'
    subject: 'test'
    ...
  },
  verifyOptions: {
    algorithm: ['HS256'],
    issuer: 'server'
    audience: /client\d{2}/
    subject: 'test'
    ...
  },
})
```

### Retrieve secret from other sources
- You can define a funciton to retrieve secret from other sources.
```
const auth = restifyAuth({
  secret: async (req?: Request, decoded?: jwtPayload) => {
    // retrieve
    return secret;
  }
})
```

### Additional validation
- You can define a funciton to perform additional validation when verify/refresh token.
```
(async) funciton (req: Request, decoded?: jwtPayload) => {
  success: boolean,
  payload?: string | jwt.JwtPayload, // new payload
  message?: string,
}
```

```
const auth = restifyAuth({
  secret: 'test-secret',
  verifyHandler: async (req) => {
    // ...
    return {
      success: !isRevoked(req);
    }
  },
  refreshHandler: async (req, decoded) => {
    // ...
    return {
      success: true,
      payload: {
        user: req.query.user,
        someNewData: '',
      },
      message: 'token is valid and need to be refreshed, send a new one',
    }
  },
})
```

### Error handling
- `UnauthorizedError` (status: 401) will be thrown when the token is invalid, Restify will send this error to client, you can also add custom logic to handle this error.
```
server.on('restifyError', (req, res, err, callback) => {
  if (err.code === 'Unauthorized') {
    res.send({
      success: false,
      message: 'Login failed.',
    });
  }
  return callback();
});
```