# Restify-auth
A Restify authorization middleware based on the jsonwebtoken module.

## Options

`restifyAuth(options)`

Options has the following parameters:
- **secret**: jwt.Secret. Defines JWT signature secret or a funciton to retrieve it.
- **algorithm?**: jwt.Algorithm. Defines JWT algorithm, default to "HS256".
- **expiresIn?**: string || number. Defines expiration time of token, default to "1h" (1 hour).
- **refreshRange?**: number. Defines a time range when to refresh the token, is a number in [0, 1].
    For example, expiresIn is '10 days' and resresh is 0.7, then:
    from day 1 to day 3, token is valid;
    from day 4 to day 10, the token is valid and a new token will be sent to the client;
    from day 11, the token expires.
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
import { restifyAuth } from '../index';

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
import { restifyAuth } from '../index';

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

server.get('/test', (req, res, next) => {
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
$ curl -H "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidGVzdGVyIiwiaWF0IjoxNjU2NTc4NzkxLCJleHAiOjE2NTY1ODIzOTF9.y_RoXlBaBiznQ8-furj4fA1-EPHCTaZaCc6MSuBsb70" "http://127.0.0.1:9001/payload"
{"user":"tester","iat":1656578791,"exp":1656582391}
```

3. Access with invalid token or without token, authorization is failed.
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
