import {
  Request, Response, Next, RequestHandler,
} from 'restify';
import { UnauthorizedError } from 'restify-errors';
import jwt from 'jsonwebtoken';

declare module 'restify' {
  // add property to "Request" to store jwt payload
  // eslint-disable-next-line no-shadow
  interface Request {
    [key: string]: string | jwt.JwtPayload | jwt.Jwt,
  }
}

export type Payload = string | jwt.JwtPayload | jwt.Jwt

export interface AuthResult {
  /**
   * Required, indicates the result of the authorization operation.
   */
  success: boolean,
  /**
   * Optional, payload for the new token.
   */
  payload?: string | jwt.JwtPayload,
  /**
   * Optional, some usefull message.
   */
  message?: string,
}

/**
 * A function that defines additional authentication operations.
 */
export interface AuthHandler {
  (req: Request, decoded?: Payload): AuthResult | Promise<AuthResult>
}

/**
 * A function that defines how to retrieve the JWT secret key.
 */
export interface SecretGetter {
  (req?: Request, decoded?: Payload) : jwt.Secret | Promise<jwt.Secret>;
}

/**
 * A function that defines how to get token.
 */
export interface TokenGetter {
  (req: Request): string | Promise<string>
}

/**
 * Options of restify-auth middleware.
 */
export interface AuthOptions {
  /**
   * Defines JWT signature secret or a funciton to retrieve it.
   */
  secret: jwt.Secret | SecretGetter,
  /**
   * Defines JWT algorithm, default to "HS256".
   */
  algorithm?: jwt.Algorithm,
  /**
   * Defines expiration time of token, default to "1h" (1 hour).
   */
  expiresIn?: string | number,
  /**
    * Defines a time range when to refresh the token, is a number in [0, 1].
    * For example, expiresIn is '10 days' and resresh is 0.7, then:
    * from day 1 to day 3, token is valid;
    * from day 4 to day 10, the token is valid and a new token will be sent to the client;
    * from day 11, the token expires.
    * Defaults to 0, the token will not refresh automatically.
   */
  refreshRange?: number,
  /**
   * Use this option to pass full JWT signing options when needed.
   * It will override the `secret`, `algorithm` and `expiresIn`.
   */
  signOptions?: jwt.SignOptions,
  /**
   * Use this option to pass full JWT verifying options when needed.
   * It will override the `secret`, `algorithm` and `expiresIn`.
   */
  verifyOptions?: jwt.VerifyOptions,
  /**
   * Defines header name where the token is placed, default to "authorization".
   */
  authHeader?: string,
  /**
   * Defines property name in request where the JWT payload is placed, default to "auth".
   */
  requestProperty?: string,
  /**
   * Define a function to get the token from somewhere else instead of `authHeader`.
   */
  getToken?: TokenGetter,
  /**
   * If the request path is in this list, token validation will be ignored.
   * Format: path[|method][,method],
   * e.g. ['/login', '/login|post', '/login|get,post']
   */
  ignored?: string[],
  /**
   * Define a function to perform additional token validation.
   * The default function returns True.
   */
  verifyHandler?: AuthHandler,
  /**
   * Define a function to perform additional token validation,
   * and then return the new payload for signing new token.
   * The default function returns True and the origin payload.
   */
  refreshHandler?: AuthHandler,
}

const prototype = (value: any): string => {
  const callPrototype = Object.prototype.toString.call(value);
  return callPrototype.split(' ')[1].replace(']', '');
};

/**
 * pick the origin payload data from decoded payload.
 * @param payload decoded payload
 * @returns origin payload data
 */
export const pickOriginPayload = (
  payload: Payload,
  complete: boolean = false,
): string | jwt.JwtPayload => {
  const exclude = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
  const newPayload = {} as jwt.JwtPayload;

  if (prototype(payload) === 'String') return payload as string;

  if (prototype(payload) === 'Object') {
    const oldPayload = (complete ? (payload as jwt.Jwt).payload : payload) as jwt.JwtPayload;

    Object.keys(oldPayload).forEach((key) => {
      if (!exclude.includes(key)) {
        newPayload[key] = oldPayload[key];
      }
    });
  }

  return newPayload;
};

/**
 * Set option to the given value if its type is correct, otherwise set to default.
 * @param givenValue given value
 * @param types expected types of this value
 * @param defaultValue default value
 * @returns given value / default value.
 */
export const setOption = <T>(givenValue: T, types: string, defaultValue: T): T => {
  if (givenValue && types.split('|').includes(prototype(givenValue))) return givenValue;
  return defaultValue;
};

export const restifyAuth = (opt: AuthOptions) => {
  if (!opt.secret) throw new Error('restify-auth: "secret" is missing');

  // define options
  const getSecret = setOption(
    opt.secret,
    'Function',
    async () => opt.secret as jwt.Secret,
  ) as SecretGetter;

  const algorithm = setOption(opt.algorithm, 'String', 'HS256') as jwt.Algorithm;
  const expiresIn = setOption(opt.expiresIn, 'String|Number', '1h') as string | number;
  const refreshRange = setOption(opt.refreshRange, 'Number', 0) as number;

  const signOption = setOption(
    opt.signOptions,
    'Object',
    { expiresIn, algorithm },
  ) as jwt.SignOptions;
  const verifyOptions = setOption(
    opt.verifyOptions,
    'Object',
    { algorithms: [algorithm] },
  ) as jwt.VerifyOptions;

  const requestProperty = setOption(opt.requestProperty, 'String', 'auth') as string;
  const authHeader = setOption(opt.authHeader, 'String', 'authorization') as string;
  const ignored = setOption(opt.ignored, 'Array', []) as Array<string>;

  const getToken = setOption(
    opt.getToken,
    'Function',
    (req) => req.header(authHeader),
  ) as TokenGetter;
  const verifyHandler = setOption(
    opt.verifyHandler,
    'Function',
    async () => ({ success: true }),
  ) as AuthHandler;
  const refreshHandler = setOption(
    opt.refreshHandler,
    'Function',
    async (req: Request) => ({
      success: true,
      payload: pickOriginPayload(req[requestProperty], verifyOptions.complete),
    }),
  ) as AuthHandler;

  /**
   * Authorization middleware for restify.
   */
  const authorizer: RequestHandler = async (req: Request, res: Response, next: Next) => {
    // do not verify token when the request is in ignored list.
    const ignoreRequest = ignored.some((item) => {
      const [path, methods] = item.split('|');

      if (!methods || !req.method) return path === req.path();
      return path === req.path() && methods.includes(req.method!.toLowerCase());
    });
    if (ignoreRequest) return next();

    try {
      const bearerToken = await getToken(req);
      if (!bearerToken) {
        throw new UnauthorizedError('token is required');
      }

      const tokenParts = bearerToken.split(' ');
      if (tokenParts.length !== 2) {
        throw new UnauthorizedError('bad token format');
      }

      const [scheme, token] = tokenParts;
      if (scheme !== 'Bearer') {
        throw new UnauthorizedError('bad token scheme');
      }

      let decoded: Payload;
      try {
        decoded = jwt.decode(token, { complete: verifyOptions.complete }) as Payload;
      } catch (err) {
        throw new UnauthorizedError(`jwt - ${(<Error>err).message}`);
      }

      const secret = await getSecret(req, decoded);
      try {
        jwt.verify(token, secret, verifyOptions);
      } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
          throw new UnauthorizedError('token has expired');
        } else {
          throw new UnauthorizedError(`jwt - ${(<Error>err).message}.`);
        }
      }

      const verifyResult = await verifyHandler(req, decoded);
      if (!verifyResult.success) {
        throw new UnauthorizedError('token has revoked');
      }

      req[requestProperty] = decoded;

      // refresh token
      const payload = verifyOptions.complete
        ? (decoded as jwt.Jwt).payload
        : decoded;

      if (prototype(payload) === 'Object') {
        const { iat, exp } = payload as jwt.JwtPayload;
        const now = Math.floor(Date.now() / 1000);

        if ((exp! - now) / (exp! - iat!) <= refreshRange) {
          const refreshResult = await refreshHandler(req, decoded);
          if (refreshResult.success) {
            const newPayload = refreshResult.payload || pickOriginPayload(payload);
            const newToken = jwt.sign(newPayload, secret, signOption);

            res.header(authHeader, `Bearer ${newToken}`);
          }
        }
      }

      return next();
    } catch (error) {
      return next(error);
    }
  };

  /**
   * A wrapper of jwt.sign.
   * @param payload jwt payload
   * @param req request
   * @returns Bearer token
   */
  const sign = async (payload: Payload, req?: Request) => {
    const secret = await getSecret(req);
    const token = jwt.sign(payload, secret, signOption);

    return `Bearer ${token}`;
  };

  return {
    authorizer,
    sign,
  };
};
