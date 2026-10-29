import { lookup } from 'node:dns/promises';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { BlockList, isIP } from 'node:net';

/**
 * Outbound HTTP for integrations, built to resist server-side request
 * forgery:
 *  - only http(s); http only when explicitly allowed (development)
 *  - no credentials embedded in URLs
 *  - every resolved address is checked against private, loopback,
 *    link-local, multicast, and reserved ranges (unless explicitly allowed)
 *  - the connection is pinned to the validated address, so a second DNS
 *    answer (rebinding) cannot redirect it
 *  - redirects are never followed
 *  - bounded time (AbortSignal) and bounded response size
 * This is not a general-purpose fetch facility: it exposes only status and
 * size, never the response body, to callers.
 */

export class SafeHttpError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'SafeHttpError';
  }
}

const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 23],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['fec0::', 10],
  ['ff00::', 8],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

/** Extract an embedded IPv4 address from an IPv4-mapped/compatible IPv6 address. */
function embeddedIpv4(v6: string): string | null {
  const lower = v6.toLowerCase();
  const dotted = /^(?:::ffff:|::)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (dotted) return dotted[1]!;
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(lower);
  if (hex) {
    const hi = parseInt(hex[1]!, 16);
    const lo = parseInt(hex[2]!, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) {
    const v4 = embeddedIpv4(address);
    if (v4) return blocked.check(v4, 'ipv4');
    return blocked.check(address, 'ipv6');
  }
  return true; // not an IP address: refuse
}

export interface UrlPolicy {
  allowInsecureHttp: boolean;
  allowPrivateNetwork: boolean;
}

/** Static URL checks that need no network access. Returns an error code or null. */
export function checkUrlPolicy(raw: string, policy: UrlPolicy): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'INVALID_URL';
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && policy.allowInsecureHttp)) {
    return 'SCHEME_NOT_ALLOWED';
  }
  if (url.username || url.password) return 'CREDENTIALS_IN_URL';
  if (!url.hostname) return 'INVALID_URL';
  if (url.hash) return 'FRAGMENT_NOT_ALLOWED';
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) && !policy.allowPrivateNetwork && isBlockedAddress(host)) {
    return 'DESTINATION_NOT_ALLOWED';
  }
  if (!policy.allowPrivateNetwork && /(^|\.)(localhost|local|internal)$/i.test(host)) {
    return 'DESTINATION_NOT_ALLOWED';
  }
  return null;
}

export async function resolveAllowedAddress(
  hostname: string,
  policy: UrlPolicy,
): Promise<{ address: string; family: 4 | 6 }> {
  const host = hostname.replace(/^\[|\]$/g, '');
  let addresses: { address: string; family: number }[];
  if (isIP(host)) {
    addresses = [{ address: host, family: isIP(host) }];
  } else {
    try {
      addresses = await lookup(host, { all: true, verbatim: true });
    } catch {
      throw new SafeHttpError('DNS_RESOLUTION_FAILED');
    }
  }
  if (addresses.length === 0) throw new SafeHttpError('DNS_RESOLUTION_FAILED');
  // If any answer is disallowed, refuse: attackers control which answer is used.
  if (!policy.allowPrivateNetwork && addresses.some((a) => isBlockedAddress(a.address))) {
    throw new SafeHttpError('DESTINATION_NOT_ALLOWED');
  }
  const first = addresses[0]!;
  return { address: first.address, family: first.family === 6 ? 6 : 4 };
}

export interface SafeGetResult {
  status: number;
  bytesRead: number;
  latencyMs: number;
}

export async function safeHttpGet(
  rawUrl: string,
  opts: UrlPolicy & {
    signal: AbortSignal;
    headers?: Record<string, string>;
    maxBytes?: number;
  },
): Promise<SafeGetResult> {
  const policyError = checkUrlPolicy(rawUrl, opts);
  if (policyError) throw new SafeHttpError(policyError);
  const url = new URL(rawUrl);
  const started = performance.now();
  const { address } = await resolveAllowedAddress(url.hostname, opts);
  const hostHeader = url.host;
  const isHttps = url.protocol === 'https:';
  const maxBytes = opts.maxBytes ?? 65536;
  const servername = isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname;

  return new Promise<SafeGetResult>((resolve, reject) => {
    const req = (isHttps ? httpsRequest : httpRequest)(
      {
        host: address,
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers: {
          ...opts.headers,
          host: hostHeader,
          'user-agent': 'AEGIS-Probe/0.1',
          accept: '*/*',
        },
        signal: opts.signal,
        ...(isHttps ? { servername, rejectUnauthorized: true } : {}),
      },
      (res: IncomingMessage) => {
        let bytes = 0;
        res.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > maxBytes) res.destroy();
        });
        const done = () =>
          resolve({
            status: res.statusCode ?? 0,
            bytesRead: Math.min(bytes, maxBytes),
            latencyMs: Math.round(performance.now() - started),
          });
        res.on('end', done);
        res.on('close', done);
        res.on('error', () => done());
      },
    );
    req.on('error', (err: NodeJS.ErrnoException) => {
      if (opts.signal.aborted || err.name === 'AbortError')
        return reject(new SafeHttpError('TIMEOUT'));
      reject(new SafeHttpError(classifyNetworkError(err)));
    });
    req.end();
  });
}

function classifyNetworkError(err: NodeJS.ErrnoException): string {
  switch (err.code) {
    case 'ECONNREFUSED':
      return 'CONNECTION_REFUSED';
    case 'ECONNRESET':
      return 'CONNECTION_RESET';
    case 'ETIMEDOUT':
      return 'TIMEOUT';
    case 'EHOSTUNREACH':
    case 'ENETUNREACH':
      return 'HOST_UNREACHABLE';
    default:
      if (err.code?.startsWith('ERR_TLS') || /certificate|self.signed|SSL/i.test(err.message)) {
        return 'TLS_ERROR';
      }
      return 'NETWORK_ERROR';
  }
}
