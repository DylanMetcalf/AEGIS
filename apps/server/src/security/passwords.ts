import { hash, verify } from '@node-rs/argon2';

/**
 * Argon2id with OWASP-recommended parameters (19 MiB, t=2, p=1). Hashes are
 * self-describing, so parameters can be raised later; verify() reads them
 * from the stored hash.
 */
const ARGON2_OPTIONS = {
  algorithm: 2, // Argon2id
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(password: string): Promise<string> {
  return hash(password, ARGON2_OPTIONS);
}

let dummyHash: Promise<string> | null = null;

/**
 * Verify a password. When there is no stored hash (unknown account), a dummy
 * hash is verified instead so that response timing does not reveal whether
 * the account exists.
 */
export async function verifyPassword(
  storedHash: string | null,
  password: string,
): Promise<boolean> {
  if (!storedHash) {
    dummyHash ??= hashPassword('aegis-dummy-password-for-timing-equalization');
    await verify(await dummyHash, password).catch(() => false);
    return false;
  }
  try {
    return await verify(storedHash, password);
  } catch {
    return false;
  }
}
