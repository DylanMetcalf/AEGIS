import { z } from 'zod';
import {
  ASSET_STATUSES,
  ASSET_TYPES,
  AUDIT_OUTCOMES,
  CRITICALITIES,
  ENVIRONMENTS,
  MEMBERSHIP_STATUSES,
  TENANT_ROLES,
} from './enums.js';

/**
 * Request schemas shared by server (authoritative validation) and web
 * (early feedback only). All object schemas are strict: unknown keys are
 * rejected so that clients cannot smuggle fields such as tenantId.
 */

export const uuidSchema = z.string().uuid();

/** Printable text without control characters (except none), trimmed. */
export const safeText = (min: number, max: number) =>
  z
    .string()
    .trim()
    .min(min)
    .max(max)
    // eslint-disable-next-line no-control-regex
    .refine((v) => !/[\u0000-\u001f\u007f]/.test(v), 'Control characters are not allowed');

/** Multi-line text: allows newline and tab only. */
export const safeMultilineText = (max: number) =>
  z
    .string()
    .max(max)
    // eslint-disable-next-line no-control-regex
    .refine((v) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(v), 'Invalid characters');

export const emailSchema = z.string().trim().toLowerCase().email().max(254);

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 256;

/** Login accepts any length up to the maximum so policy changes never lock users out. */
export const loginRequestSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1).max(PASSWORD_MAX_LENGTH),
  })
  .strict();

export const newPasswordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Password must be at least ${PASSWORD_MIN_LENGTH} characters`)
  .max(PASSWORD_MAX_LENGTH);

export const changePasswordRequestSchema = z
  .object({
    currentPassword: z.string().min(1).max(PASSWORD_MAX_LENGTH),
    newPassword: newPasswordSchema,
  })
  .strict()
  .refine((v) => v.currentPassword !== v.newPassword, {
    message: 'New password must differ from the current password',
    path: ['newPassword'],
  });

export const reauthenticateRequestSchema = z
  .object({ password: z.string().min(1).max(PASSWORD_MAX_LENGTH) })
  .strict();

export const selectTenantRequestSchema = z.object({ tenantId: uuidSchema }).strict();

/** Identifier for something the asset owner is authorized to defend. */
const scopeIdentifier = safeText(1, 253).refine(
  (v) => /^[A-Za-z0-9._:/@*\-[\]]+$/.test(v),
  'Identifier may contain letters, digits and . _ : / @ * - [ ] only',
);

/**
 * Authorization scope: an explicit statement of what AEGIS is permitted to
 * observe and defend for this asset, and who authorized it.
 */
export const authorizationScopeSchema = z
  .object({
    statement: safeText(10, 1000),
    identifiers: z.array(scopeIdentifier).min(1).max(50),
    authorizedBy: safeText(1, 200),
    authorizedAt: z.string().datetime({ offset: true }),
    expiresAt: z.string().datetime({ offset: true }).nullable().optional(),
  })
  .strict()
  .refine((v) => !v.expiresAt || Date.parse(v.expiresAt) > Date.parse(v.authorizedAt), {
    message: 'expiresAt must be after authorizedAt',
    path: ['expiresAt'],
  });

export const createAssetRequestSchema = z
  .object({
    name: safeText(1, 200),
    assetType: z.enum(ASSET_TYPES),
    environment: z.enum(ENVIRONMENTS),
    criticality: z.enum(CRITICALITIES),
    description: safeMultilineText(2000).optional(),
    authorizationScope: authorizationScopeSchema,
  })
  .strict();

export const updateAssetRequestSchema = z
  .object({
    version: z.number().int().positive(),
    name: safeText(1, 200).optional(),
    assetType: z.enum(ASSET_TYPES).optional(),
    environment: z.enum(ENVIRONMENTS).optional(),
    criticality: z.enum(CRITICALITIES).optional(),
    status: z.enum(ASSET_STATUSES).optional(),
    description: safeMultilineText(2000).nullable().optional(),
    authorizationScope: authorizationScopeSchema.optional(),
  })
  .strict();

export const listQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(100).default(25),
    cursor: z.string().max(512).optional(),
  })
  .strict();

export const assetListQuerySchema = listQuerySchema
  .extend({
    assetType: z.enum(ASSET_TYPES).optional(),
    environment: z.enum(ENVIRONMENTS).optional(),
    status: z.enum(ASSET_STATUSES).optional(),
    sort: z.enum(['createdAt', 'name']).default('createdAt'),
    order: z.enum(['asc', 'desc']).default('desc'),
  })
  .strict();

export const credentialRefSchema = z
  .string()
  .regex(
    /^env:AEGIS_SECRET_[A-Z0-9_]{1,64}$/,
    'Credential references must look like env:AEGIS_SECRET_NAME',
  );

export const createIntegrationRequestSchema = z
  .object({
    provider: z.string().regex(/^[a-z0-9_.-]{1,64}$/),
    name: safeText(1, 200),
    config: z.record(z.string(), z.unknown()),
    credentialRef: credentialRefSchema.nullable().optional(),
    grantedPermissions: z
      .array(z.string().regex(/^[a-z0-9_.:-]{1,64}$/))
      .max(50)
      .default([]),
    assetId: uuidSchema.nullable().optional(),
  })
  .strict();

export const updateIntegrationRequestSchema = z
  .object({
    version: z.number().int().positive(),
    name: safeText(1, 200).optional(),
    config: z.record(z.string(), z.unknown()).optional(),
    credentialRef: credentialRefSchema.nullable().optional(),
    grantedPermissions: z
      .array(z.string().regex(/^[a-z0-9_.:-]{1,64}$/))
      .max(50)
      .optional(),
    assetId: uuidSchema.nullable().optional(),
  })
  .strict();

export const integrationTransitionRequestSchema = z
  .object({ version: z.number().int().positive() })
  .strict();

export const addMemberRequestSchema = z
  .object({
    email: emailSchema,
    role: z.enum(TENANT_ROLES),
  })
  .strict();

export const updateMemberRequestSchema = z
  .object({
    role: z.enum(TENANT_ROLES).optional(),
    status: z.enum(MEMBERSHIP_STATUSES).optional(),
  })
  .strict()
  .refine((v) => v.role !== undefined || v.status !== undefined, 'Nothing to update');

export const createTenantRequestSchema = z
  .object({
    slug: z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9][a-z0-9-]{1,62}$/, 'Lowercase letters, digits and hyphens; 2-63 chars'),
    displayName: safeText(1, 200),
    addCreatorAsAdmin: z.boolean().default(true),
  })
  .strict();

export const auditListQuerySchema = listQuerySchema
  .extend({
    action: z
      .string()
      .regex(/^[a-z][a-z0-9_.]{0,99}$/)
      .optional(),
    outcome: z.enum(AUDIT_OUTCOMES).optional(),
  })
  .strict();

export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type CreateAssetRequest = z.infer<typeof createAssetRequestSchema>;
export type UpdateAssetRequest = z.infer<typeof updateAssetRequestSchema>;
export type AuthorizationScope = z.infer<typeof authorizationScopeSchema>;
export type CreateIntegrationRequest = z.infer<typeof createIntegrationRequestSchema>;
export type UpdateIntegrationRequest = z.infer<typeof updateIntegrationRequestSchema>;
export type AddMemberRequest = z.infer<typeof addMemberRequestSchema>;
export type CreateTenantRequest = z.infer<typeof createTenantRequestSchema>;
