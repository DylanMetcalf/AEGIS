import { z } from 'zod';
import {
  FINDING_STATUSES,
  RELATIONSHIP_KINDS,
  SEVERITIES,
  TELEMETRY_EVENT_TYPES,
} from './enums.js';
import { listQuerySchema, safeMultilineText, safeText, uuidSchema } from './schemas.js';

/** Phase 2 request schemas. Strict objects throughout. */

const attributeKey = z.string().regex(/^[a-z][a-z0-9_]{0,63}$/);
const attributeValue = z.union([
  z.string().max(512),
  z
    .number()
    .refine(
      (n) => Number.isFinite(n) && Math.abs(n) <= Number.MAX_SAFE_INTEGER,
      'Number out of range',
    ),
  z.boolean(),
]);

export const telemetryEventSchema = z
  .object({
    eventType: z.enum(TELEMETRY_EVENT_TYPES),
    observedAt: z.string().datetime({ offset: true }),
    severity: z.enum(SEVERITIES).default('INFO'),
    sourceEventId: z
      .string()
      .regex(/^[A-Za-z0-9_.:-]{1,128}$/)
      .optional(),
    actor: z
      .object({
        userId: z
          .string()
          .regex(/^[A-Za-z0-9_.:@-]{1,128}$/)
          .optional(),
        ip: z.union([z.ipv4(), z.ipv6()]).optional(),
      })
      .strict()
      .optional(),
    attributes: z
      .record(attributeKey, attributeValue)
      .refine((a) => Object.keys(a).length <= 30, 'At most 30 attributes')
      .default({}),
  })
  .strict();

export const INGEST_MAX_BATCH = 500;
export const ingestBatchSchema = z
  .object({ events: z.array(telemetryEventSchema).min(1).max(INGEST_MAX_BATCH) })
  .strict();

export const findingListQuerySchema = listQuerySchema
  .extend({
    status: z.enum(FINDING_STATUSES).optional(),
    severity: z.enum(SEVERITIES).optional(),
    assetId: uuidSchema.optional(),
    active: z.enum(['true', 'false']).optional(),
  })
  .strict();

export const updateFindingRequestSchema = z
  .object({
    version: z.number().int().positive(),
    status: z.enum(FINDING_STATUSES).optional(),
    resolutionNote: safeMultilineText(2000).optional(),
    assigneePrincipalId: uuidSchema.nullable().optional(),
  })
  .strict()
  .refine(
    (v) => v.status !== undefined || v.assigneePrincipalId !== undefined,
    'Nothing to update',
  );

export const createInvestigationRequestSchema = z
  .object({
    title: safeText(1, 200),
    summary: safeMultilineText(4000).optional(),
    findingIds: z.array(uuidSchema).max(100).default([]),
  })
  .strict();

export const updateInvestigationRequestSchema = z
  .object({
    version: z.number().int().positive(),
    title: safeText(1, 200).optional(),
    summary: safeMultilineText(4000).nullable().optional(),
    status: z.enum(['OPEN', 'CLOSED']).optional(),
    addFindingIds: z.array(uuidSchema).max(100).optional(),
    removeFindingIds: z.array(uuidSchema).max(100).optional(),
  })
  .strict();

export const noteRequestSchema = z
  .object({ text: safeMultilineText(4000).refine((t) => t.trim().length > 0, 'Note is empty') })
  .strict();

export const createRelationshipRequestSchema = z
  .object({ fromAssetId: uuidSchema, toAssetId: uuidSchema, kind: z.enum(RELATIONSHIP_KINDS) })
  .strict()
  .refine((v) => v.fromAssetId !== v.toAssetId, {
    message: 'An asset cannot relate to itself',
    path: ['toAssetId'],
  });

export const graphQuerySchema = z
  .object({ assetId: uuidSchema, depth: z.coerce.number().int().min(1).max(2).default(1) })
  .strict();

export type TelemetryEventInput = z.infer<typeof telemetryEventSchema>;
export type UpdateFindingRequest = z.infer<typeof updateFindingRequestSchema>;
