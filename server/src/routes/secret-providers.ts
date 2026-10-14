import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import {
  EXTERNAL_SECRET_LOCATOR_MAX_LENGTH,
  EXTERNAL_SECRET_OPTION_MAX_LENGTH,
  SECRET_PROVIDER_SETTING_MAX_LENGTH,
  type SecretProviderInfo,
  type SecretProvidersResponse,
} from '@muxus/shared';
import type { AppContext } from '../app.js';
import { SecretProviderError } from '../secret-providers/provider.js';
import { SecretProviderInputError } from '../secret-providers/registry.js';
import { HttpProblem, sendError } from '../util/errors.js';

const FIELD_KEY = z.string().min(1).max(64);
const MAX_FIELDS = 32;

// Values are checked again, in characters, by the registry and the provider.
const settingsSchema = z.object({
  settings: z
    .record(FIELD_KEY, z.string().max(SECRET_PROVIDER_SETTING_MAX_LENGTH * 4).nullable())
    .refine((settings) => Object.keys(settings).length <= MAX_FIELDS),
});

export const externalSecretOptionsSchema = z
  .record(FIELD_KEY, z.string().max(EXTERNAL_SECRET_OPTION_MAX_LENGTH * 4))
  .refine((options) => Object.keys(options).length <= MAX_FIELDS);

const testSchema = z.object({
  locator: z.string().min(1).max(EXTERNAL_SECRET_LOCATOR_MAX_LENGTH * 4),
  options: externalSecretOptionsSchema.optional(),
});

/** Which password managers Muxus can ask, their settings, and a check that a locator resolves. */
export function registerSecretProviderRoutes(app: FastifyInstance, ctx: AppContext): void {
  app.get('/api/secret-providers', async (req): Promise<SecretProvidersResponse> => {
    const { refresh } = req.query as { refresh?: string };
    return { providers: await ctx.secretProviders.list(refresh === '1' || refresh === 'true') };
  });

  app.put('/api/secret-providers/:id/settings', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!ctx.secretProviders.get(id)) return sendProviderMissing(reply, id);
    const parsed = settingsSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ message: 'The settings could not be read.' });
    }
    try {
      const info: SecretProviderInfo = await ctx.secretProviders.saveSettings(id, parsed.data.settings);
      return info;
    } catch (err) {
      if (err instanceof SecretProviderInputError) {
        return sendError(reply, new HttpProblem(400, err.message, 'invalid-secret-provider-settings'));
      }
      return sendError(reply, err);
    }
  });

  // Reads the value and throws it away: the answer says only whether the
  // manager could provide it, and why not.
  app.post('/api/secret-providers/:id/test', async (req, reply) => {
    const { id } = req.params as { id: string };
    const provider = ctx.secretProviders.get(id);
    if (!provider) return sendProviderMissing(reply, id);
    const parsed = testSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply
        .code(400)
        .send({ message: `Enter the ${provider.descriptor.locator.label.toLocaleLowerCase()}.` });
    }
    let request: { locator: string; options: Record<string, string> };
    try {
      request = ctx.secretProviders.checkSecret(id, parsed.data.locator, parsed.data.options);
    } catch (err) {
      if (err instanceof SecretProviderInputError) {
        return sendError(reply, new HttpProblem(400, err.message, 'invalid-vault-secret'));
      }
      return sendError(reply, err);
    }
    // A client that gives up mid-read (the manager's approval prompt can
    // wait minutes) must not hold the provider's queue. The reply's close is
    // the signal: the request's own fires as soon as its body is read.
    const controller = new AbortController();
    reply.raw.once('close', () => {
      if (!reply.raw.writableFinished) controller.abort();
    });
    try {
      await ctx.secretProviders.read(id, request, { signal: controller.signal });
      return reply.header('cache-control', 'no-store').send({ ok: true });
    } catch (err) {
      if (err instanceof SecretProviderError) {
        return sendError(reply, new HttpProblem(502, err.message, 'secret-provider-unavailable'));
      }
      return sendError(reply, err);
    }
  });
}

function sendProviderMissing(reply: FastifyReply, id: string): Promise<void> {
  return sendError(
    reply,
    new HttpProblem(404, `This version of Muxus has no secret provider “${id}”.`, 'secret-provider-missing'),
  );
}
