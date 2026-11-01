import { z } from 'zod';

const digest = z.string().regex(/^[a-f0-9]{64}$/);
const integer = z.number().int().nonnegative().safe();
const timestamp = z.string().datetime({ offset: true });
const ociReferencePattern =
	/^oci:\/\/[a-z0-9]+(?:[.-][a-z0-9]+)*(?::([0-9]{1,5}))?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[a-f0-9]{64}$/u;
const provider = z.enum(['github', 'gitlab']);
const metadata = z.object({
	name: z.string().optional(),
	description: z.string().optional(),
	license: z.string().optional(),
});

function validOCIReference(value: string): boolean {
	if (value.length > 2048) return false;
	const match = ociReferencePattern.exec(value);
	const port = match?.[1];
	return match !== null && (port === undefined || (Number(port) >= 1 && Number(port) <= 65535));
}

export const catalogueSchema = z.object({
	schema_version: z.literal(1),
	statuses: z.literal('statuses.json').optional(),
	plugins: z.array(z.object({
		name: z.string().regex(/^(github|gitlab)\.com\/[A-Za-z0-9_./-]+$/),
		plugin_id: z.string(),
		manifest: z.string().regex(/^plugins\/[a-f0-9]{64}\/index\.json$/),
		aliases: z.array(z.string().regex(/^[a-z][a-z0-9-]{0,63}$/)).default([]),
	})),
});

export const manifestSchema = z.object({
	plugin: z.object({
		schema_version: z.union([z.literal(1), z.literal(2)]).default(1),
		provider,
		repository: z.string(),
		plugin_id: z.string(),
		repository_id: z.string(),
	}),
	versions: z.array(z.object({
		version: z.string(),
		record: z.string().regex(/^versions\/[a-f0-9]{64}\.json$/),
	})).min(1),
});

export const entrySchema = z.object({
	identity_version: z.literal(2).optional(),
	submission: z.union([
		z.object({
			provider,
			repository: z.string(),
			tag: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/),
			asset: z.string(),
			sha256: digest,
			kind: z.enum(['core', 'component']),
			schema_version: z.literal(1),
		}),
		z.object({
			schema_version: z.literal(2),
			provider,
			repository: z.string(),
			tag: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/),
			kind: z.enum(['core', 'component', 'manifest']),
			artifact: z.discriminatedUnion('type', [
				z.object({ type: z.literal('release-asset'), name: z.string(), sha256: digest }),
				z.object({
					type: z.literal('oci'),
					reference: z.string().refine(validOCIReference),
				}),
			]),
		}),
	]),
	repository_id: integer,
	asset_id: integer,
	url: z.string().refine(value =>
		validOCIReference(value) || (URL.canParse(value) && new URL(value).protocol === 'https:')
	),
	published_at: timestamp,
	artifact: z.object({ metadata, plugin_id: z.string().optional() }).optional(),
	validation: z.object({ metadata, plugin_id: z.string().optional() }).optional(),
}).superRefine((entry, context) => {
	if (
		entry.submission.schema_version === 2 && entry.submission.artifact.type === 'oci'
		&& entry.url !== entry.submission.artifact.reference
	) {
		context.addIssue({ code: 'custom', message: 'OCI entry URL must equal its pinned source reference' });
	}
}).refine(entry => entry.artifact !== undefined || entry.validation !== undefined, 'Missing declaration metadata');

export const stateSchema = z.enum(['active', 'deprecated', 'withdrawn', 'revoked']);
export const statusSchema = z.object({
	schema_version: z.literal(1),
	releases: z.array(z.object({
		name: z.string(),
		version: z.string(),
		sha256: digest,
		status: stateSchema,
		reason: z.string(),
		replacement: z.string().optional(),
	})),
});

export const downloadsSchema = z.object({
	schema_version: z.literal(1),
	observed_at: timestamp,
	releases: z.array(z.object({
		provider,
		repository_id: integer,
		version: z.string(),
		asset_id: integer,
		sha256: digest,
		status: z.enum(['available', 'unavailable', 'unsupported']),
		count: integer.optional(),
	})),
});

export const metricSchema = z.discriminatedUnion('state', [
	z.object({ state: z.literal('available'), count: integer }),
	z.object({ state: z.enum(['not collected', 'unavailable', 'unsupported']) }),
]);

export const summarySchema = z.object({
	name: z.string(),
	description: z.string(),
	repository: z.string(),
	path: z.string().regex(/^plugins\/[a-f0-9]{64}\/index\.html$/),
	version: z.string(),
	updatedAt: timestamp,
	downloads: metricSchema,
});

// Build output for this site's browser client, separate from registry protocol files.
export const searchIndexSchema = z.array(summarySchema);
export type PluginSummary = z.infer<typeof summarySchema>;
export type Metric = z.infer<typeof metricSchema>;
export type Entry = z.infer<typeof entrySchema>;
export type ReleaseStatus = z.infer<typeof statusSchema>['releases'][number];
export type DownloadSnapshot = z.infer<typeof downloadsSchema>;
export type ReleaseState = z.infer<typeof stateSchema>;

export interface Release {
	version: string;
	kind: 'core' | 'component' | 'manifest';
	source: { type: 'release-asset'; name: string; reference: string } | { type: 'oci'; reference: string };
	sha256: string;
	pinnedURL: string;
	record: string;
	publishedAt: string;
	reference: string;
	state: ReleaseState;
	reason: string;
	replacement: string;
	downloads: Metric;
}

export interface Plugin extends PluginSummary {
	id: string;
	license: string;
	repositoryURL: string;
	releases: Release[];
}

export interface SiteData {
	plugins: Plugin[];
	observedAt: string | null;
}
