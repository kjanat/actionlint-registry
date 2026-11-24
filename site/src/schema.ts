import { Effect, Schema } from 'effect';

const digest = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/));
const integer = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }));
const timestamp = Schema.String.check(
	Schema.isPattern(
		/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/u,
	),
	Schema.makeFilter(value => {
		const date = value.slice(0, 10);
		const parsed = new Date(date + 'T00:00:00Z');
		return Number.isFinite(parsed.getTime()) && parsed.toISOString().startsWith(date);
	}, { message: 'Expected a valid calendar date' }),
);
const ociReferencePattern =
	/^oci:\/\/[a-z0-9]+(?:[.-][a-z0-9]+)*(?::([0-9]{1,5}))?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[a-f0-9]{64}$/u;
const provider = Schema.Literals(['github', 'gitlab']);
const interfaceNames = Schema.Array(Schema.String.check(Schema.isBetweenLength(1, 512)))
	.check(Schema.isMaxLength(4096)).pipe(Schema.mutable);
const metadata = Schema.Struct({
	name: Schema.String.pipe(Schema.optionalKey),
	description: Schema.String.pipe(Schema.optionalKey),
	license: Schema.String.pipe(Schema.optionalKey),
	engine: Schema.optionalKey(Schema.Unknown),
	config_schema: Schema.optionalKey(Schema.Unknown),
	rules: Schema.optionalKey(Schema.Unknown),
	descriptor: Schema.optionalKey(Schema.Unknown),
});

function validOCIReference(value: string): boolean {
	if (value.length > 2048) return false;
	const match = ociReferencePattern.exec(value);
	const port = match?.[1];
	return match !== null && (port === undefined || (Number(port) >= 1 && Number(port) <= 65535));
}

export const catalogueSchema = Schema.Struct({
	schema_version: Schema.Literal(1),
	statuses: Schema.Literal('statuses.json').pipe(Schema.optionalKey),
	plugins: Schema.Array(Schema.Struct({
		name: Schema.String.check(Schema.isPattern(/^(github|gitlab)\.com\/[A-Za-z0-9_./-]+$/)),
		plugin_id: Schema.String,
		manifest: Schema.String.check(Schema.isPattern(/^plugins\/[a-f0-9]{64}\/index\.json$/)),
		aliases: Schema.Array(Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,63}$/))).pipe(
			Schema.withDecodingDefault(Effect.succeed([])),
		),
	})),
});

export const manifestSchema = Schema.Struct({
	plugin: Schema.Struct({
		schema_version: Schema.Literals([1, 2]).pipe(Schema.withDecodingDefault(Effect.succeed(1))),
		provider,
		repository: Schema.String,
		plugin_id: Schema.String,
		repository_id: Schema.String,
	}),
	versions: Schema.Array(
		Schema.Struct({
			version: Schema.String,
			record: Schema.String.check(Schema.isPattern(/^versions\/[a-f0-9]{64}\.json$/)),
			imports: interfaceNames.pipe(Schema.optionalKey),
			exports: interfaceNames.pipe(Schema.optionalKey),
		}).check(Schema.makeFilter(version => (version.imports === undefined) === (version.exports === undefined), {
			message: 'A version lists both imports and exports or neither',
		})),
	).check(Schema.isMinLength(1)),
});

export const entrySchema = Schema.Struct({
	identity_version: Schema.Literal(2).pipe(Schema.optionalKey),
	submission: Schema.Union([
		Schema.Struct({
			provider,
			repository: Schema.String,
			tag: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/)),
			asset: Schema.String,
			sha256: digest,
			kind: Schema.Literals(['core', 'component']),
			schema_version: Schema.Literal(1),
		}),
		Schema.Struct({
			schema_version: Schema.Literal(2),
			provider,
			repository: Schema.String,
			tag: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/)),
			kind: Schema.Literals(['core', 'component', 'manifest']),
			artifact: Schema.Union([
				Schema.Struct({ type: Schema.Literal('release-asset'), name: Schema.String, sha256: digest }),
				Schema.Struct({
					type: Schema.Literal('oci'),
					reference: Schema.String.check(
						Schema.makeFilter(validOCIReference, { message: 'Expected a pinned OCI reference' }),
					),
				}),
			]),
		}),
	]),
	repository_id: integer,
	asset_id: integer,
	url: Schema.String.check(
		Schema.makeFilter(
			value => validOCIReference(value) || (URL.canParse(value) && new URL(value).protocol === 'https:'),
			{ message: 'Expected HTTPS or a pinned OCI reference' },
		),
	),
	published_at: timestamp,
	artifact: Schema.Struct({ metadata, plugin_id: Schema.String.pipe(Schema.optionalKey) }).pipe(Schema.optionalKey),
	validation: Schema.Struct({ metadata, plugin_id: Schema.String.pipe(Schema.optionalKey) }).pipe(Schema.optionalKey),
}).check(
	Schema.makeFilter(entry => {
		const { submission } = entry;
		return submission.schema_version !== 2 || submission.artifact.type !== 'oci'
			|| entry.url === submission.artifact.reference;
	}, { message: 'OCI entry URL must equal its pinned source reference' }),
	Schema.makeFilter(entry => entry.artifact !== undefined || entry.validation !== undefined, {
		message: 'Missing declaration metadata',
	}),
);

export const stateSchema = Schema.Literals(['active', 'deprecated', 'withdrawn', 'revoked']);
export const statusSchema = Schema.Struct({
	schema_version: Schema.Literal(1),
	releases: Schema.Array(Schema.Struct({
		name: Schema.String,
		version: Schema.String,
		sha256: digest,
		status: stateSchema,
		reason: Schema.String,
		replacement: Schema.String.pipe(Schema.optionalKey),
	})),
});

export const downloadsSchema = Schema.Struct({
	schema_version: Schema.Literal(1),
	observed_at: timestamp,
	releases: Schema.Array(Schema.Struct({
		provider,
		repository_id: integer,
		version: Schema.String,
		asset_id: integer,
		sha256: digest,
		status: Schema.Literals(['available', 'unavailable', 'unsupported']),
		count: integer.pipe(Schema.optionalKey),
	})),
});

export const metricSchema = Schema.Union([
	Schema.Struct({ state: Schema.Literal('available'), count: integer }),
	Schema.Struct({ state: Schema.Literals(['not collected', 'unavailable', 'unsupported']) }),
]);

export const summarySchema = Schema.Struct({
	name: Schema.String,
	description: Schema.String,
	repository: Schema.String,
	path: Schema.String.check(Schema.isPattern(/^plugins\/[a-f0-9]{64}\/index\.html$/)),
	version: Schema.String,
	updatedAt: timestamp,
	downloads: metricSchema,
});

// Build output for this site's browser client, separate from registry protocol files.
export const searchIndexSchema = Schema.Array(summarySchema).pipe(Schema.mutable);
export type PluginSummary = typeof summarySchema.Type;
export type Metric = typeof metricSchema.Type;
export type Entry = typeof entrySchema.Type;
export type PluginMetadata = typeof metadata.Type;
export type ReleaseStatus = typeof statusSchema['Type']['releases'][number];
export type DownloadSnapshot = typeof downloadsSchema.Type;
export type ReleaseState = typeof stateSchema.Type;

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
	interfaces: { imports: string[]; exports: string[] } | null;
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
