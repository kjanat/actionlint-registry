import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Option, Result, Schema } from 'effect';
import type { Entry, PluginMetadata, Release } from '#schema.ts';

const registry = 'https://plugins.actionlint.kjanat.dev/';
const draft = 'https://json-schema.org/draft/2020-12/schema';
const catalogPath = 'schemas/plugin-config.catalog.json';

const sameSchema = Schema.toEquivalence(Schema.JsonObject);
const decodeSchema = Schema.decodeUnknownOption(Schema.JsonObject);
const decodeSchemaId = Schema.decodeUnknownOption(Schema.String.check(Schema.isPattern(/^\S+$/u)));
const engine = Schema.Struct({ name: Schema.NonEmptyString });
const rule = Schema.Struct({
	category: Schema.NonEmptyString,
	name: Schema.NonEmptyString,
	options_schema: Schema.JsonObject,
});
const decodeEngine = Schema.decodeUnknownOption(engine);
const decodeRule = Schema.decodeUnknownOption(rule);

export interface PluginSchemaSource {
	name: string;
	description: string;
	versions: readonly { entry: Entry; release: Release }[];
}

function settings(metadata: PluginMetadata) {
	const result = new Map<string, { path: string[]; schema: Schema.JsonObject; file: boolean }>();
	const parsedEngine = decodeEngine(metadata.engine);
	const config = decodeSchema(metadata.config_schema);
	if (Option.isSome(parsedEngine) && Option.isSome(config)) {
		const path = ['tools', parsedEngine.value.name, 'config'];
		result.set(JSON.stringify(path), { path, schema: config.value, file: true });
	}
	const rules = Array.isArray(metadata.rules) ? metadata.rules : [];
	for (const candidate of [...rules, metadata.descriptor]) {
		const parsed = decodeRule(candidate);
		if (Option.isNone(parsed)) continue;
		const { category, name, options_schema } = parsed.value;
		const path = ['lint', 'rules', category, name, 'options'];
		result.set(JSON.stringify(path), { path, schema: options_schema, file: false });
	}
	return result.values();
}

interface ConfigProperty {
	properties?: Record<string, ConfigProperty>;
	items?: ConfigProperty;
	anyOf?: ({ $ref: string } | { type: 'null' | 'string' })[];
}

function versionSchema(url: URL, metadata: PluginMetadata) {
	const resources = new Map<string, string>();
	const resourceIds = new Map<string, Schema.JsonObject>();
	const root: Record<string, ConfigProperty> = Object.create(null);
	for (const setting of settings(metadata)) {
		const key = JSON.stringify(setting.schema);
		let resourceId = resources.get(key);
		if (!resourceId) {
			const declaredId = setting.schema.$id;
			const parsedId = decodeSchemaId(declaredId);
			// A distinct resource base keeps local references relative to the plugin's schema.
			const resolved = declaredId === undefined
				? new URL(`?settings=${resources.size + 1}`, url)
				: Option.isSome(parsedId)
				? URL.parse(parsedId.value, url)
				: null;
			if (!resolved || resolved.hash) return Result.fail('invalid schema $id');
			resolved.hash = '';
			const id = resolved.href;
			const schema = { ...setting.schema, $id: id };
			const previous = resourceIds.get(id);
			if (id === url.href || (previous && !sameSchema(previous, schema))) {
				return Result.fail('conflicting schema $id');
			}
			resourceId = id;
			resources.set(key, id);
			resourceIds.set(id, schema);
		}

		let properties = root;
		for (const segment of setting.path.slice(0, -1)) {
			const node = properties[segment] ??= {};
			properties = node.properties ??= Object.create(null);
		}
		const leaf = setting.file ? 'config' : 'options';
		properties[leaf] = {
			anyOf: [
				{ $ref: resourceId },
				{ type: 'null' },
				...(setting.file ? [{ type: 'string' } as const] : []),
			],
		};
	}
	if (resources.size === 0) return Result.succeed(undefined);
	return Result.succeed({
		$schema: draft,
		$id: url.href,
		type: 'object',
		properties: { ...root, overrides: { items: { properties: root } } },
		$defs: Object.fromEntries(Array.from(resourceIds.values(), (schema, index) => [`settings-${index + 1}`, schema])),
	});
}

export async function writePluginConfigSchemas(output: string, plugins: readonly PluginSchemaSource[]): Promise<void> {
	async function write(path: string, value: unknown) {
		const target = join(output, path);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, `${JSON.stringify(value, null, 2)}\n`);
	}
	const schemas = [];
	for (const plugin of plugins) {
		const versions = new Map<string, string>();
		let preferred: string | undefined;
		for (const { entry, release } of plugin.versions) {
			const metadata = entry.artifact?.metadata ?? entry.validation?.metadata;
			if (!metadata) continue;
			const path = release.record.replace(/\.json$/u, '.config.schema.json');
			const url = new URL(path, registry);
			const result = versionSchema(url, metadata);
			if (Result.isFailure(result)) {
				console.warn(`Skipping configuration schema for ${plugin.name}@${release.version}: ${result.failure}`);
				continue;
			}
			const schema = result.success;
			if (!schema) continue;
			await write(path, schema);
			versions.set(release.version, url.href);
			if (release.state === 'active') preferred ??= url.href;
		}
		const url = preferred ?? versions.values().next().value;
		if (url) {
			schemas.push({ name: plugin.name, description: plugin.description, url, versions: Object.fromEntries(versions) });
		}
	}
	await write(catalogPath, {
		$schema: 'https://www.schemastore.org/schema-catalog.json',
		version: 1,
		schemas,
	});
}
