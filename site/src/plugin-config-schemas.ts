import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Schema } from 'effect';
import type { Entry, PluginMetadata, Release } from '#schema.ts';

const registry = 'https://plugins.actionlint.kjanat.dev/';
const draft = 'https://json-schema.org/draft/2020-12/schema';
const catalogPath = 'schemas/plugin-config.catalog.json';

const schemaObject = Schema.Record(Schema.String, Schema.Unknown);
const engine = Schema.Struct({ name: Schema.NonEmptyString });
const rule = Schema.Struct({
	category: Schema.NonEmptyString,
	name: Schema.NonEmptyString,
	options_schema: schemaObject,
});

export interface PluginSchemaSource {
	name: string;
	description: string;
	versions: readonly { entry: Entry; release: Release }[];
}

function settings(metadata: PluginMetadata) {
	const result = new Map<string, { path: string[]; schema: Record<string, unknown>; file: boolean }>();
	const parsedEngine = Schema.decodeUnknownOption(engine)(metadata.engine);
	const config = Schema.decodeUnknownOption(schemaObject)(metadata.config_schema);
	if (parsedEngine._tag === 'Some' && config._tag === 'Some') {
		const path = ['tools', parsedEngine.value.name, 'config'];
		result.set(JSON.stringify(path), { path, schema: config.value, file: true });
	}
	const rules = Array.isArray(metadata.rules) ? metadata.rules : [];
	for (const candidate of [...rules, metadata.descriptor]) {
		const parsed = Schema.decodeUnknownOption(rule)(candidate);
		if (parsed._tag === 'None') continue;
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
	const resources = new Map<string, { id: string; schema: Record<string, unknown> }>();
	const resourceIds = new Set<string>();
	const root: Record<string, ConfigProperty> = Object.create(null);
	for (const setting of settings(metadata)) {
		const key = JSON.stringify(setting.schema);
		let resource = resources.get(key);
		if (!resource) {
			const declaredId = setting.schema.$id;
			// A distinct resource base keeps local references relative to the plugin's schema.
			const id = typeof declaredId === 'string'
				? new URL(declaredId, url).href
				: new URL(`?settings=${resources.size + 1}`, url).href;
			if (id === url.href || resourceIds.has(id)) throw new Error(`Duplicate schema resource ${id} in ${url}`);
			resource = { id, schema: { ...setting.schema, $id: id } };
			resources.set(key, resource);
			resourceIds.add(id);
		}

		let properties = root;
		for (const segment of setting.path.slice(0, -1)) {
			const node = properties[segment] ??= {};
			properties = node.properties ??= Object.create(null);
		}
		const leaf = setting.file ? 'config' : 'options';
		properties[leaf] = {
			anyOf: [
				{ $ref: resource.id },
				{ type: 'null' },
				...(setting.file ? [{ type: 'string' } as const] : []),
			],
		};
	}
	if (resources.size === 0) return;
	return {
		$schema: draft,
		$id: url.href,
		type: 'object',
		properties: { ...root, overrides: { items: { properties: root } } },
		$defs: Object.fromEntries(Array.from(resources.values(), ({ schema }, index) => [`settings-${index + 1}`, schema])),
	};
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
			const schema = versionSchema(url, metadata);
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
