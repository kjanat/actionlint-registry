import { expect, spyOn, test } from 'bun:test';
import { join } from 'node:path';
import { buildSite } from '#build.tsx';
import { createExport } from '#test/fixtures.ts';

test('publishes the declared configuration schema for each release tag', async () => {
	const directory = await createExport([{
		name: 'Example',
		repository: 'publisher/example',
		versions: [1, 2].map(version => ({
			version: `v${version}`,
			publishedAt: `2026-01-0${version}T00:00:00Z`,
			count: null,
			metadata: {
				description: 'Example options',
				engine: { name: 'example' },
				config_schema: {
					type: 'object',
					properties: { level: { $ref: '#/$defs/level' } },
					$defs: { level: { const: version } },
				},
			},
		})),
	}]);
	const output = join(directory, 'site');
	await buildSite(directory, output);
	const catalog = await Bun.file(join(output, 'schemas/plugin-config.catalog.json')).json();
	const origin = 'https://plugins.actionlint.kjanat.dev';
	const records = `/plugins/${'1'.padStart(64, '0')}/versions/`;
	const v1 = origin + records + '1'.padStart(64, '0') + '.config.schema.json';
	const v2 = origin + records + '2'.padStart(64, '0') + '.config.schema.json';
	expect(catalog.schemas).toEqual([{
		name: 'github.com/publisher/example',
		description: 'Example options',
		url: v2,
		versions: { v1, v2 },
	}]);
	for (const [url, version] of [[v1, 1], [v2, 2]] as const) {
		const schema = await Bun.file(join(output, new URL(url).pathname)).json();
		const resource = schema.$defs['settings-1'];
		expect(schema.$id).toBe(url);
		expect(schema.properties.tools.properties.example.properties.config.anyOf[0]).toEqual({ $ref: resource.$id });
		expect(resource.properties.level.$ref).toBe('#/$defs/level');
		expect(resource.$defs.level.const).toBe(version);
	}
});

test('reports releases with invalid or conflicting schema IDs and publishes the remaining releases', async () => {
	const id = 'https://example.com/options.schema.json';
	const config = { $id: id, type: 'object' };
	const declarations = [
		{ ...config, $id: 'https://[' },
		{ ...config, $id: '' },
		config,
		config,
	];
	const directory = await createExport([{
		name: 'Example',
		repository: 'publisher/example',
		versions: declarations.map((config_schema, index) => ({
			version: `v${index + 1}`,
			publishedAt: `2026-01-0${index + 1}T00:00:00Z`,
			count: null,
			metadata: {
				engine: { name: 'example' },
				config_schema,
				descriptor: {
					category: 'correctness',
					name: 'example',
					options_schema: { type: index === 2 ? 'string' : 'object', $id: id },
				},
			},
		})),
	}]);
	const output = join(directory, 'site');
	const warnings = spyOn(console, 'warn').mockImplementation(() => {});
	try {
		await buildSite(directory, output);
		expect(warnings.mock.calls).toEqual([
			['Skipping configuration schema for github.com/publisher/example@v3: conflicting schema $id'],
			['Skipping configuration schema for github.com/publisher/example@v2: invalid schema $id'],
			['Skipping configuration schema for github.com/publisher/example@v1: invalid schema $id'],
		]);
	} finally {
		warnings.mockRestore();
	}
	const catalog = await Bun.file(join(output, 'schemas/plugin-config.catalog.json')).json();
	const versions = catalog.schemas[0].versions;
	expect(Object.keys(versions)).toEqual(['v4']);
	const schema = await Bun.file(join(output, new URL(versions.v4).pathname)).json();
	expect(Object.values(schema.$defs)).toEqual([config]);
	expect(schema.properties.lint.properties.rules.properties.correctness.properties.example.properties.options.anyOf[0])
		.toEqual({ $ref: id });
});
