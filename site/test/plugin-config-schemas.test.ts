import { expect, test } from 'bun:test';
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
