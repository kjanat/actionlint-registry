import { Schema } from 'effect';
import { describe, expect, test } from 'bun:test';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { buildSite } from '#build.tsx';
import { loadCatalogue } from '#catalogue.ts';
import { downloadsSchema } from '#schema.ts';
import { createExport, fixture } from '#test/fixtures.ts';

describe('public registry JSON projection', () => {
	test('renders a historical record with a numeric description', async () => {
		const dir = await createExport([fixture('Historical plugin')]);
		const key = '1'.padStart(64, '0');
		const path = `plugins/${key}/versions/${key}.json`;
		const { artifact, record_version, ...record } = await Bun.file(join(dir, path)).json();
		const metadata = { name: 'Historical plugin', description: 7, config_schema: { type: 'boolean' } };
		await writeFile(join(dir, path), JSON.stringify({ ...record, validation: { ...artifact, metadata } }));

		const site = join(dir, 'website');
		expect(await buildSite(dir, site)).toBe(1);
		const [plugin] = await Bun.file(join(site, 'assets/search-index.json')).json();
		expect(plugin).toMatchObject({ name: 'Historical plugin', description: '' });
		expect(await Bun.file(join(site, plugin.path)).text()).toContain('Historical plugin');
		expect((await Bun.file(join(site, path)).json()).validation.metadata).toEqual(metadata);
	});

	test('monorepo packages keep their selectors and release statuses distinct', async () => {
		const version = { version: 'v1.0.0', publishedAt: '2026-01-01T00:00:00Z', count: 2 };
		const directory = await createExport([{
			name: 'Grant',
			repository: 'publisher/monorepo',
			repositoryID: 42,
			pluginID: 'github.com/publisher/monorepo/plugins/grant',
			identityVersion: 2,
			versions: [{ ...version, state: 'withdrawn', reason: 'Package-specific withdrawal' }],
		}, {
			name: 'Syft',
			repository: 'publisher/monorepo',
			repositoryID: 42,
			pluginID: 'github.com/publisher/monorepo/plugins/syft',
			identityVersion: 2,
			versions: [version],
		}]);
		const data = await loadCatalogue(directory);
		expect(data.plugins.map(plugin => plugin.repositoryURL)).toEqual([
			'https://github.com/publisher/monorepo',
			'https://github.com/publisher/monorepo',
		]);
		expect(data.plugins.map(plugin => plugin.releases[0]?.reference)).toEqual([
			'github.com/publisher/monorepo/plugins/grant@v1.0.0',
			'github.com/publisher/monorepo/plugins/syft@v1.0.0',
		]);
		expect(data.plugins.map(plugin => plugin.releases[0]?.state)).toEqual(['withdrawn', 'active']);
	});

	test('package selectors cannot claim a different publishing repository', async () => {
		const directory = await createExport([{
			...fixture('Forged package'),
			repository: 'publisher/monorepo',
			pluginID: 'github.com/other/repository/plugins/check',
			identityVersion: 2,
		}]);
		await expect(loadCatalogue(directory)).rejects.toThrow('outside its publishing repository');
	});

	test('groups versions and follows newest publication, even when its version sorts earlier', async () => {
		const directory = await createExport([{
			name: 'Plugin',
			versions: [
				{ version: 'v10.0.0', publishedAt: '2026-01-01T00:00:00Z', count: 4 },
				{
					version: 'v2.0.0',
					publishedAt: '2026-02-01T00:00:00Z',
					count: 7,
					metadata: { name: 'Updated', description: 'Current description', license: 'Apache-2.0' },
				},
			],
		}]);
		const data = await loadCatalogue(directory);
		expect(data.plugins).toHaveLength(1);
		expect(data.plugins[0]).toMatchObject({
			name: 'Updated',
			description: 'Current description',
			license: 'Apache-2.0',
			version: 'v2.0.0',
			downloads: { state: 'available', count: 11 },
		});
		expect(data.plugins[0]?.releases.map(release => release.version)).toEqual(['v2.0.0', 'v10.0.0']);
	});

	test('keeps zero, partial, absent and overflowing counts distinct', async () => {
		const directory = await createExport([
			fixture('Zero', 0),
			{
				name: 'Partial',
				versions: [
					{ version: 'v1', publishedAt: '2026-01-01T00:00:00Z', count: 30 },
					{ version: 'v2', publishedAt: '2026-01-02T00:00:00Z', count: null },
				],
			},
			{
				name: 'Overflow',
				versions: [
					{ version: 'v1', publishedAt: '2026-01-01T00:00:00Z', count: Number.MAX_SAFE_INTEGER },
					{ version: 'v2', publishedAt: '2026-01-02T00:00:00Z', count: 1 },
				],
			},
		]);
		expect((await loadCatalogue(directory)).plugins.map(plugin => plugin.downloads)).toEqual([
			{ state: 'available', count: 0 },
			{ state: 'unavailable' },
			{ state: 'unavailable' },
		]);
		await rm(join(directory, 'downloads.json'));
		expect((await loadCatalogue(directory)).plugins.every(plugin => plugin.downloads.state === 'not collected')).toBe(
			true,
		);
	});

	test.each(['provider', 'repository_id', 'version', 'asset_id', 'sha256'])(
		'rejects a count from a different %s',
		async field => {
			const directory = await createExport([fixture('Plugin')]);
			const snapshot = Schema.decodeUnknownSync(downloadsSchema)(
				JSON.parse(await readFile(join(directory, 'downloads.json'), 'utf8')),
			);
			const original = snapshot.releases[0];
			if (!original) throw new Error('Missing fixture observation');
			const observation = { ...original };
			if (field === 'provider') observation.provider = 'gitlab';
			if (field === 'repository_id') observation.repository_id++;
			if (field === 'version') observation.version = 'other';
			if (field === 'asset_id') observation.asset_id++;
			if (field === 'sha256') observation.sha256 = 'f'.repeat(64);
			await writeFile(join(directory, 'downloads.json'), JSON.stringify({ ...snapshot, releases: [observation] }));
			expect((await loadCatalogue(directory)).plugins[0]?.downloads).toEqual({ state: 'unavailable' });
		},
	);

	test('case variants remain unknown extension fields', async () => {
		const directory = await createExport([{
			name: 'Plugin',
			versions: [{
				version: 'v1',
				publishedAt: '2026-01-01T00:00:00Z',
				count: 1,
				metadata: {
					name: 'Correct',
					description: 'Correct description',
					license: 'MIT',
					Name: { future: true },
					Description: ['future'],
					License: 'Wrong',
				},
			}],
		}]);
		expect((await loadCatalogue(directory)).plugins[0]).toMatchObject({
			name: 'Correct',
			description: 'Correct description',
			license: 'MIT',
		});
	});

	test('only curated aliases supply shorthand; digest revocation covers every tag', async () => {
		const sha256 = 'f'.repeat(64);
		const directory = await createExport([{
			name: 'Metadata does not own an alias',
			aliases: ['curated'],
			versions: [
				{ version: 'v1', publishedAt: '2026-01-01T00:00:00Z', count: 1, sha256, state: 'revoked' },
				{ version: 'v2', publishedAt: '2026-01-02T00:00:00Z', count: 2, sha256 },
			],
		}, fixture('No alias')]);
		const data = await loadCatalogue(directory);
		expect(data.plugins[0]?.releases.map(release => [release.reference, release.state])).toEqual([
			['curated@v2', 'revoked'],
			['curated@v1', 'revoked'],
		]);
		expect(data.plugins[1]?.releases[0]?.reference).toBe('github.com/publisher/plugin-2@v1.0.0');
	});

	test('projects manifest assets and OCI sources without inventing OCI downloads', async () => {
		const reference = `oci://ghcr.io:5443/publisher/plugin@sha256:${'c'.repeat(64)}`;
		const directory = await createExport([{
			name: 'Sources',
			versions: [
				{
					version: 'manifest',
					publishedAt: '2026-01-01T00:00:00Z',
					count: 1,
					source: { type: 'release-asset', name: 'plugin.json.gz' },
				},
				{ version: 'oci', publishedAt: '2026-01-02T00:00:00Z', count: 50, source: { type: 'oci', reference } },
			],
		}]);
		const releases = (await loadCatalogue(directory)).plugins[0]?.releases;
		expect(releases?.[0]).toMatchObject({
			kind: 'component',
			source: { type: 'oci', reference },
			pinnedURL: reference,
			sha256: 'c'.repeat(64),
			downloads: { state: 'unsupported' },
		});
		expect(releases?.[1]).toMatchObject({
			kind: 'manifest',
			source: { type: 'release-asset', name: 'plugin.json.gz' },
		});
	});

	test('projects the interfaces each version imports and exports', async () => {
		const interfaces = {
			imports: ['wasi:cli/environment@0.2.0', 'kjanat:actionlint/invocation-context@0.2.0'],
			exports: ['kjanat:actionlint/analyzer@0.2.0'],
		};
		const directory = await createExport([{
			name: 'Plugin',
			versions: [
				{ version: 'v1', publishedAt: '2026-01-01T00:00:00Z', count: 1 },
				{ version: 'v2', publishedAt: '2026-01-02T00:00:00Z', count: 1, interfaces },
				{ version: 'v3', publishedAt: '2026-01-03T00:00:00Z', count: 1, interfaces: { imports: [], exports: [] } },
			],
		}]);
		expect((await loadCatalogue(directory)).plugins[0]?.releases.map(release => release.interfaces)).toEqual([
			{ imports: [], exports: [] },
			interfaces,
			null,
		]);
	});

	test.each(['imports', 'exports'] as const)('rejects a version listing only its %s', async field => {
		const directory = await createExport([{
			name: 'Plugin',
			versions: [{
				version: 'v1',
				publishedAt: '2026-01-01T00:00:00Z',
				count: 1,
				interfaces: { [field]: ['kjanat:actionlint/analyzer@0.2.0'] },
			}],
		}]);
		await expect(loadCatalogue(directory)).rejects.toThrow('both imports and exports or neither');
	});
});
