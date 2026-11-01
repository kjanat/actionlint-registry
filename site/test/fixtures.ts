import { afterEach } from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { ReleaseState } from '#schema.ts';

export interface VersionFixture {
	version: string;
	publishedAt: string;
	count: number | null;
	sha256?: string;
	state?: ReleaseState;
	reason?: string;
	replacement?: string;
	metadata?: Record<string, unknown>;
	source?: { type: 'release-asset'; name: string } | { type: 'oci'; reference: string };
}
export interface PluginFixture {
	name: string;
	repository?: string;
	repositoryID?: number;
	pluginID?: string;
	identityVersion?: 2;
	aliases?: string[];
	versions: VersionFixture[];
}
const temporary: string[] = [];
afterEach(async () => {
	for (const directory of temporary.splice(0)) await rm(directory, { recursive: true, force: true });
});

export function fixture(name: string, count: number | null = 10): PluginFixture {
	return { name, versions: [{ version: 'v1.0.0', publishedAt: '2026-03-29T00:30:00Z', count }] };
}

export async function createExport(plugins: PluginFixture[]): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), 'registry-site-test-'));
	temporary.push(directory);
	async function write(path: string, value: unknown) {
		await mkdir(dirname(join(directory, path)), { recursive: true });
		await writeFile(join(directory, path), JSON.stringify(value));
	}
	const catalogue = [];
	const downloads = [];
	const statuses = [];
	for (const [index, plugin] of plugins.entries()) {
		const key = (index + 1).toString(16).padStart(64, '0');
		const repository = plugin.repository ?? `publisher/plugin-${index + 1}`;
		const repositoryID = plugin.repositoryID ?? index + 1;
		const pluginID = plugin.pluginID ?? `plugin-${index + 1}`;
		const name = plugin.identityVersion === 2 ? pluginID.toLowerCase() : `github.com/${repository}`;
		const manifest = `plugins/${key}/index.json`;
		catalogue.push({ name, plugin_id: pluginID, manifest, aliases: plugin.aliases ?? [] });
		const versions = [];
		for (const [versionIndex, version] of plugin.versions.entries()) {
			const hash = (versionIndex + 1).toString(16).padStart(64, '0');
			const sourceDigest = version.source?.type === 'oci'
				? /@sha256:([a-f0-9]{64})$/u.exec(version.source.reference)?.[1]
				: undefined;
			const sha256 = sourceDigest ?? version.sha256 ?? (index * 100 + versionIndex + 1).toString(16).padStart(64, 'a');
			const record = `versions/${hash}.json`;
			const asset_id = version.source?.type === 'oci' ? 0 : index * 100 + versionIndex + 1;
			versions.push({ version: version.version, record, compatibility: [] });
			await write(`plugins/${key}/${record}`, {
				record_version: 2,
				...(plugin.identityVersion === 2 ? { identity_version: 2 } : {}),
				submission: version.source
					? {
						schema_version: 2,
						provider: 'github',
						repository,
						tag: version.version,
						kind: version.source.type === 'oci' ? 'component' : 'manifest',
						artifact: version.source.type === 'oci'
							? version.source
							: { ...version.source, sha256 },
					}
					: {
						schema_version: 1,
						provider: 'github',
						repository,
						tag: version.version,
						asset: 'plugin.wasm',
						sha256,
						kind: 'component',
					},
				repository_id: repositoryID,
				asset_id,
				url: version.source?.type === 'oci'
					? version.source.reference
					: `https://github.com/${repository}/releases/download/${version.version}/${
						version.source?.type === 'release-asset' ? version.source.name : 'plugin.wasm'
					}`,
				published_at: version.publishedAt,
				artifact: {
					plugin_id: pluginID,
					metadata: version.metadata
						?? { name: plugin.name, description: `${plugin.name} description`, license: 'MIT' },
				},
			});
			if (version.source?.type !== 'oci') {
				downloads.push({
					provider: 'github',
					repository_id: repositoryID,
					version: version.version,
					asset_id,
					sha256,
					...(version.count === null ? { status: 'unavailable' } : { status: 'available', count: version.count }),
				});
			}
			if (version.state) {
				statuses.push({
					name,
					version: version.version,
					sha256,
					status: version.state,
					reason: version.reason ?? 'Maintainer explanation',
					replacement: version.replacement,
				});
			}
		}
		await write(manifest, {
			plugin: {
				schema_version: plugin.identityVersion ?? 1,
				provider: 'github',
				repository,
				repository_id: String(repositoryID),
				plugin_id: pluginID,
			},
			versions,
		});
	}
	await write('index.json', { schema_version: 1, statuses: 'statuses.json', plugins: catalogue });
	await write('downloads.json', { schema_version: 1, observed_at: '2026-03-29T01:30:00Z', releases: downloads });
	await write('statuses.json', { schema_version: 1, releases: statuses });
	return directory;
}
