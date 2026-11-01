import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { checkCandidate, checkPublished } from '@/scripts/check.ts';
import { cleanEnvironment, execute, object } from '@/scripts/process.ts';

for (const local of [false, true]) {
	test(`OCI rehearsal ${local ? 'from a local layout stays offline' : 'limits network to acquisition'} and binds the root`, () =>
		exerciseOCIRehearsal(local));
}

async function exerciseOCIRehearsal(local: boolean) {
	const directory = await mkdtemp(join(tmpdir(), 'registry-oci-rehearsal-'));
	const rootBytes = JSON.stringify({ schemaVersion: 2, layers: [] });
	const digest = createHash('sha256').update(rootBytes).digest('hex');
	const primaryBytes = 'primary layer bytes differ from the OCI root';
	const primaryDigest = createHash('sha256').update(primaryBytes).digest('hex');
	const reference = `oci://ghcr.io/owner/repo/plugin@sha256:${digest}`;
	const artifact = {
		sha256: digest,
		repository: 'https://github.com/owner/repo',
		plugin_id: 'github.com/owner/repo/plugin',
		plugin_version: '1.0.0',
		kind: 'manifest',
		contract: 'process-v1',
	};
	let catalogue = '';
	let cachedRoot = '';
	let cachedPrimary = '';
	let probes = 0;
	try {
		const host = join(directory, 'host');
		const fixture = join(directory, 'fixture.ts');
		const registry = join(directory, 'registry');
		const report = join(directory, 'candidate.json');
		await writeFile(host, 'tested host');
		await writeFile(fixture, 'trusted behavioral fixture');
		const receipt = await checkCandidate({
			actionlint: host,
			fixture,
			registry,
			artifact: reference,
			store: directory,
			report,
			allowConfigProcesses: true,
			...(local ? { ociLayout: join(directory, 'layout') } : {}),
		}, async (binary, args, cwd, env) => {
			if (args[0] === 'version') return JSON.stringify({ version: 'host' });
			if (binary === registry) {
				assert.equal(args[args.indexOf('--artifact') + 1], reference);
				assert.equal(env.HTTPS_PROXY, local ? 'http://127.0.0.1:1' : undefined);
				if (local) assert.equal(args[args.indexOf('--oci-layout') + 1], join(directory, 'layout'));
				const output = args[args.indexOf('--output') + 1];
				assert.ok(output);
				catalogue = output;
				await mkdir(catalogue);
				await writeFile(
					join(catalogue, 'index.json'),
					JSON.stringify({
						plugins: [{
							name: artifact.plugin_id,
							plugin_id: artifact.plugin_id,
						}],
					}),
				);
				if (local) {
					await mkdir(join(catalogue, 'oci-blobs'));
					await writeFile(join(catalogue, 'oci-blobs', digest), rootBytes);
					await writeFile(join(catalogue, 'oci-blobs', primaryDigest), primaryBytes);
				}
				return JSON.stringify({ artifact });
			}
			if (args[0] === 'plugin') {
				assert.equal(env.HTTPS_PROXY, local ? 'http://127.0.0.1:1' : undefined);
				assert.ok(args.includes(artifact.plugin_id));
				assert.ok(env.LOCALAPPDATA);
				assert.ok(env.HOME);
				const cacheBase = process.platform === 'darwin' ? join(env.HOME, 'Library', 'Caches') : env.LOCALAPPDATA;
				const cache = join(cacheBase, 'actionlint', 'artifacts');
				await mkdir(cache, { recursive: true });
				cachedRoot = join(cache, digest);
				cachedPrimary = join(cache, primaryDigest);
				if (local) {
					assert.equal(await readFile(cachedRoot, 'utf8'), rootBytes);
					assert.equal(await readFile(cachedPrimary, 'utf8'), primaryBytes);
				} else {
					await writeFile(cachedRoot, rootBytes);
					await writeFile(cachedPrimary, primaryBytes);
				}
				await mkdir(join(cwd, '.github'));
				await writeFile(join(cwd, '.github', 'actionlint.yaml'), 'plugins: []\n');
				return JSON.stringify({
					plugins: [{
						source: 'candidate',
						sha256: digest,
						name: artifact.plugin_id,
						plugin_id: artifact.plugin_id,
						repository: 'github.com/owner/repo',
						version: 'v1.0.0',
						contract: artifact.contract,
					}],
				});
			}
			assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:1');
			if (args[0] === 'check') {
				assert.ok(args.includes('--allow-config-processes'));
				return JSON.stringify({ completed: true, exit_code: 0, diagnostics: [] });
			}
			if (args.includes('verify')) {
				probes++;
				if (probes === 2) await assert.rejects(readFile(join(catalogue, 'index.json')), /ENOENT/);
				return JSON.stringify({ checks: ['selected package executed'], probe: ['check', '--json'] });
			}
			assert.ok(args.includes('prepare'));
			return '';
		}, async (_binary, args, _cwd, env, expected) => {
			assert.equal(expected, 3);
			assert.ok(args.includes('--allow-config-processes'));
			assert.equal(env.HTTPS_PROXY, 'http://127.0.0.1:1');
			await assert.rejects(readFile(cachedRoot), /ENOENT/);
			assert.equal(await readFile(cachedPrimary, 'utf8'), primaryBytes);
			return { stdout: '', stderr: 'plugin artifact is not cached' };
		});
		assert.equal(probes, 2);
		assert.equal(receipt.artifact.sha256, digest);
		assert.equal(receipt.installation.name, artifact.plugin_id);
		assert.equal(object(JSON.parse(await readFile(report, 'utf8'))).missing_cache_rejected, true);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

test('a candidate report cannot overwrite an OCI layout file', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-layout-report-'));
	try {
		const report = join(directory, 'index.json');
		await writeFile(report, 'original layout index');
		await assert.rejects(
			checkCandidate({
				actionlint: 'unused',
				fixture: 'unused',
				registry: 'unused',
				store: 'unused',
				artifact: `oci://ghcr.io/owner/repo@sha256:${'a'.repeat(64)}`,
				ociLayout: directory,
				report,
			}),
			/overwrite the OCI layout/,
		);
		assert.equal(await readFile(report, 'utf8'), 'original layout index');
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('delivery requests the actual release tag without synthesizing a version prefix', async () => {
	// Stop at the installer call: a release named 1.0.0 must never request v1.0.0.
	// Capture the installer handoff and stop before installation begins.
	const directory = await mkdtemp(join(tmpdir(), 'registry-delivery-tag-'));
	try {
		const host = join(directory, 'host');
		const fixture = join(directory, 'fixture.ts');
		const receipt = join(directory, 'candidate.json');
		const hostBytes = 'host handshake';
		const fixtureBytes = 'export async function prepare() {}';
		const hash = (value: string) => createHash('sha256').update(value).digest('hex');
		await writeFile(host, hostBytes);
		await writeFile(fixture, fixtureBytes);
		await writeFile(
			receipt,
			JSON.stringify({
				schema_version: 1,
				offline: true,
				missing_cache_rejected: true,
				host: { sha256: hash(hostBytes) },
				fixture: { sha256: hash(fixtureBytes) },
				artifact: { repository: 'https://github.com/owner/repo', plugin_version: 'v1.0.0', sha256: 'a'.repeat(64) },
			}),
		);
		for (const tag of ['1.0.0', 'v1.0.0']) {
			const stopped = new Error('Installer handoff verified');
			let installs = 0;
			await assert.rejects(
				checkPublished({
					actionlint: host,
					fixture,
					receipt,
					report: join(directory, 'delivery.json'),
					tag,
				}, async (binary, args, cwd, env, expected) => {
					if (args[0] === 'version') return JSON.stringify({ version: 'test host' });
					if (args[0] === 'plugin') {
						assert.deepEqual(args, ['plugin', 'install', 'github.com/owner/repo', '--version', tag, '--json']);
						installs++;
						throw stopped;
					}
					return execute(binary, args, cwd, env, expected);
				}),
				(error) => error === stopped,
			);
			assert.equal(installs, 1);
		}
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('a report cannot replace candidate bytes or its delivery receipt', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-report-'));
	try {
		const artifact = join(directory, 'plugin.wasm');
		await writeFile(artifact, 'candidate bytes');
		await assert.rejects(
			checkCandidate({
				actionlint: process.execPath,
				fixture: 'unused.ts',
				registry: 'unused',
				artifact,
				store: directory,
				report: artifact,
			}),
			/overwrite an input/,
		);
		assert.equal(await readFile(artifact, 'utf8'), 'candidate bytes');
		await assert.rejects(
			checkPublished({
				tag: '1.0.0',
				actionlint: process.execPath,
				fixture: 'unused.ts',
				receipt: artifact,
				report: artifact,
			}),
			/overwrite an input/,
		);
		assert.equal(await readFile(artifact, 'utf8'), 'candidate bytes');
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('failed verification removes an old success receipt', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-stale-receipt-'));
	try {
		const report = join(directory, 'candidate.json');
		await writeFile(report, '{"offline":true}');
		await assert.rejects(
			checkCandidate({
				actionlint: join(directory, 'missing-host'),
				fixture: 'unused.ts',
				registry: 'unused',
				artifact: 'unused.wasm',
				store: directory,
				report,
			}),
			/ENOENT/,
		);
		await assert.rejects(readFile(report), /ENOENT/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('failed delivery preflight removes an old delivery report', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-delivery-report-'));
	try {
		const receipt = join(directory, 'candidate.json');
		const report = join(directory, 'installation.json');
		await writeFile(receipt, '{}');
		await writeFile(report, '{"offline":true}');
		await assert.rejects(
			checkPublished({ actionlint: 'unused', fixture: 'unused.ts', receipt, report, tag: '1.0.0' }),
			/successful candidate receipt/,
		);
		await assert.rejects(readFile(report), /ENOENT/);
		assert.equal(await readFile(receipt, 'utf8'), '{}');
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('fixture processes receive a fresh home and no inherited credentials', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-environment-'));
	try {
		const environment = cleanEnvironment(directory, join(directory, 'cache'));
		const output = await execute(
			process.execPath,
			['-e', 'console.log(JSON.stringify(process.env))'],
			directory,
			environment,
		);
		const actual: unknown = JSON.parse(output);
		assert.ok(actual && typeof actual === 'object');
		assert.equal('GH_TOKEN' in actual, false);
		assert.equal('ACTIONS_ID_TOKEN_REQUEST_TOKEN' in actual, false);
		assert.equal('HOME' in actual && actual.HOME, directory);
		assert.equal(
			'HTTPS_PROXY' in actual && actual.HTTPS_PROXY,
			'http://127.0.0.1:1',
		);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('guest output cannot grow the check process without a bound', async () => {
	await assert.rejects(
		execute(
			process.execPath,
			['-e', 'process.stdout.write("x".repeat(3 * 1024 * 1024))'],
			process.cwd(),
			process.env,
		),
		/exceeded 2 MiB/,
	);
});
