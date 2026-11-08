import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { cleanEnvironment, execute, executeResult, object, strings } from '@/scripts/process.ts';

interface InstallationOptions {
	actionlint: string;
	fixture: string;
	report: string;
	allowConfigProcesses?: boolean;
}
export interface CheckOptions extends InstallationOptions {
	registry: string;
	artifact: string;
	store: string;
	checker?: string;
	kind?: 'core' | 'component' | 'manifest';
	ociLayout?: string;
}
export interface PublishedOptions extends InstallationOptions {
	receipt: string;
	tag: string;
}
type Source =
	| { kind: 'candidate'; options: CheckOptions }
	| { kind: 'published'; artifact: Record<string, unknown>; version: string; name?: string };

function sha256(data: Buffer): string {
	return createHash('sha256').update(data).digest('hex');
}
function string(value: unknown, name: string): string {
	if (typeof value !== 'string' || value.length === 0) {
		throw new Error(`Missing ${name}`);
	}
	return value;
}

async function cachedArtifacts(
	directory: string,
	digest: string,
): Promise<string[]> {
	const found: string[] = [];
	for (const item of await readdir(directory, { withFileTypes: true })) {
		const path = join(directory, item.name);
		if (item.isDirectory()) {
			found.push(...(await cachedArtifacts(path, digest)));
		} else if (
			item.isFile()
			&& item.name === digest
			&& sha256(await readFile(path)) === digest
		) {
			found.push(path);
		}
	}
	return found;
}

export async function checkCandidate(options: CheckOptions, run = execute, runResult = executeResult) {
	if (options.ociLayout) {
		const location = relative(resolve(options.ociLayout), resolve(options.report));
		if (location === '' || (!isAbsolute(location) && location.split(sep)[0] !== '..')) {
			throw new Error('Report must not overwrite the OCI layout');
		}
	}
	await prepareReport(options, [
		options.artifact,
		options.registry,
		...(options.checker ? [options.checker] : []),
		...(options.ociLayout ? [options.ociLayout] : []),
	]);
	if (options.ociLayout !== undefined && (!options.ociLayout || !options.artifact.startsWith('oci://'))) {
		throw new Error('A local OCI layout requires a pinned --oci reference');
	}
	if (options.checker !== undefined && !options.artifact.startsWith('oci://')) {
		const report = object(
			object(
				JSON.parse(
					await run(
						resolve(options.registry),
						['check', '--checker', resolve(options.checker), '--artifact', resolve(options.artifact)],
						process.cwd(),
						process.env,
					),
				),
			).report,
		);
		if (report.outcome === 'failed') {
			throw new Error(`Registry checker rejected the candidate: ${String(report.detail)}`);
		}
	}
	return verifyInstallation(options, { kind: 'candidate', options }, run, runResult);
}

// Seed only the graph verified and snapshotted by the registry inspector. The
// host still verifies its selected manifests, metadata and layers on install.
async function seedOCICache(catalogue: string, directory: string, digest: string): Promise<void> {
	const entries = await readdir(join(catalogue, 'oci-blobs'), { withFileTypes: true });
	if (!entries.some((entry) => entry.name === digest)) throw new Error('OCI snapshot is missing its pinned root');
	await mkdir(directory, { recursive: true });
	let total = 0;
	for (const entry of entries) {
		if (!entry.isFile() || !/^[a-f0-9]{64}$/u.test(entry.name)) throw new Error('Invalid OCI snapshot blob');
		const data = await readFile(join(catalogue, 'oci-blobs', entry.name));
		total += data.length;
		if (total > 128 * 1024 * 1024 || sha256(data) !== entry.name) {
			throw new Error('OCI snapshot exceeds its size limit or contains corrupt bytes');
		}
		await writeFile(join(directory, entry.name), data, { flag: 'wx' });
	}
}

export async function checkPublished(options: PublishedOptions, run = execute) {
	await prepareReport(options, [options.receipt]);
	const receipt = object(JSON.parse(await readFile(options.receipt, 'utf8')));
	if (
		receipt.schema_version !== 1
		|| receipt.offline !== true
		|| receipt.missing_cache_rejected !== true
	) {
		throw new Error('A successful candidate receipt is required');
	}
	if (
		object(receipt.fixture).sha256 !== sha256(await readFile(options.fixture))
	) {
		throw new Error('Delivery fixture differs from the tested candidate');
	}
	if (object(receipt.host).sha256 !== sha256(await readFile(options.actionlint))) {
		throw new Error('Delivery host differs from the tested candidate');
	}
	const artifact = object(receipt.artifact);
	if (
		artifact.kind === 'manifest' && (receipt.allow_config_processes !== true || options.allowConfigProcesses !== true)
	) {
		throw new Error(
			'Process delivery checks require a consented candidate receipt and explicit --allow-config-processes consent',
		);
	}
	if (
		!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(options.tag)
		|| options.tag.replace(/^v/u, '') !== string(artifact.plugin_version, 'version').replace(/^v/u, '')
	) {
		throw new Error('Delivery release tag differs from the tested candidate');
	}
	return verifyInstallation(options, {
		kind: 'published',
		artifact,
		version: options.tag,
		...(receipt.installation === undefined || object(receipt.installation).name === undefined
			? {}
			: { name: string(object(receipt.installation).name, 'installed package name') }),
	}, run);
}

async function prepareReport(options: InstallationOptions, extraInputs: string[]) {
	const inputs = [options.actionlint, options.fixture, ...extraInputs];
	if (
		inputs.some(
			(input) => resolve(input).toLowerCase() === resolve(options.report).toLowerCase(),
		)
	) {
		throw new Error('Report must not overwrite an input');
	}
	await rm(resolve(options.report), { force: true });
}

async function verifyInstallation(
	options: InstallationOptions,
	source: Source,
	run = execute,
	runResult = executeResult,
) {
	const root = await mkdtemp(join(tmpdir(), 'registry-candidate-'));
	try {
		const project = join(root, 'project');
		const cache = join(root, 'cache');
		const home = join(root, 'home');
		for (const directory of [project, cache, home, join(project, '.git')]) {
			await mkdir(directory);
		}
		const env = cleanEnvironment(home, cache);
		const acquisitionEnvironment = { ...env };
		for (const proxy of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']) {
			delete acquisitionEnvironment[proxy];
		}
		const catalogue = join(root, 'catalogue');
		const binary = join(
			root,
			process.platform === 'win32' ? 'actionlint.exe' : 'actionlint',
		);
		await copyFile(resolve(options.actionlint), binary);
		await chmod(binary, 0o700);
		const hostDigest = sha256(await readFile(binary));
		const hostVersion: unknown = JSON.parse(
			await run(binary, ['version', '--json'], project, env),
		);
		const fixture = resolve(options.fixture);
		const fixtureDigest = sha256(await readFile(fixture));
		const cli = fileURLToPath(new URL('./cli.ts', import.meta.url));
		await run(
			process.execPath,
			[
				cli,
				'fixture',
				'--fixture',
				fixture,
				'--actionlint',
				binary,
				'--directory',
				project,
				'--phase',
				'prepare',
			],
			project,
			env,
		);
		const artifact = source.kind === 'published'
			? source.artifact
			: object(
				object(
					JSON.parse(
						await run(
							resolve(source.options.registry),
							[
								'candidate',
								'--artifact',
								source.options.artifact.startsWith('oci://')
									? source.options.artifact
									: resolve(source.options.artifact),
								'--store',
								resolve(source.options.store),
								'--output',
								catalogue,
								...(source.options.ociLayout ? ['--oci-layout', resolve(source.options.ociLayout)] : []),
							],
							project,
							source.options.artifact.startsWith('oci://') && !source.options.ociLayout ? acquisitionEnvironment : env,
						),
					),
				).artifact,
			);
		if (source.kind === 'candidate' && source.options.kind && artifact.kind !== source.options.kind) {
			throw new Error('Requested execution kind differs from the inspected candidate');
		}
		if (artifact.kind === 'manifest' && options.allowConfigProcesses !== true) {
			throw new Error('Process candidate checks require explicit --allow-config-processes consent');
		}
		const digest = string(artifact.sha256, 'artifact digest');
		if (source.kind === 'candidate' && source.options.ociLayout) {
			const cacheBase = process.platform === 'darwin' ? join(home, 'Library', 'Caches') : cache;
			await seedOCICache(catalogue, join(cacheBase, 'actionlint', 'artifacts'), digest);
		}
		const repository = string(artifact.repository, 'repository').replace(
			/^https:\/\//u,
			'',
		);
		let name = source.kind === 'published' ? source.name ?? repository : repository;
		if (source.kind === 'candidate') {
			const entries = object(JSON.parse(await readFile(join(catalogue, 'index.json'), 'utf8'))).plugins;
			if (!Array.isArray(entries) || entries.length !== 1) {
				throw new Error('Candidate catalogue must contain one package');
			}
			const item = object(entries[0]);
			if (item.plugin_id !== artifact.plugin_id) throw new Error('Candidate catalogue plugin identity changed');
			name = string(item.name, 'candidate package name');
		}
		if (
			name.toLowerCase() !== repository.toLowerCase()
			&& (name !== string(artifact.plugin_id, 'plugin ID').toLowerCase()
				|| !name.startsWith(`${repository.toLowerCase()}/`))
		) throw new Error('Package selector is outside its publishing repository');
		const version = source.kind === 'published'
			? source.version
			: `v${string(artifact.plugin_version, 'version').replace(/^v/u, '')}`;
		const install = ['plugin', 'install', name, '--version', version, '--json'];
		if (source.kind === 'candidate') {
			install.push('--registry', `${pathToFileURL(catalogue).href}/`);
		}
		const needsAcquisition = source.kind === 'published'
			|| (source.options.artifact.startsWith('oci://') && !source.options.ociLayout);
		const installation = object(JSON.parse(
			await run(binary, install, project, needsAcquisition ? acquisitionEnvironment : env),
		));
		const plugins = installation.plugins;
		if (!Array.isArray(plugins) || plugins.length !== 1) {
			throw new Error('Installer must report exactly one installed candidate');
		}
		const pin = object(plugins[0]);
		if (
			(source.kind === 'candidate'
				? pin.source !== 'candidate'
				: pin.source === 'candidate')
			|| pin.sha256 !== digest
			|| pin.version !== version
			|| string(pin.name, 'installed repository').toLowerCase() !== name.toLowerCase()
			|| pin.contract !== artifact.contract
			|| pin.plugin_id !== artifact.plugin_id
			|| (pin.repository !== undefined && pin.repository !== repository)
		) {
			throw new Error('Installed plugin differs from inspected package');
		}
		const configPath = join(project, '.github', 'actionlint.yaml');
		const config = await readFile(configPath);
		const verifyConfig = async () => {
			if (!(await readFile(configPath)).equals(config)) {
				throw new Error('Checking modified the project configuration');
			}
		};
		const probeFixture = async () =>
			object(
				JSON.parse(
					await run(
						process.execPath,
						[
							cli,
							'fixture',
							'--fixture',
							fixture,
							'--actionlint',
							binary,
							'--directory',
							project,
							'--phase',
							'verify',
							...(options.allowConfigProcesses ? ['--allow-config-processes'] : []),
						],
						project,
						env,
					),
				),
			);
		const first = await probeFixture();
		await verifyConfig();
		const checks = strings(first.checks);
		const probe = strings(first.probe);
		const probeArgs = options.allowConfigProcesses && !probe.includes('--allow-config-processes')
			? [...probe, '--allow-config-processes']
			: probe;
		const positive = object(JSON.parse(await run(binary, probeArgs, project, env, [0, 1])));
		await verifyConfig();
		if (
			positive.completed !== true
			|| (positive.exit_code !== 0 && positive.exit_code !== 1)
			|| !Array.isArray(positive.diagnostics)
		) {
			throw new Error(
				'Fixture probe did not complete analysis before cache removal',
			);
		}
		if (source.kind === 'candidate') await rm(catalogue, { recursive: true });
		const offline = await probeFixture();
		await verifyConfig();
		if (JSON.stringify(offline) !== JSON.stringify(first)) {
			throw new Error('Offline fixture results changed');
		}
		const cached = await cachedArtifacts(root, digest);
		const [cachedArtifact] = cached;
		if (cached.length !== 1 || cachedArtifact === undefined) {
			throw new Error(
				'Expected exactly one cached candidate with the inspected digest',
			);
		}
		await rm(cachedArtifact);
		const missing = await runResult(binary, probeArgs, project, env, 3);
		await verifyConfig();
		if (
			missing.stdout.trim() !== ''
			|| !missing.stderr.toLowerCase().includes('plugin')
		) {
			throw new Error('Missing cache did not report a plugin error');
		}
		const receipt = {
			schema_version: 1,
			artifact: { ...artifact, sha256: digest },
			host: { sha256: hostDigest, version: hostVersion },
			fixture: { sha256: fixtureDigest, checks },
			allow_config_processes: options.allowConfigProcesses === true,
			installation: { name, repository, version, sha256: digest },
			offline: true,
			missing_cache_rejected: true,
		};
		if (sha256(await readFile(fixture)) !== fixtureDigest) {
			throw new Error('Fixture changed during verification');
		}
		await writeFile(
			resolve(options.report),
			`${JSON.stringify(receipt, null, 2)}\n`,
		);
		return receipt;
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}
