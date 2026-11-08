import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { HTTPClient, HTTPError } from '@/scripts/http.ts';
import {
	GitHubPublisher,
	publishOCI,
	verifyCandidateReceipt,
	verifyPackage,
	waitForPublication,
} from '@/scripts/publish.ts';
import type { Submission } from '@/scripts/publish.ts';

const identifier = '12345678-1234-4234-8234-123456789abc';
const checksum = (value: string | Buffer) => createHash('sha256').update(value).digest('hex');

test('OCI publication requires an exact host rehearsal before requesting submission credentials', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-oci-publication-'));
	const actionlint = join(directory, 'host');
	const fixture = join(directory, 'fixture.ts');
	const candidateReceipt = join(directory, 'candidate.json');
	const digest = checksum('OCI root manifest');
	const reference = `oci://ghcr.io/owner/repo/plugin@sha256:${digest}`;
	const entry: Submission = {
		schema_version: 2,
		repository: 'owner/repo',
		tag: 'v1.0.0',
		kind: 'manifest',
		artifact: { type: 'oci', reference },
	};
	const valid = {
		schema_version: 1,
		offline: true,
		missing_cache_rejected: true,
		allow_config_processes: true,
		artifact: {
			sha256: digest,
			kind: 'manifest',
			repository: 'https://github.com/owner/repo',
			plugin_id: 'github.com/owner/repo/plugin',
			plugin_version: '1.0.0',
		},
		installation: { sha256: digest, name: 'github.com/owner/repo/plugin', version: 'v1.0.0' },
		host: { sha256: checksum('tested host') },
		fixture: { sha256: checksum('tested fixture'), checks: ['native execution'] },
	};
	const options = {
		actionlint,
		fixture,
		candidateReceipt,
		allowConfigProcesses: true,
		reference,
		repository: entry.repository,
		tag: entry.tag,
		kind: entry.kind,
		receipt: join(directory, 'publication.json'),
		timeoutSeconds: 1,
	};
	try {
		await writeFile(actionlint, 'tested host');
		await writeFile(fixture, 'tested fixture');
		await writeFile(candidateReceipt, JSON.stringify(valid));
		await verifyCandidateReceipt(candidateReceipt, entry, actionlint, fixture);
		await assert.rejects(publishOCI({ ...options, allowConfigProcesses: false }), /explicit .*consent/);
		for (
			const artifact of [
				{ ...valid.artifact, sha256: checksum('primary layer') },
				{ ...valid.artifact, plugin_version: '1.0.1' },
			]
		) {
			await writeFile(candidateReceipt, JSON.stringify({ ...valid, artifact }));
			await assert.rejects(publishOCI(options), /Candidate receipt/);
		}
		await writeFile(candidateReceipt, JSON.stringify(valid));
		await writeFile(actionlint, 'different host');
		await assert.rejects(publishOCI(options), /host changed/);
		await assert.rejects(readFile(options.receipt), /ENOENT/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

async function fixture() {
	const directory = await mkdtemp(join(tmpdir(), 'registry-publication-'));
	const wasm = Buffer.from('\0asm-candidate');
	const metadata = Buffer.from('{"name":"test"}');
	await writeFile(join(directory, 'plugin.wasm'), wasm);
	await writeFile(join(directory, 'metadata.json'), metadata);
	await writeFile(
		join(directory, 'SHA256SUMS'),
		`${checksum(wasm)}  plugin.wasm\n${checksum(metadata)}  metadata.json\n`,
	);
	return {
		directory,
		sha256: checksum(wasm),
		cleanup: () => rm(directory, { recursive: true, force: true }),
	};
}

async function server(
	handler: (
		request: IncomingMessage,
		response: ServerResponse,
	) => Promise<void> | void,
) {
	const listener = createServer((request, response) => {
		Promise.resolve(handler(request, response)).catch((error) => {
			response.writeHead(500);
			response.end(String(error));
		});
	});
	await new Promise<void>((done) => listener.listen(0, '127.0.0.1', done));
	const address = listener.address();
	if (!address || typeof address === 'string') {
		throw new Error('Missing test listener address');
	}
	return {
		origin: `http://127.0.0.1:${address.port}`,
		close: () => new Promise<void>((done, reject) => listener.close((error) => (error ? reject(error) : done()))),
	};
}

async function body(request: IncomingMessage): Promise<Buffer> {
	const chunks: Buffer[] = [];
	for await (const chunk of request) chunks.push(Buffer.from(chunk));
	return Buffer.concat(chunks);
}

function json(response: ServerResponse, value: unknown, status = 200) {
	response.writeHead(status, { 'content-type': 'application/json' });
	response.end(JSON.stringify(value));
}

test('modified sidecars and extra files stop package publication', async () => {
	// A passing candidate digest cannot excuse changed metadata or an unlisted upload. These
	// cases use real package bytes and require verification to reject the changed package.
	const sample = await fixture();
	try {
		const pkg = await verifyPackage(
			sample.directory,
			'plugin.wasm',
			sample.sha256,
		);
		assert.deepEqual(
			pkg.files.map((file) => file.name),
			['SHA256SUMS', 'metadata.json', 'plugin.wasm'],
		);
		await writeFile(join(sample.directory, 'metadata.json'), '{}');
		await assert.rejects(
			verifyPackage(sample.directory, 'plugin.wasm', sample.sha256),
			/checksum mismatch/,
		);
		await writeFile(join(sample.directory, 'extra'), 'unreviewed');
		await assert.rejects(
			verifyPackage(sample.directory, 'plugin.wasm', sample.sha256),
			/Every package file/,
		);
	} finally {
		await sample.cleanup();
	}
});

test('process manifest release assets use their distributed-byte checksum', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-manifest-publication-'));
	const manifest = Buffer.from(JSON.stringify({ schema_version: 1, transport: 'process', metadata: {} }));
	try {
		await writeFile(join(directory, 'plugin.json'), manifest);
		await writeFile(join(directory, 'SHA256SUMS'), `${checksum(manifest)}  plugin.json\n`);
		const pkg = await verifyPackage(directory, 'plugin.json', checksum(manifest), 'manifest');
		assert.equal(pkg.asset, 'plugin.json');
		assert.equal(pkg.sha256, checksum(manifest));
		await assert.rejects(verifyPackage(directory, 'plugin.json', checksum(manifest)), /Wasm asset filename/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('candidate receipt must describe the artifact being published and completed offline checks', async () => {
	// A receipt from another build or an incomplete rehearsal must stop before GitHub publication.
	// Mutate each release identity and required outcome while keeping the other successful evidence.
	const sample = await fixture();
	const path = join(sample.directory, 'receipt.json');
	const host = join(sample.directory, 'host');
	const behavior = join(sample.directory, 'installation.ts');
	await writeFile(host, 'tested host');
	await writeFile(behavior, 'tested fixture');
	const entry = {
		repository: 'owner/repo',
		tag: 'v1.0.0',
		asset: 'plugin.wasm',
		sha256: sample.sha256,
		kind: 'component',
	};
	const valid = {
		schema_version: 1,
		artifact: {
			sha256: sample.sha256,
			repository: 'https://github.com/owner/repo',
			plugin_version: '1.0.0',
			kind: 'component',
		},
		installation: { version: 'v1.0.0', sha256: sample.sha256 },
		host: { sha256: checksum('tested host') },
		fixture: { sha256: checksum('tested fixture'), checks: ['source following'] },
		offline: true,
		missing_cache_rejected: true,
	};
	try {
		await writeFile(path, JSON.stringify(valid));
		await verifyCandidateReceipt(path, { ...entry, kind: 'component' }, host, behavior);
		for (const tag of ['1.0.0', 'v1.0.0']) {
			for (const version of ['1.0.0', 'v1.0.0']) {
				await writeFile(
					path,
					JSON.stringify({
						...valid,
						artifact: { ...valid.artifact, repository: 'https://github.com/OWNER/Repo', plugin_version: version },
					}),
				);
				await verifyCandidateReceipt(
					path,
					{ ...entry, repository: 'Owner/repo', tag, kind: 'component' },
					host,
					behavior,
				);
			}
		}
		for (
			const invalid of [
				{ ...valid, offline: false },
				{ ...valid, missing_cache_rejected: false },
				{ ...valid, artifact: { ...valid.artifact, sha256: 'c'.repeat(64) } },
				{
					...valid,
					artifact: {
						...valid.artifact,
						repository: 'https://github.com/other/repo',
					},
				},
				{ ...valid, artifact: { ...valid.artifact, plugin_version: '1.0.1' } },
				{ ...valid, installation: { ...valid.installation, version: 'v0.9.0' } },
				{ ...valid, fixture: { ...valid.fixture, checks: [] } },
			]
		) {
			await writeFile(path, JSON.stringify(invalid));
			await assert.rejects(
				verifyCandidateReceipt(path, { ...entry, kind: 'component' }, host, behavior),
				/Candidate receipt/,
			);
		}
		await writeFile(path, JSON.stringify(valid));
		await writeFile(host, 'different host');
		await assert.rejects(verifyCandidateReceipt(path, { ...entry, kind: 'component' }, host, behavior), /host changed/);
		await writeFile(host, 'tested host');
		await writeFile(behavior, 'different fixture');
		await assert.rejects(
			verifyCandidateReceipt(path, { ...entry, kind: 'component' }, host, behavior),
			/fixture changed/,
		);
	} finally {
		await sample.cleanup();
	}
});

test('process manifest receipt requires recorded native-execution consent', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'registry-process-receipt-'));
	const host = join(directory, 'host');
	const fixturePath = join(directory, 'fixture.ts');
	const receiptPath = join(directory, 'candidate.json');
	const hostBytes = 'host';
	const fixtureBytes = 'fixture';
	const digest = 'a'.repeat(64);
	const receipt = {
		schema_version: 1,
		offline: true,
		missing_cache_rejected: true,
		artifact: {
			sha256: digest,
			kind: 'manifest',
			repository: 'https://github.com/owner/repo',
			plugin_version: '1.0.0',
		},
		installation: { sha256: digest, version: 'v1.0.0' },
		host: { sha256: checksum(hostBytes) },
		fixture: { sha256: checksum(fixtureBytes), checks: ['native invocation'] },
		allow_config_processes: true,
	};
	try {
		await writeFile(host, hostBytes);
		await writeFile(fixturePath, fixtureBytes);
		await writeFile(receiptPath, JSON.stringify(receipt));
		const entry: Submission = {
			schema_version: 2,
			repository: 'owner/repo',
			tag: 'v1.0.0',
			kind: 'manifest',
			artifact: { type: 'release-asset', name: 'plugin.json', sha256: digest },
		};
		await verifyCandidateReceipt(receiptPath, entry, host, fixturePath);
		await writeFile(receiptPath, JSON.stringify({ ...receipt, allow_config_processes: false }));
		await assert.rejects(verifyCandidateReceipt(receiptPath, entry, host, fixturePath), /Candidate receipt/);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});

test('GitHub publication downloads every uploaded byte before making a draft public', async () => {
	// Exercise the actual HTTP publisher against a release service that stores upload bodies.
	// Corrupt one download and require the draft to stay private; matching bytes may publish once.
	for (
		const { corrupt, resume, notes } of [
			{ corrupt: false, resume: false, notes: 'Fix source tracking.' },
			{ corrupt: true, resume: false, notes: 'Fix source tracking.' },
			{ corrupt: false, resume: true, notes: 'Fix source tracking.' },
			{ corrupt: false, resume: false, notes: '' },
		]
	) {
		const sample = await fixture();
		const uploads = new Map<number, { name: string; bytes: Buffer }>();
		let draft = true;
		let created = resume;
		let creations = 0;
		if (resume) {
			uploads.set(1, { name: 'SHA256SUMS', bytes: await readFile(join(sample.directory, 'SHA256SUMS')) });
		}
		let publishes = 0;
		let downloads = 0;
		const description = () => ({
			id: 7,
			draft,
			immutable: !draft,
			assets: [...uploads].map(([id, file]) => ({ id, name: file.name })),
		});
		const remote = await server(async (request, response) => {
			assert.equal(request.headers.authorization, 'Bearer publisher-token');
			const url = new URL(request.url ?? '/', 'http://test');
			if (url.pathname.includes('/git/ref/tags/')) {
				return json(response, { ref: 'refs/tags/v1.0.0' });
			}
			if (url.pathname === '/graphql') {
				const requestBody = JSON.parse((await body(request)).toString());
				assert.deepEqual(requestBody.variables, { owner: 'owner', name: 'repo', tag: 'v1.0.0' });
				return json(response, {
					data: { repository: { release: created ? { databaseId: 7, tagName: 'v1.0.0' } : null } },
				});
			}
			if (url.pathname.endsWith('/tags/v1.0.0')) {
				return json(response, {}, 404);
			}
			if (
				url.pathname === '/repos/owner/repo/releases'
				&& request.method === 'POST'
			) {
				assert.equal(created, false, 'An existing draft must be resumed, never recreated');
				creations++;
				const value: unknown = JSON.parse((await body(request)).toString());
				assert.deepEqual(value, {
					tag_name: 'v1.0.0',
					name: 'v1.0.0',
					draft: true,
					prerelease: false,
					...(notes ? { body: notes } : { generate_release_notes: true }),
				});
				created = true;
				return json(response, description());
			}
			if (url.pathname.endsWith('/7/assets') && request.method === 'POST') {
				const name = url.searchParams.get('name');
				assert.ok(name);
				uploads.set(uploads.size + 1, { name, bytes: await body(request) });
				return json(response, {});
			}
			if (url.pathname.includes('/releases/assets/')) {
				const asset = uploads.get(Number(url.pathname.split('/').at(-1)));
				assert.ok(asset);
				downloads++;
				response.writeHead(200);
				response.end(
					corrupt && asset.name === 'plugin.wasm'
						? Buffer.alloc(asset.bytes.length)
						: asset.bytes,
				);
				return;
			}
			if (request.method === 'PATCH') {
				assert.ok(downloads >= uploads.size);
				assert.deepEqual(JSON.parse((await body(request)).toString()), {
					draft: false,
				});
				publishes++;
				draft = false;
			}
			json(response, description());
		});
		try {
			const pkg = await verifyPackage(
				sample.directory,
				'plugin.wasm',
				sample.sha256,
			);
			const publisher = new GitHubPublisher(
				'publisher-token',
				new HTTPClient(),
				remote.origin,
				remote.origin,
			);
			if (corrupt) {
				await assert.rejects(
					publisher.publish(
						'owner/repo',
						'v1.0.0',
						pkg,
						notes,
					),
					/asset differs/,
				);
				assert.equal(publishes, 0);
				assert.equal(draft, true);
			} else {
				await publisher.publish(
					'owner/repo',
					'v1.0.0',
					pkg,
					notes,
				);
				assert.equal(publishes, 1);
				assert.equal(creations, resume ? 0 : 1);
				for (const file of uploads.values()) {
					assert.deepEqual(
						file.bytes,
						await readFile(join(sample.directory, file.name)),
					);
				}
				await publisher.publish(
					'owner/repo',
					'v1.0.0',
					pkg,
					notes,
				);
				assert.equal(publishes, 1);
				assert.equal(uploads.size, pkg.files.length);
			}
		} finally {
			await remote.close();
			await sample.cleanup();
		}
	}
});

test('authentication failures never create a release and redirects never receive credentials', async () => {
	// GitHub auth failure is not a missing release. An authenticated redirect must also fail
	// before following its destination, otherwise an endpoint could disclose the publisher token.
	let mutations = 0;
	let captures = 0;
	let graphQLError = false;
	const remote = await server((request, response) => {
		if (request.method !== 'GET' && request.url !== '/graphql') mutations++;
		if (request.url === '/capture') captures++;
		if (graphQLError && request.url?.includes('/git/ref/tags/')) {
			return json(response, { ref: 'refs/tags/v1' });
		}
		if (graphQLError && request.url === '/graphql') {
			return json(response, { data: { repository: { release: null } }, errors: [{ message: 'Not authorized' }] });
		}
		response.writeHead(request.url === '/redirect' ? 302 : 403, {
			location: '/capture',
		});
		response.end();
	});
	try {
		await assert.rejects(
			new GitHubPublisher('secret', new HTTPClient(), remote.origin).publish(
				'owner/repo',
				'v1',
				{
					files: [],
					asset: 'plugin.wasm',
					sha256: 'a'.repeat(64),
				},
				'',
			),
			(error) => error instanceof HTTPError && error.status === 403,
		);
		assert.equal(captures, 0);
		assert.equal(mutations, 0);
		graphQLError = true;
		await assert.rejects(
			new GitHubPublisher('secret', new HTTPClient(), remote.origin).publish(
				'owner/repo',
				'v1',
				{ files: [], asset: 'plugin.wasm', sha256: 'a'.repeat(64) },
				'',
			),
			/GitHub release lookup failed/,
		);
		assert.equal(mutations, 0);
		await assert.rejects(
			new HTTPClient().json(`${remote.origin}/redirect`, {
				headers: { Authorization: 'Bearer secret' },
			}),
			/HTTP request failed/,
		);
		assert.equal(captures, 0);
	} finally {
		await remote.close();
	}
});

test('status polling survives HTTP throttling and exposes the validator while waiting', async () => {
	// A temporary API failure must not abandon a release that the registry is still processing.
	// Real HTTP responses exercise Retry-After, state transitions and the durable final receipt.
	let requests = 0;
	const remote = await server((_request, response) => {
		requests++;
		if (requests === 1) {
			response.writeHead(429, { 'retry-after': '12' });
			response.end();
			return;
		}
		json(response, {
			id: identifier,
			status: requests === 2 ? 'validating' : 'published',
			validator_run: 'https://github.com/owner/registry/actions/runs/42/attempts/1',
		});
	});
	const sample = await fixture();
	const receipt = join(sample.directory, 'publication.json');
	const delays: number[] = [];
	try {
		await waitForPublication(identifier, sample.sha256, receipt, {
			origin: remote.origin,
			sleep: async (delay) => {
				delays.push(delay);
			},
		});
		assert.deepEqual(delays, [12_000, 15_000]);
		const result: unknown = JSON.parse(await readFile(receipt, 'utf8'));
		assert.deepEqual(result, {
			id: identifier,
			sha256: sample.sha256,
			status_url: `${remote.origin}/v1/submissions/${identifier}`,
			status: 'published',
			response: {
				id: identifier,
				status: 'published',
				validator_run: 'https://github.com/owner/registry/actions/runs/42/attempts/1',
			},
		});
	} finally {
		await remote.close();
		await sample.cleanup();
	}
});

test('terminal states, wrong identity, and exhausted deadlines fail with useful receipts', async () => {
	// A green release requires published status for this submission. These server responses cover
	// rejection, mismatched identity and a stuck validator without spending real time on polling.
	const sample = await fixture();
	try {
		for (
			const status of [
				'rejected',
				'failed',
				'validating',
				'wrong-identity',
			]
		) {
			const remote = await server((_request, response) =>
				json(response, {
					id: status === 'wrong-identity' ? 'other' : identifier,
					status,
				})
			);
			try {
				const receipt = join(sample.directory, 'publication.json');
				await assert.rejects(
					waitForPublication(identifier, sample.sha256, receipt, {
						origin: remote.origin,
						timeoutMs: 0,
					}),
					status === 'wrong-identity'
						? /different submission/
						: new RegExp(status),
				);
				assert.ok((await readFile(receipt, 'utf8')).includes(identifier));
			} finally {
				await remote.close();
			}
		}
	} finally {
		await sample.cleanup();
	}
});
