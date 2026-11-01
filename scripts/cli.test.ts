import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { executeResult } from '@/scripts/process.ts';

const root = fileURLToPath(new URL('../', import.meta.url));

for (const name of ['claim', 'complete', 'recover']) {
	test(`consume ${name} help includes the runnable command path`, async () => {
		const { stdout, stderr } = await executeResult(
			process.execPath,
			['scripts/cli.ts', 'consume', name, '--help'],
			root,
			{ ...process.env, NO_COLOR: '1' },
		);
		assert.equal(stdout.split('\n')[0]?.trim(), `Usage: actionlint-registry consume ${name} [flags]`);
		assert.equal(stderr, '');
	});
}

test('candidate CLI rejects conflicting file and OCI sources before starting a host', async () => {
	const { stdout, stderr } = await executeResult(
		process.execPath,
		[
			'scripts/cli.ts',
			'check',
			'--registry',
			'unused',
			'--artifact',
			'plugin.wasm',
			'--oci',
			`oci://ghcr.io/owner/plugin@sha256:${'a'.repeat(64)}`,
		],
		root,
		{ ...process.env, NO_COLOR: '1' },
		1,
	);
	assert.equal(stdout, '');
	assert.match(stderr, /OCI source is mutually exclusive with --artifact/);
});

test('OCI publish CLI requires the tested host, fixture and receipt', async () => {
	const { stdout, stderr } = await executeResult(
		process.execPath,
		[
			'scripts/cli.ts',
			'publish',
			'--repository',
			'owner/plugin',
			'--tag',
			'v1.0.0',
			'--oci',
			`oci://ghcr.io/owner/plugin@sha256:${'a'.repeat(64)}`,
		],
		root,
		{ ...process.env, NO_COLOR: '1' },
		1,
	);
	assert.equal(stdout, '');
	assert.match(stderr, /Publication requires --actionlint, --fixture, and --candidate-receipt/);
});

test('local OCI layout checks require the intended pinned OCI source', async () => {
	const { stdout, stderr } = await executeResult(
		process.execPath,
		[
			'scripts/cli.ts',
			'check',
			'--registry',
			'unused',
			'--oci-layout',
			'layout',
		],
		root,
		{ ...process.env, NO_COLOR: '1' },
		1,
	);
	assert.equal(stdout, '');
	assert.match(stderr, /--oci-layout requires --oci/);
});
