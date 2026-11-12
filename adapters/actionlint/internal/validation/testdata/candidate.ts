import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cli, command, flag } from '@kjanat/dreamcli';

const workflow = `name: Registry smoke
on: push
permissions: {}
jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - id: sample
        shell: bash
        run: |
          sudo printf '%s\\n' value
`;

interface Context {
	directory: string;
	run(args: string[], expected?: number): Promise<string>;
}

export async function prepare({ directory }: Pick<Context, 'directory'>): Promise<void> {
	await mkdir(join(directory, '.github'), { recursive: true });
	await writeFile(join(directory, '.github', 'actionlint.yaml'), 'tools:\n  ruff: false\n  shellcheck: false\n');
	await writeFile(join(directory, 'workflow.yml'), workflow);
}

function object(value: unknown): Record<string, unknown> {
	assert.ok(value && typeof value === 'object' && !Array.isArray(value));
	return Object.fromEntries(Object.entries(value));
}

export async function verify({ directory, run }: Context): Promise<{ checks: string[]; probe: string[] }> {
	const probe = ['check', '--json', 'workflow.yml'];
	const result = object(JSON.parse(await run(probe, 1)));
	assert.equal(result.completed, true);
	assert.equal(result.exit_code, 1);
	assert.ok(Array.isArray(result.diagnostics));
	assert.equal(result.diagnostics.length, 1);
	const finding = object(result.diagnostics[0]);
	assert.equal(finding.rule, 'no-sudo');
	assert.deepEqual(finding.start, { line: 11, column: 11 });
	await writeFile(join(directory, 'workflow.yml'), workflow.replace('sudo ', ''));
	try {
		const clean = object(JSON.parse(await run(probe)));
		assert.equal(clean.completed, true);
		assert.equal(clean.exit_code, 0);
		assert.deepEqual(clean.diagnostics, []);
	} finally {
		await writeFile(join(directory, 'workflow.yml'), workflow);
	}
	return { checks: ['mapped no-sudo diagnostic', 'source correction clears diagnostic'], probe };
}

function unsignedLEB(value: number): number[] {
	const bytes: number[] = [];
	do {
		const low = value & 0x7f;
		value >>>= 7;
		bytes.push(low | (value ? 0x80 : 0));
	} while (value);
	return bytes;
}

function hostFixture(): string {
	const module = fileURLToPath(new URL('../../..', import.meta.url));
	const download = object(JSON.parse(execFileSync('go', ['mod', 'download', '-json', 'actionlint.kjanat.dev/v2'], {
		cwd: module,
		encoding: 'utf8',
	})));
	assert.ok(typeof download.Dir === 'string' && download.Dir !== '', 'go mod download returned no module directory');
	return join(download.Dir, 'internal/plugins/execution/component/testdata/plugins/no-sudo.wasm');
}

function withoutDiscovery(module: Buffer): Buffer {
	const name = Buffer.from('actionlint.plugin');
	const sections = [module.subarray(0, 8)];
	let offset = 8;
	while (offset < module.length) {
		const start = offset;
		const id = module[offset++];
		let size = 0;
		let shift = 0;
		let byte: number | undefined;
		do {
			byte = module[offset++];
			assert.ok(byte !== undefined && shift < 35, 'malformed section size');
			size += (byte & 0x7f) * 2 ** shift;
			shift += 7;
		} while (byte & 0x80);
		const end = offset + size;
		assert.ok(end <= module.length, 'truncated section');
		const body = module.subarray(offset, end);
		const discovery = id === 0 && body[0] === name.length && body.subarray(1, 1 + name.length).equals(name);
		if (!discovery) sections.push(module.subarray(start, end));
		offset = end;
	}
	return Buffer.concat(sections);
}

// Replace the upstream component's discovery metadata, just as a plugin package
// build does. Installation, lock creation and caching belong to the actual CLI.
async function packageFixture(output: string): Promise<void> {
	const bytes = withoutDiscovery(await readFile(hostFixture()));
	const metadata = {
		metadata_version: 1,
		transport: 'wasm-component',
		id: 'no-sudo',
		name: 'No sudo',
		description: 'Registry component fixture',
		license: 'MIT',
		repository: 'https://github.com/example/plugin',
		plugin_version: '1.0.0',
		interface: 'kjanat:actionlint/analyzer@0.2.0',
		wit_sha256: '287f569cb6587a23f2195f9d8398f370c32a2b21deed1fac42f3b56fd03c7c23',
		descriptor: {
			name: 'no-sudo',
			description: 'Check runner privilege assumptions',
			category: 'suspicious',
			subcategory: 'scripts',
			maturity: 'stable',
			provider: 'example',
			explanation: 'Self-hosted runners may not provide sudo.',
			help: 'Run without privilege elevation or explicitly prepare the runner.',
			options_schema: {},
			required_inputs: ['scripts', 'invocations'],
		},
	};
	const name = Buffer.from('actionlint.plugin');
	const section = Buffer.concat([Buffer.from(unsignedLEB(name.length)), name, Buffer.from(JSON.stringify(metadata))]);
	await writeFile(output, Buffer.concat([bytes, Buffer.from([0, ...unsignedLEB(section.length)]), section]));
}

if (import.meta.main) {
	await cli('registry-fixture').command(
		command('package')
			.description('Package the upstream no-sudo component for candidate installation')
			.flag('output', flag.string().required().describe('Packaged Wasm destination'))
			.action(async ({ flags }) => {
				await packageFixture(flags.output);
			}),
	).run();
}
