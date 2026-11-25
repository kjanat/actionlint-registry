import { expect, test } from 'bun:test';
import { chmod, mkdir, readdir, readFile, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { buildSite } from '#build.tsx';
import { createExport, fixture } from '#test/fixtures.ts';

test('each sort lists 20 of the 100 plugins per page', async () => {
	const directory = await createExport(
		Array.from(
			{ length: 100 },
			(_, index) => fixture(`Plugin ${String(index + 1).padStart(3, '0')}`, index === 99 ? null : index),
		),
	);
	const before = await readFile(join(directory, 'index.json'), 'utf8');
	expect(await buildSite(directory, directory)).toBe(100);
	const home = await readFile(join(directory, 'index.html'), 'utf8');
	expect(home.match(/class="plugin-card"/g)).toHaveLength(20);
	expect(home).toContain('Plugin 099');
	expect(home).not.toContain('Plugin 001');
	expect(home).not.toContain('Plugin 100');
	for (const path of ['page/5/index.html', 'sort/name/page/5/index.html', 'sort/updated/page/5/index.html']) {
		const page = await readFile(join(directory, path), 'utf8');
		expect(page.match(/class="plugin-card"/g)).toHaveLength(20);
		expect(page).toContain('rel="prev"');
	}
	expect(await readFile(join(directory, 'index.json'), 'utf8')).toBe(before);
	expect((await stat(join(directory, 'assets/client.js'))).size).toBeGreaterThan(0);
	expect((await stat(join(directory, 'assets/search-index.json'))).size).toBeGreaterThan(0);
	const named = await readFile(join(directory, 'sort/name/index.html'), 'utf8');
	expect(named).toContain('href="../../assets/site.css"');
	expect(named).toContain('href="../../plugins/');
});

test('an empty catalogue links to publishing instructions', async () => {
	const directory = await createExport([]);
	expect(await buildSite(directory, directory)).toBe(0);
	const home = await readFile(join(directory, 'index.html'), 'utf8');
	expect(home).toContain('No plugins published yet.');
	expect(home).toContain('Publish your first plugin');
	expect(home).not.toContain('class="plugin-card"');
});

test('a separate output lists the legacy records it copies', async () => {
	const directory = await createExport([fixture('Plugin')]);
	await unlink(join(directory, 'downloads.json'));
	const output = join(directory, 'website');
	await mkdir(output);
	await chmod(output, 0o755);
	await buildSite(directory, output);
	expect((await stat(output)).mode & 0o777).toBe(0o755);
	const record = `plugins/${'1'.padStart(64, '0')}/versions/${'1'.padStart(64, '0')}.json`;
	expect(await readFile(join(output, 'index.json'), 'utf8')).toBe(
		await readFile(join(directory, 'index.json'), 'utf8'),
	);
	expect(await readFile(join(output, record), 'utf8')).toBe(await readFile(join(directory, record), 'utf8'));
	expect(await Bun.file(join(output, '.registry-export-files.json')).json()).toEqual([
		'index.json',
		`plugins/${'1'.padStart(64, '0')}/index.json`,
		record,
		'statuses.json',
	]);
});

test('a rebuild refuses a nonempty output after a plugin is removed', async () => {
	const source = await createExport([fixture('Removed')]);
	const destination = join(source, 'website');
	await buildSite(source, destination);
	const empty = await createExport([]);
	await writeFile(join(source, 'index.json'), await readFile(join(empty, 'index.json')));
	await expect(buildSite(source, destination)).rejects.toThrow('empty directory');
	expect(await readFile(join(destination, 'index.html'), 'utf8')).toContain('Removed');
	await expect(buildSite(destination, destination)).rejects.toThrow('regenerate the registry export');
	const rebuilt = join(empty, 'website');
	expect(await buildSite(empty, rebuilt)).toBe(0);
	expect(await Bun.file(join(rebuilt, 'index.html')).text()).not.toContain('Removed');
	expect(await Bun.file(join(rebuilt, 'plugins', '1'.padStart(64, '0'), 'index.html')).exists()).toBe(false);
});

test('interactive pages load their client even without download observations', async () => {
	const directory = await createExport([fixture('Plugin')]);
	await unlink(join(directory, 'downloads.json'));
	await buildSite(directory, directory);
	for (const path of ['index.html', `plugins/${'1'.padStart(64, '0')}/index.html`]) {
		expect(await Bun.file(join(directory, path)).text()).toContain('assets/client.js');
	}
	expect(await Bun.file(join(directory, '404.html')).text()).not.toContain('assets/client.js');
});

test('an existing file stops the in-place build and rolls back its new files', async () => {
	const directory = await createExport([fixture('Plugin')]);
	const sort = join(directory, 'sort');
	await mkdir(sort);
	const conflict = join(sort, 'updated');
	await writeFile(conflict, 'user file');
	const before = (await readdir(directory, { recursive: true })).sort();
	await expect(buildSite(directory, directory)).rejects.toThrow();
	expect((await readdir(directory, { recursive: true })).sort()).toEqual(before);
	expect(await readFile(conflict, 'utf8')).toBe('user file');
});

test('the builder copies only regular files listed in the export manifest', async () => {
	const source = await createExport([fixture('Plugin')]);
	const paths = (await readdir(source, { recursive: true }))
		.filter(path => path.endsWith('.json')).map(path => path.replaceAll('\\', '/'));
	const marker = join(source, '.registry-export-files.json');
	await writeFile(marker, JSON.stringify(paths));
	await writeFile(join(source, 'notes.json'), '{}');
	await expect(buildSite(source, source)).rejects.toThrow('Unmanaged entry');
	const output = join(source, 'website');
	await buildSite(source, output);
	expect(await Bun.file(join(output, 'notes.json')).exists()).toBe(false);
	expect(await Bun.file(join(output, 'index.json')).exists()).toBe(true);
	expect(await Bun.file(join(output, '.registry-export-files.json')).json()).toEqual(paths.toSorted());

	const empty = await createExport([]);
	await writeFile(marker, JSON.stringify([...paths, '../index.json']));
	await expect(buildSite(source, join(empty, 'website'))).rejects.toThrow();
	await unlink(join(source, 'downloads.json'));
	await symlink(join(source, 'notes.json'), join(source, 'downloads.json'));
	await writeFile(marker, JSON.stringify(paths));
	await expect(buildSite(source, join(empty, 'website'))).rejects.toThrow('missing or non-regular files');
	await unlink(join(source, 'downloads.json'));
	await writeFile(join(source, 'downloads.json'), '{}');
	await symlink(empty, join(source, 'schemas'), 'dir');
	await writeFile(marker, JSON.stringify([...paths, 'schemas/index.json']));
	await expect(buildSite(source, join(empty, 'website'))).rejects.toThrow('missing or non-regular files');
});

test('an in-place build lists legacy export files and leaves private JSON out', async () => {
	const directory = await createExport([fixture('Plugin')]);
	await unlink(join(directory, 'downloads.json'));
	const schemas = join(directory, 'schemas');
	await mkdir(schemas);
	await writeFile(join(schemas, 'notes.json'), '{}');
	const root = `plugins/${'1'.padStart(64, '0')}`;
	await buildSite(directory, directory);
	expect(await Bun.file(join(directory, '.registry-export-files.json')).json()).toEqual([
		'index.json',
		`${root}/index.json`,
		`${root}/versions/${'1'.padStart(64, '0')}.json`,
		'statuses.json',
	]);
	expect(await readFile(join(schemas, 'notes.json'), 'utf8')).toBe('{}');
});

test('an in-place build leaves an existing export manifest byte-for-byte unchanged', async () => {
	const directory = await createExport([]);
	const marker = join(directory, '.registry-export-files.json');
	const original = JSON.stringify(['statuses.json', 'downloads.json', 'index.json'], null, 2) + '\n';
	await writeFile(marker, original);
	await buildSite(directory, directory);
	expect(await readFile(marker, 'utf8')).toBe(original);
});

test('each release links its host reports or shows Unverified', async () => {
	const sha256 = 'a'.repeat(64);
	const compatibility = (['passed', 'failed', 'unsupported'] as const).map((outcome, i) => ({
		host: { name: 'actionlint', revision: `v${i + 1}` },
		policy: 'component-v3',
		outcome,
		report: `../../compatibility/${sha256}/${String(i).repeat(64)}.json`,
	}));
	const directory = await createExport([{
		name: 'Plugin',
		versions: [
			{ version: 'v2', publishedAt: '2026-03-02T00:00:00Z', count: 0, sha256, compatibility },
			{ version: 'v1', publishedAt: '2026-03-01T00:00:00Z', count: 0 },
		],
	}]);
	const plugin = `plugins/${'1'.padStart(64, '0')}`;
	for (const { report, ...check } of compatibility) {
		const file = resolve(directory, plugin, report);
		await mkdir(dirname(file), { recursive: true });
		await writeFile(file, JSON.stringify({
			observed_at: '2026-03-03T00:00:00Z',
			checker_sha256: 'b'.repeat(64),
			report: {
				schema_version: 1,
				artifact_sha256: sha256,
				checks: ['instantiate'],
				...check,
				...(check.outcome === 'passed' ? {} : { detail: 'Host could not instantiate this component' }),
			},
		}));
	}
	const output = join(directory, 'website');
	await buildSite(directory, output);
	const html = await readFile(join(output, plugin, 'index.html'), 'utf8');
	const [v2, v1] = html.split('<li class="release"').slice(1);
	expect(v1).toContain('<dt>Host compatibility</dt><dd>Unverified</dd>');
	expect(v2).not.toContain('Unverified');
	for (const check of compatibility) {
		const label = `${check.host.name}@${check.host.revision} · ${check.outcome}`;
		expect(v2).toContain(`href="${check.report}">${label}</a> (${check.policy})`);
		expect(await Bun.file(resolve(output, plugin, check.report)).json()).toHaveProperty('checker_sha256', 'b'.repeat(64));
	}
});
