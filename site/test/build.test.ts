import { expect, test } from 'bun:test';
import { chmod, mkdir, readdir, readFile, stat, symlink, unlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { buildSite } from '#build.tsx';
import { createExport, fixture } from '#test/fixtures.ts';

test('100-plugin build emits 20-row static pages for every sort and preserves registry JSON', async () => {
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

test('empty export builds useful static fallback pages', async () => {
	const directory = await createExport([]);
	expect(await buildSite(directory, directory)).toBe(0);
	const home = await readFile(join(directory, 'index.html'), 'utf8');
	expect(home).toContain('No plugins published yet.');
	expect(home).toContain('Publish your first plugin');
	expect(home).not.toContain('class="plugin-card"');
});

test('separate output keeps publication records reachable and byte-for-byte intact', async () => {
	const directory = await createExport([fixture('Plugin')]);
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
});

test('removing a plugin requires a fresh snapshot and keeps the previous site intact', async () => {
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

test('an in-place collision preserves existing files and removes newly staged paths', async () => {
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

test('only regular files owned by the export can be published', async () => {
	const source = await createExport([fixture('Plugin')]);
	const paths = (await readdir(source, { recursive: true })).filter(path => path.endsWith('.json')).map(path => path.replaceAll('\\', '/'));
	const marker = join(source, '.registry-export-files.json');
	await writeFile(marker, JSON.stringify(paths));
	await writeFile(join(source, 'notes.json'), '{}');
	await expect(buildSite(source, source)).rejects.toThrow('Unmanaged entry');
	const output = join(source, 'website');
	await buildSite(source, output);
	expect(await Bun.file(join(output, 'notes.json')).exists()).toBe(false);
	expect(await Bun.file(join(output, 'index.json')).exists()).toBe(true);

	const empty = await createExport([]);
	await writeFile(marker, JSON.stringify([...paths, '../index.json']));
	await expect(buildSite(source, join(empty, 'website'))).rejects.toThrow();
	await unlink(join(source, 'downloads.json'));
	await symlink(join(source, 'notes.json'), join(source, 'downloads.json'));
	await writeFile(marker, JSON.stringify(paths));
	await expect(buildSite(source, join(empty, 'website'))).rejects.toThrow('missing or non-regular files');
});
