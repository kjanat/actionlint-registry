/** @jsxImportSource preact */
import { constants } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readdir, readFile, rename, rm, rmdir, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { render } from 'preact-render-to-string';
import { Schema } from 'effect';
import { loadCatalogue } from '#catalogue.ts';
import { Home, NotFound, PluginPage } from '#components.tsx';
import { pageSize, staticPath } from '#directory.ts';
import type { Sort } from '#directory.ts';
import type { SiteData } from '#schema.ts';

const siteManifest = '.registry-site-files.json';
const exportManifest = '.registry-export-files.json';
const publicJSON = /^(?:(?:index|statuses|downloads)\.json|(?:plugins|compatibility|schemas)\/(?:[a-z0-9_-][a-z0-9._-]*\/)*[a-z0-9_-][a-z0-9._-]*\.json)$/i;
const decodeManifest = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Array(Schema.String.check(Schema.isPattern(publicJSON)))));

export async function buildSite(input: string, output: string): Promise<number> {
	const source = resolve(input);
	const destination = resolve(output);
	const inPlace = source === destination;
	const entries = await readdir(source);
	if (entries.includes(siteManifest) || entries.includes('index.html')) {
		throw new Error('Site input already contains a rendered site; regenerate the registry export before building');
	}
	await mkdir(destination, { recursive: true });
	if (!inPlace && (await readdir(destination)).length > 0) {
		throw new Error('Site output must be an empty directory');
	}

	const exportPaths = await publicExportFiles(source, entries.includes(exportManifest), inPlace);
	const staging = await mkdtemp(join(dirname(destination), '.registry-site-'));
	try {
		if (!inPlace) {
			for (const path of exportPaths) {
				const target = join(staging, path);
				await mkdir(dirname(target), { recursive: true });
				await copyFile(join(source, path), target);
			}
		}
		const data = await loadCatalogue(inPlace ? source : staging);
		const linked = new Set(data.plugins.flatMap(plugin => [
			plugin.path.replace(/index\.html$/, 'index.json'),
			...plugin.releases.map(release => release.record),
		]));
		for (const path of exportPaths) {
			if (path.startsWith('plugins/') && !linked.has(path)) {
				throw new Error(`Unreferenced publication file in the export: ${path}`);
			}
		}
		const files = await renderSite(data, staging);
		await writeFile(join(staging, siteManifest), JSON.stringify(files));
		if (inPlace) {
			await addSiteFiles(staging, destination, [...files, siteManifest]);
		} else {
			const mode = (await lstat(destination)).mode & 0o777;
			await chmod(staging, mode);
			// Windows requires an absent target. rmdir also refuses a destination populated during the build.
			await rmdir(destination);
			try {
				await rename(staging, destination);
			} catch (error) {
				await mkdir(destination, { recursive: true, mode });
				throw error;
			}
		}
		return data.plugins.length;
	} finally {
		await rm(staging, { recursive: true, force: true });
	}
}

// Adding to an export must never replace an existing path, including one created by a concurrent build.
async function addSiteFiles(staging: string, destination: string, files: string[]) {
	const directories = new Set([destination]);
	const created: string[] = [];
	const added: string[] = [];
	async function ensureDirectory(path: string): Promise<void> {
		if (directories.has(path)) return;
		await ensureDirectory(dirname(path));
		try {
			await mkdir(path);
			created.push(path);
		} catch (error) {
			if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
			if (!(await lstat(path)).isDirectory()) throw error;
		}
		directories.add(path);
	}

	try {
		for (const file of files) {
			const target = join(destination, file);
			await ensureDirectory(dirname(target));
			await copyFile(join(staging, file), target, constants.COPYFILE_EXCL);
			added.push(target);
		}
	} catch (error) {
		await Promise.all(added.map(file => unlink(file)));
		for (const path of created.reverse()) await rmdir(path);
		throw error;
	}
}

async function publicExportFiles(source: string, marked: boolean, inPlace: boolean): Promise<Set<string>> {
	let owned: Set<string> | undefined;
	const directories = new Set<string>();
	if (marked) {
		const marker = join(source, exportManifest);
		if (!(await lstat(marker)).isFile()) throw new Error(`Invalid export manifest: ${marker}`);
		owned = new Set(decodeManifest(await readFile(marker, 'utf8')));
		for (const file of owned) {
			for (let dir = posix.dirname(file); dir !== '.'; dir = posix.dirname(dir)) directories.add(dir);
		}
	}

	const files = new Set<string>();
	for (const entry of await readdir(source, { recursive: true, withFileTypes: true })) {
		const path = relative(source, join(entry.parentPath, entry.name)).split(sep).join('/');
		if (path === exportManifest) continue;
		if (entry.isFile() && (owned?.has(path) ?? publicJSON.test(path))) files.add(path);
		else if (owned && inPlace && !(entry.isDirectory() && directories.has(path))) {
			throw new Error(`Unmanaged entry in site input: ${path}`);
		}
	}
	if (owned && files.size !== owned.size) throw new Error('Export manifest lists missing or non-regular files');
	return files;
}

async function renderSite(data: SiteData, output: string): Promise<string[]> {
	const source = fileURLToPath(new URL('.', import.meta.url));
	const assets = join(output, 'assets');
	await mkdir(assets, { recursive: true });
	const bundled = await Bun.build({
		entrypoints: [join(source, 'client.tsx')],
		outdir: assets,
		naming: 'client.js',
		target: 'browser',
		minify: true,
		jsx: { runtime: 'automatic', importSource: 'preact' },
	});
	if (!bundled.success) throw new AggregateError(bundled.logs, 'Client bundle failed');
	await writeFile(join(assets, 'site.css'), await Bun.file(join(source, 'site.css')).text());
	const summaries = data.plugins.map(({ name, description, repository, path, version, updatedAt, downloads }) => ({
		name,
		description,
		repository,
		path,
		version,
		updatedAt,
		downloads,
	}));
	await writeFile(join(assets, 'search-index.json'), JSON.stringify(summaries));
	const files = ['assets/client.js', 'assets/site.css', 'assets/search-index.json'];
	async function page(path: string, html: string) {
		const target = join(output, path);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(target, `<!doctype html>\n${html}\n`);
		files.push(path);
	}
	const pages = Math.max(1, Math.ceil(data.plugins.length / pageSize));
	const sorts: Sort[] = ['downloads', 'name', 'updated'];
	for (const sort of sorts) {
		for (let number = 1; number <= pages; number++) {
			const path = staticPath(sort, number);
			const root = relative(dirname(path), '.').replaceAll('\\', '/');
			await page(
				path,
				render(<Home root={root ? `${root}/` : ''} data={data} state={{ query: '', sort, page: number }} />),
			);
		}
	}
	for (const plugin of data.plugins) {
		await page(plugin.path, render(<PluginPage plugin={plugin} observedAt={data.observedAt} />));
	}
	await page('404.html', render(<NotFound />));
	return files;
}
