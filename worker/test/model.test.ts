import { expect, test } from 'bun:test';
import { HttpError, sourceDigest, submission, text } from '#model';
import type { Submission } from '#model';

test('Text validation rejects ASCII control characters anywhere in a value', () => {
	for (let code = 0; code < 32; code++) {
		for (const value of [String.fromCharCode(code), `before${String.fromCharCode(code)}after`]) {
			expect(() => text(value)).toThrow(HttpError);
		}
	}
	expect(() => text(`before${String.fromCharCode(127)}after`)).toThrow(HttpError);
});

test('Text validation preserves printable ASCII and Unicode within the length limit', () => {
	for (const value of [' ', '~', 'https://github.com/kjanat/actionlint', 'café', '日本語', '🎨']) {
		expect(text(value, value.length)).toBe(value);
	}
	for (const value of ['', null, 42]) {
		expect(() => text(value)).toThrow(HttpError);
	}
	expect(() => text('abcd', 3)).toThrow(HttpError);
});

test('v2 submissions preserve release asset and digest-pinned OCI source unions', () => {
	const base: Pick<
		Extract<Submission, { schema_version: 2 }>,
		'schema_version' | 'provider' | 'repository' | 'tag' | 'kind'
	> = {
		schema_version: 2,
		provider: 'github',
		repository: 'Acme/Plugin',
		tag: 'v1',
		kind: 'manifest',
	};
	const asset = submission({
		...base,
		artifact: { type: 'release-asset', name: 'manifest.json.gz', sha256: 'a'.repeat(64) },
	});
	expect(asset).toEqual({
		...base,
		repository: 'acme/plugin',
		artifact: { type: 'release-asset', name: 'manifest.json.gz', sha256: 'a'.repeat(64) },
	});
	if (asset.schema_version !== 2) throw new Error('expected v2 submission');
	expect(sourceDigest(asset)).toBe('a'.repeat(64));
	const oci = submission({
		...base,
		kind: 'component',
		artifact: { type: 'oci', reference: `oci://ghcr.io/acme/plugin@sha256:${'b'.repeat(64)}` },
	});
	expect(sourceDigest(oci)).toBe('b'.repeat(64));
	const ociProcess = submission({
		...base,
		artifact: { type: 'oci', reference: `oci://ghcr.io:443/acme/process-plugin@sha256:${'c'.repeat(64)}` },
	});
	expect(ociProcess.kind).toBe('manifest');
	for (
		const invalid of [
			{
				...base,
				asset: 'legacy.wasm',
				sha256: 'a'.repeat(64),
				artifact: { type: 'oci', reference: `oci://ghcr.io/acme/plugin@sha256:${'b'.repeat(64)}` },
			},
			{ ...base, artifact: { type: 'oci', reference: 'oci://ghcr.io/acme/plugin:latest' } },
			{
				...base,
				kind: 'component',
				artifact: { type: 'oci', reference: `oci://ghcr.io:65536/acme/plugin@sha256:${'b'.repeat(64)}` },
			},
			{ ...base, artifact: { type: 'release-asset', name: 'manifest.wasm', sha256: 'a'.repeat(64) } },
		]
	) expect(() => submission(invalid)).toThrow(HttpError);
});
