export type AuthErrorCode =
	| 'oidc_invalid'
	| 'oidc_bearer_missing'
	| 'github_issuer'
	| 'github_visibility'
	| 'github_subject'
	| 'github_repository_id'
	| 'github_owner_id'
	| 'github_repository'
	| 'github_ref'
	| 'github_commit'
	| 'github_workflow'
	| 'github_run_id'
	| 'github_run_attempt'
	| 'validator_repository'
	| 'validator_workflow'
	| 'validator_ref'
	| 'validator_ref_type'
	| 'validator_event';

export class HttpError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly code?: AuthErrorCode,
	) {
		super(message);
	}
}

export function object(value: unknown): Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new HttpError(400, 'The value must be a JSON object.');
	}
	return Object.fromEntries(Object.entries(value));
}

export function text(value: unknown, limit = 512): string {
	if (
		typeof value !== 'string'
		|| value.length === 0
		|| value.length > limit
	) {
		throw new HttpError(400, 'The value must be a nonempty string within the permitted length.');
	}
	for (const character of value) {
		const code = character.charCodeAt(0);
		if (code <= 0x1f || code === 0x7f) {
			throw new HttpError(400, 'The value must not contain ASCII control characters.');
		}
	}
	return value;
}

export function exactKeys(
	value: Record<string, unknown>,
	keys: string[],
): void {
	if (Object.keys(value).some((key) => !keys.includes(key))) {
		throw new HttpError(400, 'The request contains an unsupported field.');
	}
}

export interface ReleaseAssetSource {
	type: 'release-asset';
	name: string;
	sha256: string;
}

export interface OCISource {
	type: 'oci';
	reference: string;
}

export type Submission = {
	schema_version: 1;
	provider: 'github' | 'gitlab';
	repository: string;
	tag: string;
	asset: string;
	sha256: string;
	kind: 'core' | 'component';
} | {
	schema_version: 2;
	provider: 'github' | 'gitlab';
	repository: string;
	tag: string;
	kind: 'core' | 'component' | 'manifest';
	artifact: ReleaseAssetSource | OCISource;
};

export function sourceIdentity(value: Submission): string {
	// Release filenames preserve the durable v1 version key. Changing their
	// encoding would create new submissions and bypass existing digest bindings.
	if (value.schema_version === 1) return value.asset;
	if (value.artifact.type === 'release-asset') {
		return value.artifact.name;
	}
	return JSON.stringify({ type: value.artifact.type, name: value.artifact.reference.split('@sha256:')[0] });
}

export function sourceDigest(value: Submission): string {
	if (value.schema_version === 1) return value.sha256;
	if (value.artifact.type === 'release-asset') return value.artifact.sha256;
	const digest = /@sha256:([a-f0-9]{64})$/u.exec(value.artifact.reference)?.[1];
	if (!digest) throw new Error('Validated OCI source has no digest');
	return digest;
}

function ociReference(value: unknown): string {
	const reference = text(value, 2048);
	const match =
		/^oci:\/\/[a-z0-9]+(?:[.-][a-z0-9]+)*(?::([0-9]{1,5}))?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[a-f0-9]{64}$/u
			.exec(reference);
	const port = match?.[1];
	if (!match || (port !== undefined && (Number(port) < 1 || Number(port) > 65535))) {
		throw new HttpError(400, 'The OCI reference must use a pinned SHA-256 digest.');
	}
	return reference;
}

export function submission(value: unknown): Submission {
	const v = object(value);
	if (v.schema_version === 2) {
		exactKeys(v, ['schema_version', 'provider', 'repository', 'tag', 'kind', 'artifact']);
		if (
			(v.provider !== 'github' && v.provider !== 'gitlab')
			|| (v.kind !== 'core' && v.kind !== 'component' && v.kind !== 'manifest')
		) {
			throw new HttpError(400, 'The submission specifies an unsupported provider or execution kind.');
		}
		const repository = text(v.repository, 512).toLowerCase();
		const parts = repository.split('/');
		if (
			parts.length < 2 || (v.provider === 'github' && parts.length !== 2)
			|| parts.some(p => !/^[a-z0-9][a-z0-9._-]*$/u.test(p) || p.endsWith('.git'))
		) {
			throw new HttpError(400, 'The repository path is invalid for the selected provider.');
		}
		const tag = text(v.tag, 128);
		if (!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(tag)) {
			throw new HttpError(400, 'The release tag is invalid.');
		}
		const artifact = object(v.artifact);
		if (artifact.type === 'release-asset') {
			exactKeys(artifact, ['type', 'name', 'sha256']);
			const name = text(artifact.name, 128);
			const sha256 = text(artifact.sha256, 64);
			const extension = v.kind === 'manifest' ? /\.json(?:\.gz)?$/u : /\.wasm(?:\.gz)?$/u;
			if (
				!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(name) || !extension.test(name)
				|| !/^[a-f0-9]{64}$/u.test(sha256)
			) {
				throw new HttpError(400, 'The release asset name or SHA-256 checksum is invalid.');
			}
			return {
				schema_version: 2,
				provider: v.provider,
				repository,
				tag,
				kind: v.kind,
				artifact: { type: 'release-asset', name, sha256 },
			};
		}
		if (artifact.type === 'oci') {
			exactKeys(artifact, ['type', 'reference']);
			return {
				schema_version: 2,
				provider: v.provider,
				repository,
				tag,
				kind: v.kind,
				artifact: { type: 'oci', reference: ociReference(artifact.reference) },
			};
		}
		throw new HttpError(400, 'The submission artifact source is unsupported.');
	}
	exactKeys(v, [
		'schema_version',
		'provider',
		'repository',
		'tag',
		'asset',
		'sha256',
		'kind',
	]);
	if (
		v.schema_version !== 1
		|| (v.provider !== 'github' && v.provider !== 'gitlab')
		|| (v.kind !== 'core' && v.kind !== 'component')
	) {
		throw new HttpError(
			400,
			'The submission specifies an unsupported schema version, provider, or plugin format.',
		);
	}
	const repository = text(v.repository, 256).toLowerCase();
	const parts = repository.split('/');
	if (
		parts.length < 2
		|| (v.provider === 'github' && parts.length !== 2)
		|| parts.some((p) => !/^[a-z0-9][a-z0-9._-]*$/u.test(p) || p.endsWith('.git'))
	) {
		throw new HttpError(400, 'The repository path is invalid for the selected provider.');
	}
	const tag = text(v.tag, 128);
	const asset = text(v.asset, 128);
	const sha256 = text(v.sha256, 64);
	if (
		!/^[A-Za-z0-9][A-Za-z0-9._+-]*$/u.test(tag)
		|| !/^[A-Za-z0-9][A-Za-z0-9._+-]*\.wasm(?:\.gz)?$/u.test(asset)
		|| !/^[a-f0-9]{64}$/u.test(sha256)
	) {
		throw new HttpError(400, 'The release tag, asset filename, or SHA-256 checksum is invalid.');
	}
	return {
		schema_version: 1,
		provider: v.provider,
		repository,
		tag,
		asset,
		sha256,
		kind: v.kind,
	};
}

export interface Identity {
	issuer: string;
	subject: string;
	repository_id: string;
	owner_id: string;
	repository: string;
	ref: string;
	commit: string;
	workflow: string;
	run_id: string;
}

export interface Receipt {
	schema_version: 1;
	id: string;
	submission: Submission;
	identity: Identity;
	authorized_at: string;
}

export interface Authorization {
	identity: Identity;
	jti: string;
	expires: number;
}

export async function body(request: Request): Promise<unknown> {
	if (
		request.headers.get('content-type')?.split(';')[0]?.trim()
			!== 'application/json'
	) {
		throw new HttpError(415, 'Set the Content-Type header to application/json.');
	}
	if (request.body === null) throw new HttpError(400, 'The request must include a JSON body.');
	const reader = request.body.getReader();
	const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
	let size = 0;
	let result = '';
	try {
		for (;;) {
			const chunk = await reader.read();
			if (chunk.done) break;
			size += chunk.value.byteLength;
			if (size > 16384) {
				await reader.cancel();
				throw new HttpError(413, 'The request body exceeds 16 KiB.');
			}
			result += decoder.decode(chunk.value, { stream: true });
		}
		result += decoder.decode();
		return JSON.parse(result);
	} catch (error) {
		if (error instanceof HttpError) throw error;
		throw new HttpError(400, 'The request body is not valid JSON.');
	} finally {
		reader.releaseLock();
	}
}

export async function digest(value: string): Promise<string> {
	const bytes = await crypto.subtle.digest(
		'SHA-256',
		new TextEncoder().encode(value),
	);
	return Array.from(new Uint8Array(bytes), (n) => n.toString(16).padStart(2, '0')).join('');
}
