import { cli, command, flag, group } from '@kjanat/dreamcli';
import { checkCandidate, checkPublished } from '@/scripts/check.ts';
import type { CheckOptions } from '@/scripts/check.ts';
import { claim, complete, createClient, recover } from '@/scripts/consume.ts';
import { runFixture } from '@/scripts/fixture.ts';
import { output } from '@/scripts/http.ts';
import {
	publishOCI,
	publishPackage,
	submit as submitRelease,
	verifyPackage,
	waitForPublication,
} from '@/scripts/publish.ts';
import type { Submission } from '@/scripts/publish.ts';
import { authorizeStatus } from '@/scripts/status-admin.ts';

const check = command('check')
	.description(
		'Install and exercise an unpublished candidate without creating a release',
	)
	.flag('registry', flag.string().required().describe('Registry executable'))
	.flag(
		'actionlint',
		flag.string().default('').describe('Supported actionlint executable'),
	)
	.flag(
		'artifact',
		flag.string().default('').describe('Packaged Wasm candidate or process manifest (default: artifacts/plugin.wasm)'),
	)
	.flag('oci', flag.string().default('').describe('OCI reference pinned by @sha256'))
	.flag(
		'oci-layout',
		flag.string().default('').describe('Read the pinned OCI graph from a local ORAS image layout without network'),
	)
	.flag(
		'kind',
		flag.enum(['core', 'component', 'manifest']).describe('Execution kind, inferred from the artifact when omitted'),
	)
	.flag('allow-config-processes', flag.boolean().describe('Consent to execute native process plugins during checks'))
	.flag('checker', flag.string().default('').describe('Compatibility checker that runs before installation'))
	.flag(
		'fixture',
		flag.string().default('').describe('Plugin behavioral fixture module'),
	)
	.flag(
		'store',
		flag
			.string()
			.default('registry/plugins')
			.describe('Existing registry registrations'),
	)
	.flag(
		'report',
		flag.string().default('candidate.json').describe('Candidate check receipt'),
	)
	.example(
		({ name }) =>
			`${name} check --registry ./registry --actionlint ./actionlint --artifact ./plugin.wasm --fixture ./installation.ts`,
		'Install a local Wasm package and verify its behavior',
	)
	.example(
		({ name }) =>
			`${name} check --registry ./registry --actionlint ./actionlint --oci "$PLUGIN_OCI_REFERENCE" --oci-layout ./plugin-layout --fixture ./installation.ts --kind manifest --allow-config-processes`,
		'Test a local ORAS process package before uploading it',
	)
	.action(async ({ flags, out }) => {
		if (flags.oci && flags.artifact) {
			throw new Error('OCI source is mutually exclusive with --artifact');
		}
		if (flags['oci-layout'] && !flags.oci) throw new Error('--oci-layout requires --oci');
		if (!flags.actionlint || !flags.fixture) {
			throw new Error('Candidate checks require --actionlint and --fixture');
		}
		if (flags.kind === 'manifest' && !flags['allow-config-processes']) {
			throw new Error('Process candidate checks require explicit --allow-config-processes consent');
		}
		const options: CheckOptions = {
			actionlint: flags.actionlint,
			fixture: flags.fixture,
			registry: flags.registry,
			artifact: flags.oci || flags.artifact || 'artifacts/plugin.wasm',
			store: flags.store,
			report: flags.report,
			allowConfigProcesses: flags['allow-config-processes'],
			...(flags.checker ? { checker: flags.checker } : {}),
			...(flags.kind === undefined ? {} : { kind: flags.kind }),
			...(flags['oci-layout'] ? { ociLayout: flags['oci-layout'] } : {}),
		};
		const receipt = await checkCandidate(options);
		await output('sha256', receipt.artifact.sha256);
		out.json(receipt);
	});

const verify = command('verify')
	.description(
		'Check package files against SHA256SUMS and the distributed asset digest',
	)
	.flag(
		'directory',
		flag.string().default('artifacts').describe('Package directory'),
	)
	.flag(
		'asset',
		flag.string().default('plugin.wasm').describe('Wasm asset filename'),
	)
	.flag('kind', flag.enum(['core', 'component', 'manifest']).default('component').describe('Execution kind'))
	.flag('sha256', flag.string().required().describe('Expected distributed asset SHA-256'))
	.action(async ({ flags, out }) => {
		const pkg = await verifyPackage(flags.directory, flags.asset, flags.sha256, flags.kind);
		out.json({
			sha256: pkg.sha256,
			files: pkg.files.map(({ name, sha256, size }) => ({
				name,
				sha256,
				size,
			})),
		});
	});

const verifyInstallation = command('verify-installation')
	.description(
		'Verify delivery of the exact candidate through the production registry',
	)
	.flag('tag', flag.string().required().describe('Published release tag'))
	.flag(
		'actionlint',
		flag.string().required().describe('Supported host executable'),
	)
	.flag(
		'fixture',
		flag
			.string()
			.required()
			.describe('Behavioral fixture used by the candidate check'),
	)
	.flag(
		'receipt',
		flag.string().required().describe('Successful candidate check receipt'),
	)
	.flag(
		'report',
		flag
			.string()
			.default('installation.json')
			.describe('Delivery verification receipt'),
	)
	.flag(
		'allow-config-processes',
		flag.boolean().describe('Consent to execute native process plugins during delivery checks'),
	)
	.action(async ({ flags, out }) => {
		out.json(await checkPublished({ ...flags, allowConfigProcesses: flags['allow-config-processes'] }));
	});

const publish = command('publish')
	.description(
		'Publish a verified release asset or submit a pinned OCI source and wait for admission',
	)
	.flag('actionlint', flag.string().default('').describe('Host executable used by the candidate check'))
	.flag('fixture', flag.string().default('').describe('Behavioral fixture used by the candidate check'))
	.flag(
		'directory',
		flag.string().default('artifacts').describe('Package directory'),
	)
	.flag(
		'asset',
		flag.string().default('').describe('Release asset filename'),
	)
	.flag(
		'sha256',
		flag.string().default('').describe('Asset SHA-256'),
	)
	.flag(
		'oci',
		flag.string().default('').describe('OCI reference pinned by @sha256'),
	)
	.flag(
		'repository',
		flag
			.string()
			.env('GITHUB_REPOSITORY')
			.required()
			.describe('Public owner/repository'),
	)
	.flag(
		'tag',
		flag
			.string()
			.env('GITHUB_REF_NAME')
			.required()
			.describe('Existing release tag'),
	)
	.flag(
		'kind',
		flag
			.enum(['core', 'component', 'manifest'])
			.default('component')
			.describe('Plugin format'),
	)
	.flag('allow-config-processes', flag.boolean().describe('Consent to execute native process plugins during checks'))
	.flag(
		'candidate-receipt',
		flag.string().default('').describe('Successful candidate check receipt'),
	)
	.flag(
		'notes-file',
		flag.string().default('').describe('Optional release notes file'),
	)
	.flag(
		'receipt',
		flag
			.string()
			.default('publication.json')
			.describe('Publication progress receipt'),
	)
	.flag(
		'timeout-seconds',
		flag
			.number()
			.default(1800)
			.describe('Publication deadline, including HTTP retries'),
	)
	.action(async ({ flags }) => {
		if (!flags.actionlint || !flags.fixture || !flags['candidate-receipt']) {
			throw new Error('Publication requires --actionlint, --fixture, and --candidate-receipt from a successful check');
		}
		if (flags.oci) {
			if (flags.asset || flags.sha256) {
				throw new Error('OCI source is mutually exclusive with --asset and --sha256');
			}
			await publishOCI({
				actionlint: flags.actionlint,
				fixture: flags.fixture,
				candidateReceipt: flags['candidate-receipt'],
				allowConfigProcesses: flags['allow-config-processes'],
				reference: flags.oci,
				repository: flags.repository,
				tag: flags.tag,
				kind: flags.kind,
				receipt: flags.receipt,
				timeoutSeconds: flags['timeout-seconds'],
			});
			return;
		}
		const asset = flags.asset || (flags.kind === 'manifest' ? '' : 'plugin.wasm');
		if (!asset || !flags.sha256) throw new Error('Supply --asset and --sha256, or supply --oci');
		await publishPackage({
			actionlint: flags.actionlint,
			fixture: flags.fixture,
			directory: flags.directory,
			asset,
			sha256: flags.sha256,
			repository: flags.repository,
			tag: flags.tag,
			kind: flags.kind,
			candidateReceipt: flags['candidate-receipt'],
			allowConfigProcesses: flags['allow-config-processes'],
			notesFile: flags['notes-file'],
			receipt: flags.receipt,
			timeoutSeconds: flags['timeout-seconds'],
		});
	});

const wait = command('wait')
	.description('Resume observation of an existing registry submission')
	.flag('id', flag.string().required().describe('Registry submission UUID'))
	.flag(
		'sha256',
		flag.string().required().describe('Submitted artifact SHA-256'),
	)
	.flag(
		'receipt',
		flag
			.string()
			.default('publication.json')
			.describe('Publication progress receipt'),
	)
	.flag(
		'timeout-seconds',
		flag.number().default(1800).describe('Publication deadline'),
	)
	.action(async ({ flags }) => {
		if (
			!Number.isInteger(flags['timeout-seconds'])
			|| flags['timeout-seconds'] < 1
			|| flags['timeout-seconds'] > 7200
		) {
			throw new Error('Timeout must be between 1 and 7200 seconds');
		}
		await waitForPublication(flags.id, flags.sha256, flags.receipt, {
			timeoutMs: flags['timeout-seconds'] * 1000,
		});
	});

const submit = command('submit')
	.description('Submit an existing immutable release using publisher OIDC')
	.flag(
		'provider',
		flag
			.enum(['github', 'gitlab'])
			.env('PLUGIN_PROVIDER')
			.default('github')
			.describe('Release provider'),
	)
	.flag(
		'repository',
		flag
			.string()
			.env('PLUGIN_REPOSITORY')
			.required()
			.describe('Publisher repository path'),
	)
	.flag(
		'tag',
		flag
			.string()
			.env('PLUGIN_TAG')
			.required()
			.describe('Immutable release tag'),
	)
	.flag(
		'asset',
		flag.string().env('PLUGIN_ASSET').default('').describe('Release asset name'),
	)
	.flag(
		'sha256',
		flag.string().env('PLUGIN_SHA256').default('').describe('Release asset SHA-256'),
	)
	.flag(
		'oci',
		flag.string().env('PLUGIN_OCI').default('').describe('OCI reference pinned by @sha256'),
	)
	.flag(
		'kind',
		flag
			.enum(['core', 'component', 'manifest'])
			.env('PLUGIN_KIND')
			.required()
			.describe('Plugin format'),
	)
	.action(async ({ flags }) => {
		const source: Extract<Submission, { schema_version: 2 }>['artifact'] | null = flags.oci
			? { type: 'oci', reference: flags.oci }
			: flags.asset && flags.sha256
			? { type: 'release-asset', name: flags.asset, sha256: flags.sha256 }
			: null;
		if (source === null || (flags.oci && (flags.asset || flags.sha256))) {
			throw new Error('Supply either --oci or both --asset and --sha256');
		}
		await submitRelease(
			{
				schema_version: 2,
				repository: flags.repository,
				tag: flags.tag,
				kind: flags.kind,
				artifact: source,
			},
			process.env,
			undefined,
			flags.provider,
		);
	});

const consume = group('consume')
	.description('Claim and complete registry validation work')
	.command(
		command('claim')
			.description('Claim pending work for this validator run')
			.flag(
				'directory',
				flag
					.string()
					.default('.registry')
					.describe('Receipt and lease directory'),
			)
			.action(async ({ flags }) => {
				await claim(flags.directory, createClient());
			}),
	)
	.command(
		command('complete')
			.description('Record successful publication or deterministic rejection')
			.flag('lease', flag.string().required().describe('Claim lease file'))
			.flag(
				'status',
				flag
					.enum(['published', 'rejected'])
					.required()
					.describe('Terminal result'),
			)
			.action(async ({ flags }) => {
				await complete(flags.lease, flags.status, createClient());
			}),
	)
	.command(
		command('recover')
			.description('Reject deterministic failures or schedule validation again')
			.flag('lease', flag.string().required().describe('Claim lease file'))
			.flag(
				'report',
				flag
					.array(flag.string())
					.default([])
					.describe('Admission or merge report; repeat for each report'),
			)
			.action(async ({ flags }) => {
				await recover(flags.lease, flags.report, createClient());
			}),
	);

const fixture = command('fixture')
	.description('Run a plugin fixture against an installed candidate')
	.flag('fixture', flag.string().required().describe('Fixture module'))
	.flag('actionlint', flag.string().required().describe('Host executable'))
	.flag(
		'directory',
		flag.string().required().describe('Fresh project directory'),
	)
	.flag(
		'phase',
		flag
			.enum(['prepare', 'verify'])
			.required()
			.describe('Prepare the project or verify installed behavior'),
	)
	.flag(
		'allow-config-processes',
		flag.boolean().describe('Consent to execute native process plugins during fixture checks'),
	)
	.action(async ({ flags }) => {
		await runFixture(
			flags.fixture,
			flags.actionlint,
			flags.directory,
			flags.phase,
			flags['allow-config-processes'],
		);
	});

export const registryCLI = cli('actionlint-registry')
	.description('Check candidates and publish actionlint plugins')
	.command(check)
	.command(verify)
	.command(verifyInstallation)
	.command(publish)
	.command(wait)
	.command(submit)
	.command(consume)
	.command(fixture)
	.command(
		command('status-actor')
			.description(
				'Authorize and record the dispatcher for a registry status change',
			)
			.flag(
				'output',
				flag.string().required().describe('Trusted actor JSON destination'),
			)
			.action(async ({ flags }) => {
				await authorizeStatus(flags.output);
			}),
	);

if (import.meta.main) await registryCLI.run();
