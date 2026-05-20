<script lang="ts">
	import { getContext, onMount } from 'svelte';
	import type { Writable } from 'svelte/store';
	import type { i18n as i18nType } from 'i18next';
	import qrcode from 'qrcode-generator';
	import { toast } from 'svelte-sonner';

	import {
		disableTOTP,
		enableTOTP,
		getSessionUser,
		getTOTPStatus,
		regenerateTOTPBackupCodes,
		setupTOTP
	} from '$lib/apis/auths';
	import SensitiveInput from '$lib/components/common/SensitiveInput.svelte';
	import { copyToClipboard } from '$lib/utils';
	import { socket, user } from '$lib/stores';

	const i18n: Writable<i18nType> = getContext('i18n');

	type TOTPStatus = {
		enabled: boolean;
		created_at?: number | null;
		last_used_at?: number | null;
		backup_codes_remaining: number;
		backup_codes?: string[];
		token?: string;
		token_type?: string;
		expires_at?: number | null;
	};

	type TOTPSetup = {
		secret: string;
		otpauth_url: string;
	};

	let loaded = false;
	let status: TOTPStatus | null = null;
	let setup: TOTPSetup | null = null;
	let setupPassword = '';
	let enablePassword = '';
	let setupCode = '';
	let setupQRCode = '';
	let backupCodes: string[] = [];
	let backupCodesAcknowledged = false;
	let setupPending = false;
	let actionPending = false;

	let action: 'disable' | 'regenerate' | '' = '';
	let actionCode = '';
	let actionBackupCode = '';
	let useBackupCode = false;

	const createQRCodeDataURL = (value: string) => {
		const qr = qrcode(0, 'M');
		qr.addData(value);
		qr.make();
		return qr.createDataURL(8, 2);
	};

	$: setupQRCode = setup ? createQRCodeDataURL(setup.otpauth_url) : '';

	const loadStatus = async () => {
		status = await getTOTPStatus(localStorage.token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		loaded = true;
	};

	const refreshSessionAfterTokenChange = async (token?: string) => {
		if (!token) {
			return;
		}

		localStorage.token = token;
		const sessionUser = await getSessionUser(token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (sessionUser) {
			$socket?.emit('user-join', { auth: { token } });
			await user.set(sessionUser);
		}
	};

	const startSetupHandler = async () => {
		if (setupPending) {
			return;
		}

		setupPending = true;
		setup = await setupTOTP(localStorage.token, setupPassword).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		setupPassword = '';
		setupCode = '';
		setupPending = false;
	};

	const enableHandler = async () => {
		if (setupPending) {
			return;
		}

		setupPending = true;
		const res = await enableTOTP(localStorage.token, setupCode, enablePassword).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		enablePassword = '';

		if (res) {
			if (res.token) {
				await refreshSessionAfterTokenChange(res.token);
			}
			status = res;
			setup = null;
			setupCode = '';
			setupQRCode = '';
			backupCodes = res.backup_codes ?? [];
			backupCodesAcknowledged = false;
			toast.success($i18n.t('Two-factor authentication enabled.'));
		}
		setupPending = false;
	};

	const resetAction = () => {
		action = '';
		actionCode = '';
		actionBackupCode = '';
		useBackupCode = false;
	};

	const disableHandler = async () => {
		if (actionPending) {
			return;
		}
		actionPending = true;
		const res = await disableTOTP(
			localStorage.token,
			useBackupCode ? null : actionCode,
			useBackupCode ? actionBackupCode : null
		).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (res) {
			if (res.token) {
				await refreshSessionAfterTokenChange(res.token);
			}
			status = res;
			backupCodes = [];
			resetAction();
			toast.success($i18n.t('Two-factor authentication disabled.'));
		}
		actionPending = false;
	};

	const regenerateBackupCodesHandler = async () => {
		if (actionPending) {
			return;
		}
		actionPending = true;
		const res = await regenerateTOTPBackupCodes(
			localStorage.token,
			useBackupCode ? null : actionCode,
			useBackupCode ? actionBackupCode : null
		).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		if (res) {
			if (res.token) {
				await refreshSessionAfterTokenChange(res.token);
			}
			status = res;
			backupCodes = res.backup_codes ?? [];
			backupCodesAcknowledged = false;
			resetAction();
			toast.success($i18n.t('Backup codes regenerated.'));
		}
		actionPending = false;
	};

	const submitActionHandler = async () => {
		if (action === 'disable') {
			await disableHandler();
		} else if (action === 'regenerate') {
			await regenerateBackupCodesHandler();
		}
	};

	const copyBackupCodesHandler = async () => {
		const copied = await copyToClipboard(backupCodes.join('\n'));
		if (copied) {
			backupCodesAcknowledged = true;
			toast.success($i18n.t('Copied to clipboard'));
		} else {
			toast.error($i18n.t('Failed to copy to clipboard.'));
		}
	};

	const downloadBackupCodesHandler = () => {
		const blob = new Blob([backupCodes.join('\n')], { type: 'text/plain;charset=utf-8' });
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download = 'open-webui-backup-codes.txt';
		document.body.appendChild(link);
		link.click();
		link.remove();
		window.setTimeout(() => URL.revokeObjectURL(url), 0);
		backupCodesAcknowledged = true;
	};

	onMount(async () => {
		await loadStatus();
	});
</script>

{#if loaded && status}
	<div class="mt-2">
		<div class="flex justify-between items-center text-sm">
			<div class="font-medium">{$i18n.t('Two-factor authentication')}</div>

			{#if status.enabled}
				<div class="text-xs text-emerald-600 dark:text-emerald-400">{$i18n.t('Enabled')}</div>
			{:else if !setup}
				<div class="text-xs text-gray-500">{$i18n.t('Disabled')}</div>
			{/if}
		</div>

		{#if setup}
			<div class="mt-3 space-y-2">
				{#if setupQRCode}
					<div class="flex justify-center">
						<img
							class="h-44 w-44 rounded-lg border border-gray-100 bg-white p-2 dark:border-gray-800"
							src={setupQRCode}
							alt={$i18n.t('Two-factor authentication QR code')}
						/>
					</div>
				{/if}

				<div class="flex justify-center">
					<a class="text-xs underline" href={setup.otpauth_url}
						>{$i18n.t('Open authenticator app')}</a
					>
				</div>

				<div>
					<div class="mb-1 text-xs font-medium">{$i18n.t('Setup key')}</div>
					<div class="flex">
						<input
							class="w-full text-sm dark:text-gray-300 bg-transparent outline-hidden"
							type="text"
							value={setup.secret}
							readonly
							aria-label={$i18n.t('Setup key')}
						/>
						<button
							class="ml-1.5 px-1.5 py-1 dark:hover:bg-gray-850 transition rounded-lg text-xs"
							type="button"
							on:click={async () => {
								if (!setup) {
									return;
								}
								const copied = await copyToClipboard(setup.secret);
								if (copied) {
									toast.success($i18n.t('Copied to clipboard'));
								} else {
									toast.error($i18n.t('Failed to copy to clipboard.'));
								}
							}}
						>
							{$i18n.t('Copy')}
						</button>
					</div>
				</div>

				<div>
					<label for="totp-setup-code" class="mb-1 text-xs font-medium block"
						>{$i18n.t('Authenticator code')}</label
					>
					<input
						id="totp-setup-code"
						class="w-full text-sm dark:text-gray-300 bg-transparent outline-hidden"
						type="text"
						inputmode="numeric"
						autocomplete="one-time-code"
						bind:value={setupCode}
						placeholder={$i18n.t('Enter 6-digit code')}
					/>
				</div>

				<div>
					<label for="totp-enable-password" class="mb-1 text-xs font-medium block"
						>{$i18n.t('Current password')}</label
					>
					<SensitiveInput
						id="totp-enable-password"
						type="password"
						placeholder={$i18n.t('Current password or recent SSO sign-in')}
						bind:value={enablePassword}
						autocomplete="current-password"
						required={false}
					/>
				</div>

				<div class="flex justify-end gap-2">
					<button
						class="px-3 py-1.5 text-xs font-medium rounded-full bg-gray-100/70 hover:bg-gray-100 dark:bg-gray-850 dark:hover:bg-gray-800 transition"
						type="button"
						on:click={() => {
							setup = null;
							setupCode = '';
							setupQRCode = '';
							enablePassword = '';
						}}
					>
						{$i18n.t('Cancel')}
					</button>

					<button
						class="px-3 py-1.5 text-xs font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full"
						type="button"
						disabled={setupPending}
						class:opacity-50={setupPending}
						on:click={enableHandler}
					>
						{$i18n.t('Verify')}
					</button>
				</div>
			</div>
		{:else if !status.enabled}
			<div class="mt-3 space-y-2">
				<div>
					<label for="totp-setup-password" class="mb-1 text-xs font-medium block"
						>{$i18n.t('Current password')}</label
					>
					<SensitiveInput
						id="totp-setup-password"
						type="password"
						placeholder={$i18n.t('Current password or recent SSO sign-in')}
						bind:value={setupPassword}
						autocomplete="current-password"
						required={false}
					/>
				</div>

				<div class="flex justify-end">
					<button
						class="px-3 py-1.5 text-xs font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full"
						type="button"
						disabled={setupPending}
						class:opacity-50={setupPending}
						on:click={startSetupHandler}
					>
						{$i18n.t('Enable')}
					</button>
				</div>
			</div>
		{:else if backupCodes.length > 0}
			<div class="mt-3 space-y-2">
				<div class="text-xs font-medium">{$i18n.t('Backup codes')}</div>
				<div class="text-xs text-yellow-700 dark:text-yellow-300">
					{$i18n.t('Save these now. They will not be shown again.')}
				</div>
				<div class="grid grid-cols-2 gap-1 text-xs font-mono">
					{#each backupCodes as code}
						<div class="py-1">{code}</div>
					{/each}
				</div>

				<label class="flex gap-2 text-xs text-gray-600 dark:text-gray-300">
					<input class="mt-0.5" type="checkbox" bind:checked={backupCodesAcknowledged} />
					<span>{$i18n.t('I have saved these backup codes.')}</span>
				</label>

				<div class="flex justify-end gap-2">
					<button
						class="px-3 py-1.5 text-xs font-medium rounded-full bg-gray-100/70 hover:bg-gray-100 dark:bg-gray-850 dark:hover:bg-gray-800 transition"
						type="button"
						on:click={copyBackupCodesHandler}
					>
						{$i18n.t('Copy')}
					</button>

					<button
						class="px-3 py-1.5 text-xs font-medium rounded-full bg-gray-100/70 hover:bg-gray-100 dark:bg-gray-850 dark:hover:bg-gray-800 transition"
						type="button"
						on:click={downloadBackupCodesHandler}
					>
						{$i18n.t('Save')}
					</button>

					<button
						class="px-3 py-1.5 text-xs font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full"
						type="button"
						disabled={!backupCodesAcknowledged}
						class:opacity-50={!backupCodesAcknowledged}
						on:click={() => {
							if (!backupCodesAcknowledged) {
								return;
							}
							backupCodes = [];
							loadStatus();
						}}
					>
						{$i18n.t('Done')}
					</button>
				</div>
			</div>
		{:else if status.enabled}
			<div class="mt-2 space-y-2">
				<div class="text-xs text-gray-500">
					{$i18n.t('Backup codes remaining')}: {status.backup_codes_remaining}
				</div>

				<div class="flex gap-2">
					<button
						class="text-xs font-medium text-gray-500"
						type="button"
						on:click={() => {
							action = action === 'regenerate' ? '' : 'regenerate';
						}}
					>
						{$i18n.t('New backup codes')}
					</button>

					<button
						class="text-xs font-medium text-red-500"
						type="button"
						on:click={() => {
							action = action === 'disable' ? '' : 'disable';
						}}
					>
						{$i18n.t('Disable')}
					</button>
				</div>

				{#if action}
					<div class="space-y-2">
						{#if useBackupCode}
							<div>
								<label for="totp-action-backup" class="mb-1 text-xs font-medium block"
									>{$i18n.t('Backup code')}</label
								>
								<input
									id="totp-action-backup"
									class="w-full text-sm dark:text-gray-300 bg-transparent outline-hidden"
									type="text"
									autocomplete="one-time-code"
									bind:value={actionBackupCode}
									placeholder={$i18n.t('Enter backup code')}
								/>
							</div>
						{:else}
							<div>
								<label for="totp-action-code" class="mb-1 text-xs font-medium block"
									>{$i18n.t('Authenticator code')}</label
								>
								<input
									id="totp-action-code"
									class="w-full text-sm dark:text-gray-300 bg-transparent outline-hidden"
									type="text"
									inputmode="numeric"
									autocomplete="one-time-code"
									bind:value={actionCode}
									placeholder={$i18n.t('Enter 6-digit code')}
								/>
							</div>
						{/if}

						<div class="flex justify-between items-center">
							<button
								class="text-xs underline"
								type="button"
								on:click={() => {
									useBackupCode = !useBackupCode;
									actionCode = '';
									actionBackupCode = '';
								}}
							>
								{useBackupCode ? $i18n.t('Use authenticator code') : $i18n.t('Use backup code')}
							</button>

							<button
								class="px-3 py-1.5 text-xs font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full"
								type="button"
								disabled={actionPending}
								class:opacity-50={actionPending}
								on:click={submitActionHandler}
							>
								{action === 'disable' ? $i18n.t('Disable') : $i18n.t('Regenerate')}
							</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</div>
{/if}
