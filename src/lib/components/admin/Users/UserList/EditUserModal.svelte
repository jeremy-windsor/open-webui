<script lang="ts">
	import { toast } from 'svelte-sonner';
	import dayjs from 'dayjs';
	import { createEventDispatcher } from 'svelte';
	import { getContext } from 'svelte';
	import type { Writable } from 'svelte/store';
	import type { i18n as i18nType } from 'i18next';

	import { goto } from '$app/navigation';

	import {
		disableUserTOTPById,
		getUserGroupsById,
		getUserTOTPStatusById,
		updateUserById
	} from '$lib/apis/users';
	import { getSessionUser } from '$lib/apis/auths';

	import Modal from '$lib/components/common/Modal.svelte';
	import localizedFormat from 'dayjs/plugin/localizedFormat';
	import XMark from '$lib/components/icons/XMark.svelte';
	import SensitiveInput from '$lib/components/common/SensitiveInput.svelte';
	import UserProfileImage from '$lib/components/chat/Settings/Account/UserProfileImage.svelte';
	import { config, socket, user as currentUser } from '$lib/stores';

	const i18n: Writable<i18nType> = getContext('i18n');
	const dispatch = createEventDispatcher();
	dayjs.extend(localizedFormat);

	export let show = false;
	export let selectedUser;
	export let sessionUser;

	$: if (show) {
		init();
	}

	const init = () => {
		if (selectedUser) {
			_user = selectedUser;
			_user.password = '';
			_user.current_password = '';
			totpAdminPassword = '';
			totpAdminCode = '';
			totpAdminBackupCode = '';
			totpAdminUseBackupCode = false;
			loadUserGroups();
			if ($config?.features?.enable_totp) {
				loadTOTPStatus();
			} else {
				totpStatus = null;
			}
		}
	};

	let _user = {
		profile_image_url: '',
		role: 'pending',
		name: '',
		email: '',
		password: '',
		current_password: ''
	};

	let userGroups: any[] | null = null;
	let totpStatus: { enabled: boolean; backup_codes_remaining: number } | null = null;
	let totpAdminPassword = '';
	let totpAdminCode = '';
	let totpAdminBackupCode = '';
	let totpAdminUseBackupCode = false;

	const submitHandler = async () => {
		const res = await updateUserById(localStorage.token, selectedUser.id, _user).catch((error) => {
			toast.error(`${error}`);
		});

		if (res) {
			dispatch('save');
			show = false;
		}
	};

	const loadUserGroups = async () => {
		if (!selectedUser?.id) return;
		userGroups = null;

		userGroups = await getUserGroupsById(localStorage.token, selectedUser.id).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
	};

	const loadTOTPStatus = async () => {
		if (!selectedUser?.id) return;
		totpStatus = await getUserTOTPStatusById(localStorage.token, selectedUser.id).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
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
			await currentUser.set(sessionUser);
		}
	};

	const disableTOTPHandler = async () => {
		if (!selectedUser?.id) return;
		if (!confirm($i18n.t('Disable two-factor authentication for this user?'))) return;

		const res = await disableUserTOTPById(localStorage.token, selectedUser.id, {
			...(totpAdminPassword ? { password: totpAdminPassword } : {}),
			...(totpAdminUseBackupCode ? { backup_code: totpAdminBackupCode } : { code: totpAdminCode })
		}).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		totpAdminPassword = '';
		totpAdminCode = '';
		totpAdminBackupCode = '';

		if (res) {
			if (res.token) {
				await refreshSessionAfterTokenChange(res.token);
			}
			totpStatus = res;
			toast.success($i18n.t('Two-factor authentication disabled.'));
		}
	};
</script>

<Modal size="sm" bind:show>
	<div>
		<div class=" flex justify-between dark:text-gray-300 px-5 pt-4 pb-2">
			<div class=" text-lg font-medium self-center">{$i18n.t('Edit User')}</div>
			<button
				class="self-center"
				aria-label={$i18n.t('Close')}
				on:click={() => {
					show = false;
				}}
			>
				<XMark className={'size-5'} />
			</button>
		</div>

		<div class="flex flex-col md:flex-row w-full md:space-x-4 dark:text-gray-200">
			<div class=" flex flex-col w-full sm:flex-row sm:justify-center sm:space-x-6">
				<form
					class="flex flex-col w-full"
					on:submit|preventDefault={() => {
						submitHandler();
					}}
				>
					<div class=" px-5 pt-3 pb-5 w-full">
						<div class="flex self-center w-full">
							<div class=" self-start h-full mr-6">
								<UserProfileImage
									imageClassName="size-14"
									bind:profileImageUrl={_user.profile_image_url}
									user={_user}
								/>
							</div>

							<div class=" flex-1">
								<div class="overflow-hidden w-ful mb-2">
									<div class=" self-center capitalize font-medium truncate">
										{selectedUser.name}
									</div>

									<div class="text-xs text-gray-500">
										{$i18n.t('Created at')}
										{dayjs(selectedUser.created_at * 1000).format('LL')}
									</div>
								</div>

								<div class=" flex flex-col space-y-1.5">
									{#if (userGroups ?? []).length > 0}
										<div class="flex flex-col w-full text-sm">
											<div class="mb-1 text-xs text-gray-500">{$i18n.t('User Groups')}</div>

											<div class="flex flex-wrap gap-1 my-0.5 -mx-1">
												{#each userGroups as userGroup}
													<span
														class="px-1.5 py-0.5 rounded-xl bg-gray-100 dark:bg-gray-850 text-xs"
													>
														<a
															href={'/admin/users/groups?id=' + userGroup.id}
															on:click|preventDefault={() =>
																goto('/admin/users/groups?id=' + userGroup.id)}
														>
															{userGroup.name}
														</a>
													</span>
												{/each}
											</div>
										</div>
									{/if}

									<div class="flex flex-col w-full">
										<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Role')}</div>

										<div class="flex-1">
											<select
												class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
												bind:value={_user.role}
												aria-label={$i18n.t('Role')}
												disabled={_user.id == sessionUser.id}
												required
											>
												<option value="admin">{$i18n.t('Admin')}</option>
												<option value="user">{$i18n.t('User')}</option>
												<option value="pending">{$i18n.t('Pending')}</option>
											</select>
										</div>
									</div>

									<div class="flex flex-col w-full">
										<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Name')}</div>

										<div class="flex-1">
											<input
												class="w-full text-sm bg-transparent outline-hidden"
												type="text"
												bind:value={_user.name}
												aria-label={$i18n.t('Name')}
												placeholder={$i18n.t('Enter Your Name')}
												autocomplete="off"
												required
											/>
										</div>
									</div>

									<div class="flex flex-col w-full">
										<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Email')}</div>

										<div class="flex-1">
											<input
												class="w-full text-sm bg-transparent disabled:text-gray-500 dark:disabled:text-gray-500 outline-hidden"
												type="email"
												bind:value={_user.email}
												aria-label={$i18n.t('Email')}
												placeholder={$i18n.t('Enter Your Email')}
												autocomplete="off"
												required
											/>
										</div>
									</div>

									{#if _user?.oauth}
										<div class="flex flex-col w-full">
											<div class=" mb-1 text-xs text-gray-500">{$i18n.t('OAuth ID')}</div>

											<div class="flex-1 text-sm break-all mb-1 flex flex-col space-y-1">
												{#each Object.keys(_user.oauth) as key}
													<div>
														<span class="text-gray-500">{key}</span>
														<span class="">{_user.oauth[key]?.sub}</span>
													</div>
												{/each}
											</div>
										</div>
									{/if}

									<div class="flex flex-col w-full">
										<div class=" mb-1 text-xs text-gray-500">{$i18n.t('New Password')}</div>

										<div class="flex-1">
											<SensitiveInput
												class="w-full text-sm bg-transparent outline-hidden"
												type="password"
												aria-label={$i18n.t('New Password')}
												placeholder={$i18n.t('Enter New Password')}
												bind:value={_user.password}
												autocomplete="new-password"
												required={false}
											/>
										</div>
									</div>

									{#if selectedUser?.id === sessionUser?.id && _user.password}
										<div class="flex flex-col w-full">
											<div class=" mb-1 text-xs text-gray-500">{$i18n.t('Current Password')}</div>

											<div class="flex-1">
												<SensitiveInput
													type="password"
													aria-label={$i18n.t('Current Password')}
													placeholder={$i18n.t('Enter Current Password')}
													bind:value={_user.current_password}
													autocomplete="current-password"
													required={false}
												/>
											</div>
										</div>
									{/if}

									{#if $config?.features?.enable_totp && totpStatus?.enabled}
										<div class="flex flex-col w-full">
											<div class="mb-1 text-xs text-gray-500">
												{$i18n.t('Two-factor authentication')}
											</div>

											<div class="flex items-center justify-between gap-3">
												<div class="text-xs text-gray-500">
													{$i18n.t('Backup codes remaining')}: {totpStatus.backup_codes_remaining}
												</div>
											</div>

											<SensitiveInput
												id="admin-totp-disable-password"
												type="password"
												placeholder={$i18n.t('Current admin password or recent SSO sign-in')}
												bind:value={totpAdminPassword}
												autocomplete="current-password"
												required={false}
											/>

											<div class="text-xs text-gray-500">
												{$i18n.t(
													'Use your admin account authenticator or backup code if your admin account has two-factor authentication enabled.'
												)}
											</div>

											{#if totpAdminUseBackupCode}
												<input
													class="w-full text-sm bg-transparent outline-hidden"
													type="text"
													autocomplete="one-time-code"
													placeholder={$i18n.t('Backup code')}
													bind:value={totpAdminBackupCode}
												/>
											{:else}
												<input
													class="w-full text-sm bg-transparent outline-hidden"
													type="text"
													inputmode="numeric"
													autocomplete="one-time-code"
													placeholder={$i18n.t('Authenticator code')}
													bind:value={totpAdminCode}
												/>
											{/if}

											<button
												class="w-fit text-xs underline text-gray-500"
												type="button"
												on:click={() => {
													totpAdminUseBackupCode = !totpAdminUseBackupCode;
													totpAdminCode = '';
													totpAdminBackupCode = '';
												}}
											>
												{totpAdminUseBackupCode
													? $i18n.t('Use authenticator code')
													: $i18n.t('Use backup code')}
											</button>

											<div class="flex justify-end">
												<button
													class="text-xs font-medium text-red-500"
													type="button"
													on:click={disableTOTPHandler}
												>
													{$i18n.t('Disable')}
												</button>
											</div>
										</div>
									{/if}
								</div>
							</div>
						</div>

						<div class="flex justify-end pt-3 text-sm font-medium">
							<button
								class="px-3.5 py-1.5 text-sm font-medium bg-black hover:bg-gray-900 text-white dark:bg-white dark:text-black dark:hover:bg-gray-100 transition rounded-full flex flex-row space-x-1 items-center"
								type="submit"
							>
								{$i18n.t('Save')}
							</button>
						</div>
					</div>
				</form>
			</div>
		</div>
	</div>
</Modal>

<style>
	input::-webkit-outer-spin-button,
	input::-webkit-inner-spin-button {
		/* display: none; <- Crashes Chrome on hover */
		-webkit-appearance: none;
		margin: 0; /* <-- Apparently some margin are still there even though it's hidden */
	}

	.tabs::-webkit-scrollbar {
		display: none; /* for Chrome, Safari and Opera */
	}

	.tabs {
		-ms-overflow-style: none; /* IE and Edge */
		scrollbar-width: none; /* Firefox */
	}

	input[type='number'] {
		-moz-appearance: textfield; /* Firefox */
	}
</style>
