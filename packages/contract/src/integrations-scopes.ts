/**
 * WHICH GRANTS ARE HIGH-PRIVILEGE: the classification table the integrations
 * planner reads, written out name by name.
 *
 * The rule (docs/design/scanners.md) is that an application holds a
 * high-privilege grant when it can reach the DIRECTORY, MAIL or FILES, holds
 * ANY WRITE scope, or can read CHAT or CALENDAR content, which expose other
 * people's content as mail and files do. Reading people's profiles
 * (`User.Read.All`) and the directory's logs (`AuditLog.Read.All`) stays below
 * the bar: profiles and logs, not content. That rule is applied here to
 * Microsoft Graph's permissions one name at a time, so what counts as high is
 * a table a reviewer can read, and a test
 * holds each entry to the rule's spelling (a `ReadWrite` name is a write, a
 * `Mail.` name is mail).
 *
 * THREE ANSWERS, NEVER TWO. A name in the table with no class is LOW: it is in
 * the table because it was judged to reach none of the classes. A name with a
 * class is HIGH. A name that is not in the table, or a permission on an API
 * other than Microsoft Graph, is UNKNOWN: it is not called high, and it is not
 * called low either. The planner lists every unknown name in the results, for
 * a person to judge. Some sensitive Graph permissions (contacts, notes, chat
 * membership without its messages) are left out on purpose: they reach none
 * of the classes, and calling them LOW would be a judgement
 * nobody made.
 *
 * Delegated and application permissions share one table: Graph spells the two
 * alike, and an application permission reaches the whole directory where a
 * delegated one reaches what the signed-in person can, which is a matter of
 * scale and not of class. Keep this module free of Node built-ins.
 */

/**
 * The classes that make a grant high-privilege; holding any one is enough.
 * `CHAT` and `CALENDAR` are there because reading other people's chats or
 * calendars across a directory exposes content, as reading their mail or files
 * does (docs/design/scanners.md records the decision).
 */
export const PERMISSION_CLASSES = ['DIRECTORY', 'MAIL', 'FILES', 'CHAT', 'CALENDAR', 'WRITE'] as const;
export type PermissionClass = (typeof PERMISSION_CLASSES)[number];

/** Microsoft Graph's application id, the same in every directory. */
export const MICROSOFT_GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';

const D = 'DIRECTORY' as const;
const M = 'MAIL' as const;
const F = 'FILES' as const;
const W = 'WRITE' as const;
const C = 'CHAT' as const;
const K = 'CALENDAR' as const;

/**
 * Microsoft Graph's permissions, by name, and the classes each reaches. An
 * empty list is a judgement that it reaches none of them.
 */
export const GRAPH_PERMISSION_CLASSES: Readonly<Record<string, readonly PermissionClass[]>> = Object.freeze({
    // ── Low: sign-in and the signed-in person's own basic profile, and directory facts that name no person ──
    openid: [],
    profile: [],
    email: [],
    offline_access: [],
    'User.Read': [],
    'User.ReadBasic.All': [],
    // Below the bar: profiles and logs, not content. Listed, so they read as not high rather than unknown.
    'User.Read.All': [],
    'AuditLog.Read.All': [],
    'Presence.Read': [],
    'Presence.Read.All': [],
    'Organization.Read.All': [],
    'Domain.Read.All': [],
    'Team.ReadBasic.All': [],
    'Channel.ReadBasic.All': [],
    'ServiceHealth.Read.All': [],
    'ServiceMessage.Read.All': [],
    'Place.Read.All': [],

    // ── The directory: people, groups, applications, roles, policies, devices, sign-in records ──
    'Directory.Read.All': [D],
    'Directory.ReadWrite.All': [D, W],
    'Directory.AccessAsUser.All': [D, W],
    'User.ReadWrite.All': [D, W],
    'User.Invite.All': [D, W],
    'User.ManageIdentities.All': [D, W],
    'User.EnableDisableAccount.All': [D, W],
    'User.Export.All': [D],
    'Group.Read.All': [D],
    'Group.ReadWrite.All': [D, W],
    'Group.Create': [D, W],
    'GroupMember.Read.All': [D],
    'GroupMember.ReadWrite.All': [D, W],
    'Application.Read.All': [D],
    'Application.ReadWrite.All': [D, W],
    'Application.ReadWrite.OwnedBy': [D, W],
    'AppRoleAssignment.ReadWrite.All': [D, W],
    'DelegatedPermissionGrant.ReadWrite.All': [D, W],
    'RoleManagement.Read.Directory': [D],
    'RoleManagement.Read.All': [D],
    'RoleManagement.ReadWrite.Directory': [D, W],
    'Policy.Read.All': [D],
    'Policy.ReadWrite.ConditionalAccess': [D, W],
    'Policy.ReadWrite.AuthenticationMethod': [D, W],
    'Policy.ReadWrite.ApplicationConfiguration': [D, W],
    'Policy.ReadWrite.PermissionGrant': [D, W],
    'Policy.ReadWrite.Authorization': [D, W],
    'Device.Read.All': [D],
    'Device.ReadWrite.All': [D, W],
    'IdentityRiskyUser.Read.All': [D],
    'IdentityRiskyUser.ReadWrite.All': [D, W],
    'IdentityRiskEvent.Read.All': [D],
    'UserAuthenticationMethod.Read.All': [D],
    'UserAuthenticationMethod.ReadWrite.All': [D, W],
    'Domain.ReadWrite.All': [D, W],
    'Organization.ReadWrite.All': [D, W],
    'AdministrativeUnit.Read.All': [D],
    'AdministrativeUnit.ReadWrite.All': [D, W],
    'EntitlementManagement.Read.All': [D],
    'EntitlementManagement.ReadWrite.All': [D, W],
    'IdentityProvider.Read.All': [D],
    'IdentityProvider.ReadWrite.All': [D, W],
    'PrivilegedAccess.Read.AzureAD': [D],
    'PrivilegedAccess.ReadWrite.AzureAD': [D, W],
    'Synchronization.Read.All': [D],
    'Synchronization.ReadWrite.All': [D, W],
    'CrossTenantInformation.ReadBasic.All': [D],

    // ── Mail ──
    'Mail.Read': [M],
    'Mail.ReadBasic': [M],
    'Mail.ReadBasic.All': [M],
    'Mail.Read.Shared': [M],
    'Mail.ReadWrite': [M, W],
    'Mail.ReadWrite.Shared': [M, W],
    'Mail.Send': [M, W],
    'Mail.Send.Shared': [M, W],
    'MailboxSettings.Read': [M],
    'MailboxSettings.ReadWrite': [M, W],
    'IMAP.AccessAsUser.All': [M, W],
    'POP.AccessAsUser.All': [M, W],
    'SMTP.Send': [M, W],
    'EWS.AccessAsUser.All': [M, W],

    // ── Files: OneDrive and SharePoint ──
    'Files.Read': [F],
    'Files.Read.All': [F],
    'Files.Read.Selected': [F],
    'Files.ReadWrite': [F, W],
    'Files.ReadWrite.All': [F, W],
    'Files.ReadWrite.AppFolder': [F, W],
    'Files.ReadWrite.Selected': [F, W],
    'Files.SelectedOperations.Selected': [F, W],
    'Sites.Read.All': [F],
    'Sites.ReadWrite.All': [F, W],
    'Sites.Manage.All': [F, W],
    'Sites.FullControl.All': [F, W],
    'Sites.Selected': [F],

    // ── Chats and channel messages: other people's content, as mail is ──
    'Chat.Read': [C],
    'Chat.Read.All': [C],
    'ChatMessage.Read': [C],
    'ChatMessage.Read.All': [C],
    'ChannelMessage.Read.All': [C],
    'Chat.ReadWrite': [C, W],
    'Chat.ReadWrite.All': [C, W],
    'ChatMessage.Send': [C, W],
    'ChannelMessage.Send': [C, W],

    // ── Calendars: other people's content, as mail is ──
    'Calendars.Read': [K],
    'Calendars.Read.Shared': [K],
    'Calendars.ReadBasic': [K],
    'Calendars.ReadBasic.All': [K],
    'Calendars.ReadWrite': [K, W],
    'Calendars.ReadWrite.Shared': [K, W],

    // ── Writes that reach none of the classes above ──
    'User.ReadWrite': [W],
    'Contacts.ReadWrite': [W],
    'Contacts.ReadWrite.Shared': [W],
    'Tasks.ReadWrite': [W],
    'Tasks.ReadWrite.Shared': [W],
    'Notes.Create': [W],
    'Notes.ReadWrite': [W],
    'Notes.ReadWrite.All': [W],
    'Chat.Create': [W],
    'Team.Create': [W],
    'TeamMember.ReadWrite.All': [W],
    'OnlineMeetings.ReadWrite': [W],
    'OnlineMeetings.ReadWrite.All': [W],
    'Presence.ReadWrite': [W],
    'Bookings.ReadWrite.All': [W],
    'Schedule.ReadWrite.All': [W],
    'DeviceManagementApps.ReadWrite.All': [W],
    'DeviceManagementConfiguration.ReadWrite.All': [W],
    'DeviceManagementManagedDevices.ReadWrite.All': [W],
    'DeviceManagementRBAC.ReadWrite.All': [W],
    'DeviceManagementServiceConfig.ReadWrite.All': [W],
});

/** What the table says of one permission. */
export type PermissionClassification =
    | { readonly known: true; readonly classes: readonly PermissionClass[]; readonly high: boolean }
    | { readonly known: false };

/**
 * One permission, classified. Known only on Microsoft Graph and only by a name
 * in the table; a permission whose name the read could not resolve, or on any
 * other API, is unknown and never high.
 */
export function classifyPermission(resourceAppId: string | null, name: string | null): PermissionClassification {
    if (resourceAppId !== MICROSOFT_GRAPH_APP_ID || name === null) return { known: false };
    if (!Object.prototype.hasOwnProperty.call(GRAPH_PERMISSION_CLASSES, name)) return { known: false };
    const classes = GRAPH_PERMISSION_CLASSES[name];
    return { known: true, classes, high: classes.length > 0 };
}
