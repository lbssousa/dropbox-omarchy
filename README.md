# dropbox-omarchy

Clone of Omarchy's built-in Dropbox bar widget (`omarchy.dropbox`) that shows the
**real storage quota of your Dropbox account** instead of a fixed per-plan value
(the built-in shows 2 GB for every Basic account, ignoring referral and promo
bonus space).

The desktop client keeps the quota only in its encrypted config, so the widget
asks the Dropbox API (`users/get_space_usage`). Used space then also comes from
the API, so it counts selective-sync and online-only files too.

## Setup

1. Create an app at <https://www.dropbox.com/developers/apps>:
   - **Scoped access**, **App folder** (no file access is needed).
   - *Permissions*: `account_info.read` (enabled by default).
   - *Settings → OAuth 2 → Redirect URIs*: `http://localhost:47823/`
2. Put the app's **App key** in the widget settings (`Dropbox app key`).
   No app secret is needed: authorization uses PKCE.
3. Open the panel and click **Connect account to read the real quota**
   (or `omarchy-shell omarchy.dropbox connectQuota`), then allow access in the
   browser.

Without an app key the widget behaves like the built-in one and labels the
quota as a plan estimate.

## Storage

- Refresh token: Secret Service keyring via `secret-tool`
  (`application=lbssousa.dropbox kind=refresh_token`), or
  `~/.local/state/lbssousa.dropbox/refresh_token` (0600) without it.
- Access token: `~/.local/state/lbssousa.dropbox/access_token.json` (0600).
- Last reading: `~/.cache/lbssousa.dropbox/space.json`, refreshed every 10 min;
  on network errors the last reading is kept and marked stale.

`omarchy-shell omarchy.dropbox disconnectQuota` (or `just disconnect`) forgets
all of them.

## Development

```sh
just link       # symlink into ~/.config/omarchy/plugins and reload the shell
just validate
```
