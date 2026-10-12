---
icon: lucide/key-round
---

# 1Password

Muxus can log in with passwords that stay in 1Password. It keeps only a **secret
reference** such as `op://Network/core-sw1/password`, never the password, and asks the
1Password CLI (`op`) for the value each time it types it. The 1Password app then asks you to
approve Muxus with Touch ID, Windows Hello or your system password.

A 1Password secret works everywhere a [named secret](settings.md#passwords) does: as a host's
or folder's login password, in a [login sequence](adding-hosts.md#login-sequence), on a
[command button](commands.md#buttons-that-send-a-secret) and in **Send secret…**. It needs no
Muxus password vault and no master password.

## Set it up

1. Install the [1Password CLI](https://developer.1password.com/docs/cli/get-started/) on the
   computer that runs Muxus. The package installers, Homebrew, `winget`, Scoop and Chocolatey
   all work.
2. In the 1Password app, open **Settings → Developer** and turn on **Integrate with
   1Password CLI**.
3. In Muxus, open **Settings → Passwords**. The **1Password** group says where it found the
   CLI and which version it is. **Check again** looks once more after an install.

<figure markdown="span">
  ![The 1Password group in Settings → Passwords](../assets/screenshots/1password-settings.png#only-light){ .shadow }
  ![The 1Password group in Settings → Passwords](../assets/screenshots/1password-settings-dark.png#only-dark){ .shadow }
  <figcaption>The CLI was found, and the secrets below it are references to 1Password items. No password vault is needed.</figcaption>
</figure>

Muxus looks for `op` on `PATH` first, then in the folders the installers use:

| System | Also looked for in |
| --- | --- |
| macOS | `/usr/local/bin`, `/opt/homebrew/bin`, `/opt/local/bin` |
| Linux | `/usr/bin`, `/usr/local/bin` |
| Windows | the WinGet links and package folders, `Program Files\1Password CLI`, Scoop and Chocolatey shims |

If it lives anywhere else, enter its full path under **CLI location**.

A [service account](https://developer.1password.com/docs/service-accounts/) also works: start
Muxus with `OP_SERVICE_ACCOUNT_TOKEN` set, and the CLI reads with it instead of asking the
app.

## Add a secret

In 1Password, open the item and choose **Copy Secret Reference** from the field's menu. In
Muxus, choose **Add from 1Password** under **Settings → Passwords → Secrets**, or **New
secret from 1Password…** in any secret picker, and fill in:

- **Name**, how Muxus lists it;
- **Secret reference**, `op://vault/item/field` or `op://vault/item/section/field`. Add
  `?attribute=otp` to a one-time password field to type its current code;
- **1Password account**, only when you are signed in to more than one: its sign-in address
  or ID.

**Test** asks 1Password for the field now and says whether it could provide it. The value is
thrown away and never shown.

<figure markdown="span">
  ![Adding a secret from 1Password](../assets/screenshots/1password-secret.png#only-light){ .shadow }
  ![Adding a secret from 1Password](../assets/screenshots/1password-secret-dark.png#only-dark){ .shadow }
  <figcaption>Only the secret reference is saved. Test confirms 1Password can provide the value.</figcaption>
</figure>

## Log in to a Cisco device

A typical switch or router asks for a login password, then an `enable` password:

1. Add two 1Password secrets, for example **core-sw1 login** with
   `op://Network/core-sw1/password` and **core-sw1 enable** with
   `op://Network/core-sw1/enable`.
2. In the host editor's **Authentication** section, choose **core-sw1 login** as the
   **Login password**. To use one password for a whole folder of devices, choose it under
   **Password from a secret** in the folder's **Shared SSH credentials** instead.
3. In the **Login sequence** section, add these steps:

    | Step | Value |
    | --- | --- |
    | Wait for | `>` |
    | Send text | `enable` |
    | Wait for | `Password:` |
    | Send secret | **core-sw1 enable** |
    | Wait for | `#` |
    | Send text | `terminal length 0` |

When the device asks for the password, Muxus reads it from 1Password and types it.
1Password asks you to approve Muxus the first time, and again after about ten minutes
without use or when the app locks. Telnet and serial consoles log in the same
way, with **Wait for** `Username:` and `Password:` steps in the login sequence.

<figure markdown="span">
  ![A host's login password read from 1Password](../assets/screenshots/1password-host-login.png#only-light){ .shadow }
  ![A host's login password read from 1Password](../assets/screenshots/1password-host-login-dark.png#only-dark){ .shadow }
  <figcaption>The host logs in with a secret read from 1Password; a saved password or the prompt comes next.</figcaption>
</figure>

## When 1Password cannot help

If the CLI is missing, not signed in, the request was not approved, or the reference points
nowhere, Muxus says why and carries on:

- **SSH login**: the reason appears in the terminal, and Muxus tries the next password it
  knows (the host's saved password, then each folder's), then asks you as usual.
- **Login sequence**: Muxus asks you to type the value for that step. It is typed into the
  session and not saved. **Stop login sequence** ends the sequence there and leaves the
  session open.
- **Command button** or **Send secret…**: a message names the secret and the reason.

### "Muxus could not reach the 1Password app"

The CLI could not connect to the 1Password app within its few seconds, so Muxus tried once
more and then gave up. The same happens to `op whoami` in a terminal, which is the quickest
way to check the connection outside Muxus. Usually one of these helps:

- unlock the 1Password app, and answer any approval prompt it shows; it can open behind
  other windows;
- on Windows, turn on **Unlock using Windows Hello** under **Settings → Security** in the
  1Password app, then check **Integrate with 1Password CLI** under **Settings → Developer**;
- quit the 1Password app from its tray or menu-bar icon and start it again;
- update the CLI and the app together, for example `winget upgrade AgileBits.1Password.CLI`.

## What is stored

Muxus stores the name, the optional user name, the secret reference and the account. These
name your vault, item and field but are not the password. The value exists only while it is
typed: it goes from the CLI straight into the connection, past session history, log files
and the window, like a [vault secret](../reference/security.md#secrets-from-password-managers).

A secret reference is not part of a backup. A host, folder or login sequence restored on
another computer shows its secret as missing until you choose one again.
