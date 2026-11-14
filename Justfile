set shell := ["bash", "-uc"]

plugin_link := env("HOME") / ".config/omarchy/plugins/lbssousa.dropbox"

default:
    @just --list

# Plugin validation
validate:
    omarchy-plugin-validate .

# Load this checkout's plugin in the real shell
link:
    ln -sfn "$PWD" {{plugin_link}}
    omarchy-shell shell rescanPlugins
    omarchy-shell shell enablePlugin lbssousa.dropbox '{}'
    omarchy-restart-shell

# Authorize the Dropbox API (reads the app key from DROPBOX_APP_KEY)
connect:
    python3 status.py --authorize

# Forget the stored Dropbox API tokens
disconnect:
    python3 status.py --disconnect
