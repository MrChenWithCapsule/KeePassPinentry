# Overview of KeePassPinentry

KeePassPinentry acts as a agent between gpg-agent and KeePass, KeePassXC, or another pinentry. It accepts requests from gpg-agent, returns the passphrase if it is found in KeePass database, or invoke another pinentry if not.

This program communicates with KeePass (or KeePassXC) using the same protocol for keepassxc-browser. For KeePass, the KeePassNatMsg plugin is needed.
