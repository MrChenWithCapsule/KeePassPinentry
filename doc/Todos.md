# Todos

1. [ ] Implement a proxy between gpg-agent and pinentry
    1. [x] Implement passing commands to pinentry
    2. [ ] Implement assuan handler
    3. [ ] Add an command option to select pinentry
    4. [ ] Fix pinentry-curses asking for tty
2. [ ] Implement find passphrase in database for requested key
    1. [ ] Implement communication between KeePassPinentry and KeePass on Windows (Named Pipe)
    2. [ ] Implement communication on Unix (Unix Socket)
    3. [ ] Implement find passphrase using information given by gpg-agent
3. [ ] Add tests
