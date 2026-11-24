# pwcheck

A small command-line tool that checks how strong a password is and whether it has appeared in a known data breach.

```
$ python3 pwcheck.py
Password (hidden):

Strength : Reasonable (~59.5 bits)
  - Shorter than 12 characters

[!] Found in 1,204 known breaches. Do not use this password.
```

## How it works

- **Strength** is estimated locally: length and character variety give a rough entropy figure, which is reduced for common passwords, repeated characters and keyboard or alphabet sequences.
- **Breach check** uses the [Have I Been Pwned](https://haveibeenpwned.com/API/v3#PwnedPasswords) range API with **k-anonymity**. The password is hashed with SHA-1 and only the first 5 hex characters of the hash are sent. The API returns every hash suffix that starts with that prefix, and the match is done on your machine. The password itself never leaves your computer.
- The password is read with `getpass`, so it is not echoed to the terminal or saved in shell history.

## Usage

Python 3.8+ and no third-party packages.

```bash
python3 pwcheck.py            # strength + breach check
python3 pwcheck.py --offline  # strength only, no network
python3 -m unittest           # run the tests
```

## Limitations

The entropy figure is a rough estimate, not a guarantee. A password built from personal information (names, dates) can score well here and still be easy to guess.

## License

MIT
