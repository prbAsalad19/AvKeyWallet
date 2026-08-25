# avKeyWallet

A small, terminal-based password vault written in modern C++, backed by [libsodium](https://libsodium.gitbook.io/doc/) for authenticated encryption, Argon2id key derivation, and hardened memory handling for secrets.

> Personal / educational project. It has been reviewed for common memory-safety and parsing pitfalls, but it has **not** undergone an independent security audit. Read the [Security Design](#security-design) and [Known Limitations](#known-limitations) sections before trusting it with real credentials.

---

## Features

- **Single master password** unlocks the whole vault (Argon2id key derivation, `OPSLIMIT_SENSITIVE` / `MEMLIMIT_SENSITIVE`).
- **Authenticated encryption** of the vault contents via libsodium's `crypto_secretbox_easy` (XSalsa20-Poly1305).
- **Hardened memory for secrets**: every sensitive buffer (master key, derived key, plaintext vault, entry fields) is allocated with `sodium_malloc` / `sodium_free` instead of the regular heap — this adds guard pages, overflow canaries, protection against being swapped to disk, and automatic zeroing on release.
- **Atomic saves**: the vault is written to a temporary file and only replaces the real vault file via `rename()`, so a crash or power loss mid-save can't corrupt an existing vault.
- **Hidden password input**: master key and password fields are read character-by-character with terminal echo disabled (`termios` on POSIX, `conio.h` on Windows) and support backspace.
- **No silent truncation**: input buffers grow dynamically, so long master passwords or credentials are never quietly cut off.
- **Basic CRUD**: list, reveal, add, edit, and remove credential entries, all operating on an in-memory plaintext buffer until an explicit save.

## Security Design

| Concern | How it's handled |
|---|---|
| Secret storage in memory | `SecureBuffer` wraps `sodium_malloc`/`sodium_free`; secrets are zeroed automatically when a buffer is freed or reassigned (move-assignment releases the old buffer through `sodium_free`, which zeroes it). |
| Key derivation | Argon2id (`crypto_pwhash_ALG_ARGON2ID13`) with the `SENSITIVE` operation/memory limits, using a 16-byte salt stored alongside the vault. |
| Confidentiality & integrity | `crypto_secretbox_easy` — a fresh random 24-byte nonce is generated on every save, and the ciphertext carries a Poly1305 authentication tag, so tampering or use of the wrong password is detected on decrypt. |
| Vault file layout | `[ salt (16 bytes) ][ nonce (24 bytes) ][ ciphertext + MAC ]` — see [Vault File Format](#vault-file-format). |
| Crash safety | Save is write-temp-then-`rename`, so the on-disk vault is never left half-written. |
| Input validation | Service/username fields reject `;`, `\n`, `\r` (used as internal delimiters); passwords reject `\n`/`\r` but may contain `;`. Corrupt/too-short vault files are rejected before any parsing touches out-of-bounds memory. |
| Master key lifetime | The master password buffer is explicitly released as soon as the encryption key has been derived from it, rather than kept alive for the whole session. |

## Known Limitations

Being upfront about what this project **doesn't** protect against:

- **One password, one vault.** There's no per-entry encryption, no key rotation, and no multi-user support.
- **No defense against a compromised host.** `sodium_malloc` prevents secrets from being swapped to disk or showing up in a core dump, but it does not protect against a keylogger, a malicious process with ptrace/root access, or a compromised terminal emulator.
- **Interactive terminal use only.** The tool is not designed to be scripted, piped, or automated, and it does not expose a non-interactive CLI or API.
- **No backups or history.** Saving overwrites the vault in place (atomically, but without versioning) — there is no undo, no revision history, and no automatic backup.
- **No concurrency control.** Running two instances of the program against the same `vault.db` at once is unsafe and can lead to lost writes.
- **Not independently audited.** The cryptographic building blocks are libsodium's well-vetted primitives, but the surrounding application logic has only been reviewed informally.

## Building

### Dependencies

- A C++17-capable compiler (GCC, Clang, or MSVC)
- [libsodium](https://libsodium.gitbook.io/doc/installation) (development headers + library)

On Debian/Ubuntu:

```bash
sudo apt install libsodium-dev
```

On macOS (Homebrew):

```bash
brew install libsodium
```

### Compiling (Linux/macOS)

```bash
g++ -std=c++17 -O2 main.cpp -o avKeyWallet -lsodium
```

Or, using `pkg-config`:

```bash
g++ -std=c++17 -O2 main.cpp -o avKeyWallet $(pkg-config --cflags --libs libsodium)
```

### Compiling (Windows)

Link against the libsodium import library and ensure `conio.h` is available (standard with MSVC/MinGW). Example with MinGW:

```bash
g++ -std=c++17 -O2 main.cpp -o avKeyWallet.exe -lsodium
```

Adjust the source filename above (`main.cpp`) to match how the file is named in your checkout.

## Usage

```bash
./avKeyWallet
```

On first run (no `vault.db` in the working directory), you'll be prompted to set a master password and a new, empty vault will be created. On subsequent runs, entering the correct master password decrypts the existing vault.

```
=== SECURE VAULT MANAGER ===
Enter your master key: ********

--- MENU ---
1. List credentials
2. Show password
3. Add entry
4. Edit entry
5. Remove entry
6. Save and exit
7. Exit without saving
Choice:
```

Changes made via options 3–5 exist only in memory until you choose **6. Save and exit**; choosing **7** discards any unsaved changes (with a confirmation prompt).

## Vault File Format

```
+----------------+-----------------+--------------------------------+
|   Salt (16 B)  |  Nonce (24 B)   |   Ciphertext + Poly1305 MAC     |
+----------------+-----------------+--------------------------------+
```

The decrypted plaintext is a simple newline-separated list of entries:

```
service;username;password
service;username;password
...
```

This plaintext only ever exists in locked memory (`sodium_malloc`) and is never written to disk — only the encrypted, authenticated form leaves the process.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This is a personal project built to explore secure memory handling and authenticated encryption in C++. It is provided as-is, without warranty. Review the source yourself, and don't rely on it as your sole password manager for high-value credentials without further, independent review.
