#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <limits>
#include <stdexcept>
#include <initializer_list>
#include <sodium.h>

#if defined(_WIN32)
#include <conio.h>
#else
#include <unistd.h>
#include <termios.h>
#endif

char readChar() {
#if defined(_WIN32)
    return _getch();
#else
    struct termios old_opts, new_opts;
    char ch = 0;

    tcgetattr(STDIN_FILENO, &old_opts);
    new_opts = old_opts;
    new_opts.c_lflag &= ~(ICANON | ECHO);
    new_opts.c_cc[VMIN] = 1;
    new_opts.c_cc[VTIME] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &new_opts);
    if (read(STDIN_FILENO, &ch, 1) < 0) ch = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &old_opts);

    return ch;
#endif
}

class SecureBuffer {
private:
    unsigned char* ptr = nullptr;
    size_t len = 0;

    void release() noexcept {
        if (ptr) {
            sodium_free(ptr);
            ptr = nullptr;
        }
        len = 0;
    }

public:
    explicit SecureBuffer(size_t size) : len(size) {
        if (size > 0) {
            ptr = static_cast<unsigned char*>(sodium_malloc(size));
            if (!ptr) throw std::bad_alloc();
            sodium_memzero(ptr, size);
        }
    }

    ~SecureBuffer() { release(); }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept : ptr(other.ptr), len(other.len) {
        other.ptr = nullptr;
        other.len = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            release();
            ptr = other.ptr;
            len = other.len;
            other.ptr = nullptr;
            other.len = 0;
        }
        return *this;
    }

    unsigned char* data_ptr() { return ptr; }
    const unsigned char* data_ptr() const { return ptr; }
    size_t size() const { return len; }
};

SecureBuffer grow_buffer(SecureBuffer&& old_buf) {
    size_t old_len = old_buf.size();
    size_t new_capacity = (old_len == 0) ? 128 : old_len * 2;
    SecureBuffer bigger(new_capacity);
    if (old_len > 0) {
        std::memcpy(bigger.data_ptr(), old_buf.data_ptr(), old_len);
    }
    return bigger;
}

void print_secure(std::string_view data) {
    for (char c : data) std::putchar(c);
    std::putchar('\n');
    std::fflush(stdout);
}

SecureBuffer capture_master_key() {
    SecureBuffer masterKey(128);
    std::cout << "Enter your master key: " << std::flush;

    size_t len = 0;
    while (true) {
        const char ch = readChar();

        if (ch == '\n' || ch == '\r' || ch == 13) break;

        if (ch == 127 || ch == 8) {
            if (len > 0) {
                --len;
                masterKey.data_ptr()[len] = 0;
            }
            continue;
        }

        if (len == masterKey.size()) {
            masterKey = grow_buffer(std::move(masterKey));
        }
        masterKey.data_ptr()[len++] = static_cast<unsigned char>(ch);
    }

    SecureBuffer resizedMasterKey(len);
    std::memcpy(resizedMasterKey.data_ptr(), masterKey.data_ptr(), len);
    return resizedMasterKey;
}

SecureBuffer derive_key(const SecureBuffer& masterPass, SecureBuffer& salt) {
    if (salt.size() == 0) {
        randombytes_buf(salt.data_ptr(), 16);
    }
    SecureBuffer derived_key(32);

    if (crypto_pwhash(derived_key.data_ptr(),
                32,
                reinterpret_cast<const char*>(masterPass.data_ptr()),
                masterPass.size(),
                salt.data_ptr(),
                crypto_pwhash_OPSLIMIT_SENSITIVE,
                crypto_pwhash_MEMLIMIT_SENSITIVE,
                crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        throw std::runtime_error("Failed to derive key");
    }

    return derived_key;
}

SecureBuffer encrypt_vault(const SecureBuffer& salt, const SecureBuffer& vault_plaintext, const SecureBuffer& derivedKey) {
    SecureBuffer nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data_ptr(), nonce.size());

    size_t cipher_len = vault_plaintext.size() + crypto_secretbox_MACBYTES;
    SecureBuffer cryptedText(cipher_len);

    if (crypto_secretbox_easy(cryptedText.data_ptr(),
                            vault_plaintext.data_ptr(),
                            vault_plaintext.size(),
                            nonce.data_ptr(),
                            derivedKey.data_ptr()) != 0)
    {
        throw std::runtime_error("Vault encryption failed.");
    }

    size_t total_size = salt.size() + nonce.size() + cryptedText.size();
    SecureBuffer final_vault(total_size);
    unsigned char* dest = final_vault.data_ptr();

    std::memcpy(dest, salt.data_ptr(), salt.size());
    dest += salt.size();

    std::memcpy(dest, nonce.data_ptr(), nonce.size());
    dest += nonce.size();

    std::memcpy(dest, cryptedText.data_ptr(), cryptedText.size());

    return final_vault;
}

SecureBuffer decrypt_vault(const SecureBuffer& vault, const SecureBuffer& derived_key) {
    const size_t salt_size = 16;
    const size_t nonce_size = crypto_secretbox_NONCEBYTES;

    if (vault.size() < salt_size + nonce_size + crypto_secretbox_MACBYTES) {
        throw std::runtime_error("Vault file is too small or corrupted.");
    }

    SecureBuffer nonce(nonce_size);
    std::memcpy(nonce.data_ptr(), vault.data_ptr() + salt_size, nonce_size);

    size_t cipher_size = vault.size() - salt_size - nonce_size;
    SecureBuffer cryptedText(cipher_size);
    std::memcpy(cryptedText.data_ptr(), vault.data_ptr() + salt_size + nonce_size, cipher_size);

    size_t plaintext_size = cryptedText.size() - crypto_secretbox_MACBYTES;
    SecureBuffer plaintext(plaintext_size);

    if (crypto_secretbox_open_easy(plaintext.data_ptr(),
                                cryptedText.data_ptr(),
                                cryptedText.size(),
                                nonce.data_ptr(),
                                derived_key.data_ptr()) != 0)
    {
        throw std::runtime_error("Incorrect password or corrupted vault.");
    }

    return plaintext;
}

SecureBuffer read_vault_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open vault file.");
    }

    std::streamsize file_size = file.tellg();
    if (file_size <= 0) {
        throw std::runtime_error("Vault file is empty or invalid.");
    }

    file.seekg(0, std::ios::beg);

    SecureBuffer buffer(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(buffer.data_ptr()), file_size)) {
        throw std::runtime_error("Error reading vault file.");
    }

    return buffer;
}

void write_vault_file_atomic(const std::string& filepath, const SecureBuffer& buffer) {
    std::string tmp_filepath = filepath + ".tmp";

    {
        std::ofstream file(tmp_filepath, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            throw std::runtime_error("Unable to create temporary file for saving.");
        }

        file.write(reinterpret_cast<const char*>(buffer.data_ptr()), buffer.size());
        file.flush();

        if (!file.good()) {
            file.close();
            std::remove(tmp_filepath.c_str());
            throw std::runtime_error("Error writing temporary file.");
        }
    }

    if (std::rename(tmp_filepath.c_str(), filepath.c_str()) != 0) {
        std::remove(tmp_filepath.c_str());
        throw std::runtime_error("Error during atomic vault replacement.");
    }
}

// to remove /n and ; from any entry as these are not allowed in the vault entries
void validate_no_char(const SecureBuffer& field, const char* field_name,
                       std::initializer_list<char> forbidden) {
    const unsigned char* p = field.data_ptr();
    for (size_t i = 0; i < field.size(); ++i) {
        for (char c : forbidden) {
            if (p[i] == static_cast<unsigned char>(c)) {
                throw std::invalid_argument(
                    std::string(field_name) + " contains a forbidden character (';' or newline).");
            }
        }
    }
}

SecureBuffer add_entry(const SecureBuffer& current_plaintext,
                      const SecureBuffer& service,
                      const SecureBuffer& username,
                      const SecureBuffer& password)
{
    validate_no_char(service, "Service", {';', '\n', '\r'});
    validate_no_char(username, "Username", {';', '\n', '\r'});
    validate_no_char(password, "Password", {'\n', '\r'});

    size_t added_size = service.size() + 1 + username.size() + 1 + password.size() + 1;
    size_t new_size = current_plaintext.size() + added_size;

    SecureBuffer new_plaintext(new_size);
    unsigned char* dest = new_plaintext.data_ptr();

    if (current_plaintext.size() > 0) {
        std::memcpy(dest, current_plaintext.data_ptr(), current_plaintext.size());
        dest += current_plaintext.size();
    }

    std::memcpy(dest, service.data_ptr(), service.size());
    dest += service.size();
    *dest++ = ';';

    std::memcpy(dest, username.data_ptr(), username.size());
    dest += username.size();
    *dest++ = ';';

    std::memcpy(dest, password.data_ptr(), password.size());
    dest += password.size();
    *dest++ = '\n';

    return new_plaintext;
}

SecureBuffer remove_entry(const SecureBuffer& current_plaintext, size_t index_to_remove) {
    if (current_plaintext.size() == 0) {
        throw std::out_of_range("Vault is empty.");
    }

    const char* src = reinterpret_cast<const char*>(current_plaintext.data_ptr());
    size_t total_bytes = current_plaintext.size();

    size_t current_index = 0;
    size_t new_size = 0;
    bool found = false;

    size_t line_start = 0;
    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t content_len = i - line_start;                      // esclude '\n', combacia con list_vault_summary
            size_t line_len = content_len + (i < total_bytes ? 1 : 0); // include '\n' per il conteggio byte
            if (content_len > 0) {
                if (current_index == index_to_remove) {
                    found = true;
                } else {
                    new_size += line_len;
                }
                current_index++;
            } else if (i < total_bytes) {
                new_size += line_len; 
            }
            line_start = i + 1;
        }
    }

    if (!found) {
        throw std::out_of_range("Invalid entry index.");
    }

    SecureBuffer new_plaintext(new_size);
    unsigned char* dest = new_plaintext.data_ptr();

    current_index = 0;
    line_start = 0;
    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t content_len = i - line_start;
            size_t line_len = content_len + (i < total_bytes ? 1 : 0);
            if (content_len > 0) {
                if (current_index != index_to_remove) {
                    std::memcpy(dest, src + line_start, line_len);
                    dest += line_len;
                }
                current_index++;
            } else if (i < total_bytes) {
                std::memcpy(dest, src + line_start, line_len);
                dest += line_len;
            }
            line_start = i + 1;
        }
    }

    return new_plaintext;
}

SecureBuffer modify_entry(const SecureBuffer& current_plaintext,
                         size_t index_to_modify,
                         const SecureBuffer& new_service,
                         const SecureBuffer& new_username,
                         const SecureBuffer& new_password)
{
    if (current_plaintext.size() == 0) {
        throw std::out_of_range("Vault is empty.");
    }

    validate_no_char(new_service, "Service", {';', '\n', '\r'});
    validate_no_char(new_username, "Username", {';', '\n', '\r'});
    validate_no_char(new_password, "Password", {'\n', '\r'});

    const char* src = reinterpret_cast<const char*>(current_plaintext.data_ptr());
    size_t total_bytes = current_plaintext.size();

    size_t new_entry_len = new_service.size() + 1 + new_username.size() + 1 + new_password.size() + 1;
    size_t current_index = 0;
    size_t new_size = 0;
    bool found = false;

    size_t line_start = 0;
    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t content_len = i - line_start;
            size_t line_len = content_len + (i < total_bytes ? 1 : 0);
            if (content_len > 0) {
                if (current_index == index_to_modify) {
                    found = true;
                    new_size += new_entry_len;
                } else {
                    new_size += line_len;
                }
                current_index++;
            } else if (i < total_bytes) {
                new_size += line_len;
            }
            line_start = i + 1;
        }
    }

    if (!found) {
        throw std::out_of_range("Invalid entry index.");
    }

    SecureBuffer new_plaintext(new_size);
    unsigned char* dest = new_plaintext.data_ptr();

    current_index = 0;
    line_start = 0;
    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t content_len = i - line_start;
            size_t line_len = content_len + (i < total_bytes ? 1 : 0);
            if (content_len > 0) {
                if (current_index == index_to_modify) {
                    std::memcpy(dest, new_service.data_ptr(), new_service.size());
                    dest += new_service.size();
                    *dest++ = ';';

                    std::memcpy(dest, new_username.data_ptr(), new_username.size());
                    dest += new_username.size();
                    *dest++ = ';';

                    std::memcpy(dest, new_password.data_ptr(), new_password.size());
                    dest += new_password.size();
                    *dest++ = '\n';
                } else {
                    std::memcpy(dest, src + line_start, line_len);
                    dest += line_len;
                }
                current_index++;
            } else if (i < total_bytes) {
                std::memcpy(dest, src + line_start, line_len);
                dest += line_len;
            }
            line_start = i + 1;
        }
    }

    return new_plaintext;
}

SecureBuffer read_input_secure(const char* prompt, bool hide_echo = false) {
    std::cout << prompt << std::flush;
    SecureBuffer input_buf(128);
    size_t len = 0;

    while (true) {
        char ch = hide_echo ? readChar() : static_cast<char>(std::cin.get());

        if (ch == '\n' || ch == '\r' || ch == 13 || ch == EOF) {
            if (hide_echo) std::cout << "\n";
            break;
        }

        if (ch == 127 || ch == 8) {
            if (len > 0) {
                --len;
                input_buf.data_ptr()[len] = 0;
                if (hide_echo) std::cout << "\b \b" << std::flush;
            }
            continue;
        }

        if (len == input_buf.size()) {
            input_buf = grow_buffer(std::move(input_buf));
        }
        input_buf.data_ptr()[len++] = static_cast<unsigned char>(ch);
        if (hide_echo) std::cout << '*' << std::flush;
    }

    SecureBuffer result(len);
    std::memcpy(result.data_ptr(), input_buf.data_ptr(), len);
    return result;
}

void list_vault_summary(const SecureBuffer& plaintext) {
    if (plaintext.size() == 0) {
        std::cout << "\n[!] Vault is empty.\n";
        return;
    }

    const char* src = reinterpret_cast<const char*>(plaintext.data_ptr());
    size_t total_bytes = plaintext.size();
    size_t line_start = 0;
    size_t index = 0;

    std::cout << "\n=== VAULT CREDENTIALS ===\n";

    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t line_len = i - line_start;
            if (line_len > 0) {
                std::string_view line(src + line_start, line_len);
                size_t delim1 = line.find(';');
                size_t delim2 = (delim1 != std::string_view::npos) ? line.find(';', delim1 + 1) : std::string_view::npos;

                if (delim1 != std::string_view::npos && delim2 != std::string_view::npos) {
                    std::cout << index << ") Service: ";
                    std::cout.write(line.data(), delim1);
                    std::cout << " | Username: ";
                    std::cout.write(line.data() + delim1 + 1, delim2 - delim1 - 1);
                    std::cout << "\n";
                }
                index++;
            }
            line_start = i + 1;
        }
    }
}

void reveal_password(const SecureBuffer& plaintext, size_t target_index) {
    const char* src = reinterpret_cast<const char*>(plaintext.data_ptr());
    size_t total_bytes = plaintext.size();
    size_t line_start = 0;
    size_t current_index = 0;

    for (size_t i = 0; i <= total_bytes; ++i) {
        if (i == total_bytes || src[i] == '\n') {
            size_t line_len = i - line_start;
            if (line_len > 0) {
                if (current_index == target_index) {
                    std::string_view line(src + line_start, line_len);
                    size_t delim1 = line.find(';');
                    size_t delim2 = (delim1 != std::string_view::npos) ? line.find(';', delim1 + 1) : std::string_view::npos;

                    if (delim2 != std::string_view::npos) {
                        std::cout << "Password: ";
                        for (size_t p = delim2 + 1; p < line_len; ++p) {
                            std::putchar(line[p]);
                        }
                        std::putchar('\n');
                        std::fflush(stdout);
                        return;
                    }
                }
                current_index++;
            }
            line_start = i + 1;
        }
    }
    std::cout << "[!] Invalid index.\n";
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium.\n";
        return 1;
    }

    const std::string vault_path = "vault.db";
    SecureBuffer salt(16);
    SecureBuffer plaintext(0);
    SecureBuffer vault_file(0);
    bool vault_loaded = false;

    std::cout << "=== SECURE VAULT MANAGER ===\n";
    SecureBuffer masterPass = capture_master_key();
    std::cout << "\n";

    try {
        vault_file = read_vault_file(vault_path);
        const size_t min_vault_size = 16 /* salt */
                                     + crypto_secretbox_NONCEBYTES
                                     + crypto_secretbox_MACBYTES;
        if (vault_file.size() < min_vault_size) {
            throw std::runtime_error("Vault file is too small or corrupted.");
        }
        std::memcpy(salt.data_ptr(), vault_file.data_ptr(), salt.size());
        vault_loaded = true;
    }
    catch (const std::exception& e) {
        std::ifstream check(vault_path);
        if (!check.good()) {
            std::cout << "[i] No vault found. Creating a new vault...\n";
            randombytes_buf(salt.data_ptr(), salt.size());
        } else {
            std::cerr << "[!] Error: " << e.what() << "\n";
            return 1;
        }
    }

    SecureBuffer derived_key = derive_key(masterPass, salt);
    masterPass = SecureBuffer(0);

    if (vault_loaded) {
        try {
            plaintext = decrypt_vault(vault_file, derived_key);
            std::cout << "[+] Vault decrypted successfully.\n";
        } catch (const std::exception& e) {
            std::cerr << "[!] Error: " << e.what() << "\n";
            return 1;
        }
    }

    bool running = true;
    bool dirty = false;

    while (running) {
        std::cout << "\n--- MENU ---\n"
                  << "1. List credentials\n"
                  << "2. Show password\n"
                  << "3. Add entry\n"
                  << "4. Edit entry\n"
                  << "5. Remove entry\n"
                  << "6. Save and exit\n"
                  << "7. Exit without saving\n"
                  << "Choice: ";

        int choice = 0;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                list_vault_summary(plaintext);
                break;

            case 2: {
                list_vault_summary(plaintext);
                std::cout << "Entry index: ";
                size_t idx;
                if (std::cin >> idx) {
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    reveal_password(plaintext, idx);
                } else {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                }
                break;
            }

            case 3: {
                SecureBuffer s = read_input_secure("Service: ");
                SecureBuffer u = read_input_secure("Username: ");
                SecureBuffer p = read_input_secure("Password: ", true);

                try {
                    plaintext = add_entry(plaintext, s, u, p);
                    dirty = true;
                    std::cout << "[+] Entry added in memory.\n";
                } catch (const std::exception& e) {
                    std::cerr << "[!] Error: " << e.what() << "\n";
                }
                break;
            }

            case 4: {
                list_vault_summary(plaintext);
                std::cout << "Entry index to edit: ";
                size_t idx;
                if (std::cin >> idx) {
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    SecureBuffer s = read_input_secure("New Service: ");
                    SecureBuffer u = read_input_secure("New Username: ");
                    SecureBuffer p = read_input_secure("New Password: ", true);

                    try {
                        plaintext = modify_entry(plaintext, idx, s, u, p);
                        dirty = true;
                        std::cout << "[+] Entry updated in memory.\n";
                    } catch (const std::exception& e) {
                        std::cerr << "[!] Error: " << e.what() << "\n";
                    }
                }
                break;
            }

            case 5: {
                list_vault_summary(plaintext);
                std::cout << "Entry index to remove: ";
                size_t idx;
                if (std::cin >> idx) {
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    try {
                        plaintext = remove_entry(plaintext, idx);
                        dirty = true;
                        std::cout << "[+] Entry removed from memory.\n";
                    } catch (const std::exception& e) {
                        std::cerr << "[!] Error: " << e.what() << "\n";
                    }
                } else {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                }
                break;
            }

            case 6: {
                try {
                    SecureBuffer encrypted_vault = encrypt_vault(salt, plaintext, derived_key);
                    write_vault_file_atomic(vault_path, encrypted_vault);
                    std::cout << "[+] Vault saved to disk successfully.\n";
                    running = false;
                } catch (const std::exception& e) {
                    std::cerr << "[!] Save error: " << e.what() << "\n";
                }
                break;
            }

            case 7:
                if (dirty) {
                    std::cout << "[!] Warning: you have unsaved changes. Exit anyway? (y/n): ";
                    char c;
                    std::cin >> c;
                    if (c == 'y' || c == 'Y') running = false;
                } else {
                    running = false;
                }
                break;

            default:
                std::cout << "[!] Invalid choice.\n";
                break;
        }
    }

    std::cout << "Closing. Wiping memory...\n";
    return 0;
}
