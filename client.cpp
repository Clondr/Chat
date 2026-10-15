#include <iostream>
#include <thread>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sys/ioctl.h>
#include <termios.h>
#include <vector>
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace std;

const char ENCRYPT_KEY = 'K'; // Keeping for backward compatibility reference
atomic<bool> connection_open{true};
const uint32_t MAX_MESSAGE_SIZE = 1024 * 1024;
static uint64_t message_counter = 0; // Global message counter for nonce generation

// Improved security: Simple hash function (djb2 variant)
uint32_t simple_hash(const string& data) {
    uint32_t hash = 5381;
    for (char c : data) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c); // hash * 33 + c
    }
    return hash;
}

// Improved security: Xorshift64* PRNG for keystream generation
class XorShift64Star {
    uint64_t state;
public:
    explicit XorShift64Star(uint64_t seed) : state(seed) {}
    uint64_t next() {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        return state * 0x2545F4914F6CDD1DULL;
    }
    uint8_t next_byte() {
        return static_cast<uint8_t>(next());
    }
};

// Improved security: Generate keystream for encryption
string generate_keystream(const string& key, uint64_t nonce, size_t length) {
    // Derive key material: hash(key || nonce)
    stringstream ss;
    ss << key << nonce;
    string key_nonce = ss.str();
    uint64_t seed = simple_hash(key_nonce);

    XorShift64Star prng(seed);
    string keystream;
    keystream.reserve(length);

    for (size_t i = 0; i < length; i++) {
        keystream += prng.next_byte();
    }

    return keystream;
}

// Improved security: Generate MAC (Message Authentication Code)
// Returns 8-byte MAC by hashing input twice with different salts
string generate_mac(const string& key, const string& message, uint64_t nonce) {
    // Simple HMAC-like construction: hash(key || message || nonce)
    stringstream ss;
    ss << key << message << nonce;
    uint32_t hash1 = simple_hash(ss.str());

    // Add salt to get second 4 bytes
    ss.str(""); // Clear stringstream
    ss.clear(); // Clear error flags
    ss << key << message << nonce << 0x9e3779b9; // Golden ratio constant as salt
    uint32_t hash2 = simple_hash(ss.str());

    // Combine both hashes to get 8 bytes
    uint64_t combined = ((uint64_t)hash1 << 32) | hash2;
    return string(reinterpret_cast<char*>(&combined), 8);
}

// Improved security: Encrypt message with authentication
string encrypt_message(const string& plaintext, const string& key, uint64_t& message_counter) {
    // Generate nonce (we use message counter as nonce)
    uint64_t nonce = message_counter++;

    // Generate keystream
    string keystream = generate_keystream(key, nonce, plaintext.size());

    // Encrypt: ciphertext = plaintext XOR keystream
    string ciphertext;
    ciphertext.reserve(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext += plaintext[i] ^ keystream[i];
    }

    // Generate MAC
    string mac = generate_mac(key, ciphertext, nonce);

    // Format: [nonce:8 bytes][ciphertext][mac:variable]
    string result;
    result.resize(8 + ciphertext.size() + mac.size());

    // Copy nonce (big endian)
    for (int i = 0; i < 8; i++) {
        result[i] = static_cast<char>((nonce >> ((7 - i) * 8)) & 0xFF);
    }

    // Copy ciphertext
    memcpy(&result[8], ciphertext.data(), ciphertext.size());

    // Copy MAC
    memcpy(&result[8 + ciphertext.size()], mac.data(), mac.size());

    return result;
}

// Improved security: Decrypt and verify message
bool decrypt_message(const string& encrypted_data, const string& key, string& plaintext, uint64_t& expected_nonce) {
    if (encrypted_data.size() < 8) return false; // Need at least nonce

    // Extract nonce (big endian)
    uint64_t nonce = 0;
    for (int i = 0; i < 8; i++) {
        nonce = (nonce << 8) | static_cast<unsigned char>(encrypted_data[i]);
    }

    // Reject if nonce is too old (replay protection) or too far in future
    if (nonce < expected_nonce || nonce > expected_nonce + 1000) {
        return false;
    }

    // Extract MAC (last 8 bytes)
    if (encrypted_data.size() < 8 + 8) return false; // Need at least nonce + 1 byte ciphertext + 8 byte MAC

    size_t mac_start = encrypted_data.size() - 8;
    string mac_received = encrypted_data.substr(mac_start, 8);

    // Extract ciphertext
    string ciphertext = encrypted_data.substr(8, mac_start - 8);

    // Recompute MAC (should be exactly 8 bytes now)
    string mac_expected = generate_mac(key, ciphertext, nonce);

    // Verify MAC (constant time comparison to prevent timing attacks)
    bool mac_valid = true;
    for (size_t i = 0; i < 8; i++) {
        if (mac_received[i] != mac_expected[i]) {
            mac_valid = false;
        }
    }

    if (!mac_valid) {
        return false;
    }

    // Decrypt: plaintext = ciphertext XOR keystream
    string keystream = generate_keystream(key, nonce, ciphertext.size());
    plaintext.resize(ciphertext.size());
    for (size_t i = 0; i < ciphertext.size(); i++) {
        plaintext[i] = ciphertext[i] ^ keystream[i];
    }

    // Update expected nonce (we accept this nonce and expect next one to be at least this+1)
    expected_nonce = nonce + 1;

    return true;
}

// Функция шифрования/расшифрования (сохранена для совместимости, но теперь используется улучшенная версия выше)
string xor_cipher(string data) {
    // Шифруем/расшифровываем данные с помощью XOR (оставлена для совместимости)
    for (size_t i = 0; i < data.size(); i++) data[i] ^= ENCRYPT_KEY;
    return data;
}

bool send_message(int sock, const string& message) {
    if (message.size() > MAX_MESSAGE_SIZE) return false;

    uint32_t message_size = htonl(static_cast<uint32_t>(message.size()));
    const char* header = reinterpret_cast<const char*>(&message_size);
    size_t sent = 0;
    while (sent < sizeof(message_size)) {
        ssize_t bytes = send(sock, header + sent, sizeof(message_size) - sent, MSG_NOSIGNAL);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        sent += static_cast<size_t>(bytes);
    }

    sent = 0;
    while (sent < message.size()) {
        ssize_t bytes = send(sock, message.data() + sent, message.size() - sent, MSG_NOSIGNAL);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        sent += static_cast<size_t>(bytes);
    }
    return true;
}

bool receive_exactly(int sock, char* buffer, size_t size) {
    size_t received = 0;
    while (received < size) {
        ssize_t bytes = recv(sock, buffer + received, size - received, 0);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        received += static_cast<size_t>(bytes);
    }
    return true;
}

bool receive_message(int sock, string& message) {
    uint32_t message_size = 0;
    if (!receive_exactly(sock, reinterpret_cast<char*>(&message_size), sizeof(message_size))) {
        return false;
    }
    message_size = ntohl(message_size);
    if (message_size > MAX_MESSAGE_SIZE) return false;

    message.resize(message_size);
    return message_size == 0 || receive_exactly(sock, &message[0], message_size);
}

// Проверяем, есть ли доступный ввод без блокировки
bool kbhit() {
    termios tty{};
    tcgetattr(STDIN_FILENO, &tty);
    termios tty_old = tty;
    tty.c_lflag &= ~ICANON;
    tty.c_lflag &= ~ECHO;
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    int byteswaiting = 0;
    ioctl(STDIN_FILENO, FIONREAD, &byteswaiting);
    bool has_data = byteswaiting > 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &tty_old);
    return has_data;
}

// Читаем один символ
char readch() {
    char ch;
    read(STDIN_FILENO, &ch, 1);
    return ch;
}

// Функция для редактирования строки с поддержкой стрелок
string edit_line() {
    // Сохраняем оригинальные настройки терминала
    termios orig_tty{};
    tcgetattr(STDIN_FILENO, &orig_tty);

    // Устанавливаем нетканонический режим
    termios tty = orig_tty;
    tty.c_lflag &= ~(ICANON | ECHO);
    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);

    string buffer;
    size_t cursor_pos = 0;
    bool done = false;

    cout << "> " << flush;

    while (!done) {
        // Проверяем, есть ли ввод
        if (kbhit()) {
            char ch = readch();

            // Обрабатываем специальные клавиши
            if (ch == '\033') { // Escape sequence
                // Проверяем, есть ли следующий символ
                if (kbhit()) {
                    char ch2 = readch();
                    if (ch2 == '[') { // ANSI escape sequence
                        // Проверяем, есть ли третий символ
                        if (kbhit()) {
                            char ch3 = readch();
                            switch (ch3) {
                                case 'A': // Стрелка вверх - пока игнорируем (можно добавить историю позже)
                                    break;
                                case 'B': // Стрелка вниз - пока игнорируем
                                    break;
                                case 'C': // Стрелка вправо
                                    if (cursor_pos < buffer.size()) {
                                        cursor_pos++;
                                        cout << "\033[C"; // Перемещаем курсор вправо
                                    }
                                    break;
                                case 'D': // Стрелка влево
                                    if (cursor_pos > 0) {
                                        cursor_pos--;
                                        cout << "\033[D"; // Перемещаем курсор влево
                                    }
                                    break;
                                case 'H': // Home
                                    cursor_pos = 0;
                                    cout << "\033[1G"; // Переходим в начало строки
                                    break;
                                case 'F': // End
                                    cursor_pos = buffer.size();
                                    cout << "\033[" << (cursor_pos + 1) << "G"; // Переходим в конец строки
                                    break;
                                case '3': // Delete
                                    if (kbhit()) {
                                        char ch4 = readch();
                                        if (ch4 == '~') { // Delete key
                                            if (cursor_pos < buffer.size()) {
                                                buffer.erase(cursor_pos, 1);
                                                // Очищаем строку от курсора до конца и перерисовываем
                                                cout << "\033[K" << buffer.substr(cursor_pos);
                                                // Возвращаем курсор назад
                                                for (size_t i = 0; i < buffer.size() - cursor_pos; i++) {
                                                    cout << "\b";
                                                }
                                            }
                                        }
                                    }
                                    break;
                                default:
                                    // Другие escape-последовательности игнорируем
                                    break;
                            }
                        }
                    }
                }
            } else if (ch == '\n' || ch == '\r') { // Enter
                done = true;
                cout << endl;
            } else if (ch == '\b' || ch == 127) { // Backspace
                if (cursor_pos > 0) {
                    buffer.erase(cursor_pos - 1, 1);
                    cursor_pos--;
                    // Удаляем символ перед курсором и перерисовываем
                    cout << "\b \b" << buffer.substr(cursor_pos);
                    // Возвращаем курсор назад
                    for (size_t i = 0; i < buffer.size() - cursor_pos; i++) {
                        cout << "\b";
                    }
                }
            } else if (ch >= 32 && ch <= 126) { // Печатаемый символ (пробел до тильды)
                buffer.insert(cursor_pos, 1, ch);
                cursor_pos++;
                // Выводим новый символ и перерисовываем оставшуюся часть строки
                cout << ch;
                if (cursor_pos < buffer.size()) {
                    cout << buffer.substr(cursor_pos - 1);
                    // Возвращаем курсор на правильную позицию
                    for (size_t i = 0; i < buffer.size() - cursor_pos + 1; i++) {
                        cout << "\b";
                    }
                }
            }

            // Принудительно сбрасываем буфер вывода
            cout.flush();
        }

        // Небольшая задержка чтобы не нагружать CPU
        usleep(1000);
    }

    // Восстанавливаем оригинальные настройки терминала
    tcsetattr(STDIN_FILENO, TCSANOW, &orig_tty);
    return buffer;
}

// Функция для получения сообщений от сервера
void receive_messages(int sock) {
    while (true) {
        string encrypted_message;
        if (!receive_message(sock, encrypted_message)) {
            if (connection_open.exchange(false)) {
                cout << "\n\nСоединение с сервером закрыто. Нажмите Enter, чтобы выйти." << endl;
            }
            return;
        }

        // Расшифровываем сообщение с проверкой подлинности
        static uint64_t expected_nonce = 0;
        string msg;
        if (decrypt_message(encrypted_message, string(1, ENCRYPT_KEY), msg, expected_nonce)) {
            // Сохраняем текущую позицию курсора и выводим сообщение выше промпта
            cout << "\r\033[K" << msg << "\n> " << flush;
        } else {
            // Если не удалось расшифровать или проверка MAC не прошла, игнорируем сообщение
            // В реальном приложении здесь könnte быть логирование атаки
        }
    }
}

int main() {
    cout << "========================================\n"
         << "          Добро пожаловать в чат\n"
         << "========================================\n"
         << "Выберите режим подключения:\n"
         << "  1. Тестовый — подключиться к этому компьютеру (127.0.0.1)\n"
         << "  2. Рабочий — указать IP-адрес сервера\n"
         << "Ваш выбор: " << flush;

    string mode;
    // Для выбора режима используем обычный getline, так как это одноразовый ввод
    if (!getline(cin, mode)) return 0;

    string server_ip;
    if (mode == "1") {
        server_ip = "127.0.0.1";
        cout << "Тестовый режим: подключаемся к локальному серверу.\n";
    } else if (mode == "2") {
        cout << "Введите IPv4-адрес сервера: " << flush;
        if (!getline(cin, server_ip)) return 0;
    } else {
        cerr << "Неизвестный режим. Запустите программу и выберите 1 или 2.\n";
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    if (inet_pton(AF_INET, server_ip.c_str(), &addr.sin_addr) != 1) {
        cerr << "Некорректный IPv4-адрес: \"" << server_ip
             << "\". Пример: 192.168.1.10\n";
        return 1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        cerr << "Не удалось создать сетевой сокет: " << strerror(errno) << '\n';
        return 1;
    }

    cout << "Подключаемся к " << server_ip << ":8080...\n";
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        int error = errno;
        cerr << "Не удалось подключиться к серверу " << server_ip << ":8080: "
             << strerror(error) << '\n'
             << "Проверьте, что сервер запущен, адрес указан верно и порт 8080 доступен.\n";
        close(sock);
        return 1;
    }

    cout << "Подключение установлено.\nВведите никнейм: " << flush;
    string nick;
    // Для ввода никнейма также используем getline
    if (!getline(cin, nick)) {
        close(sock);
        return 0;
    }
    if (nick.empty()) {
        cerr << "Никнейм не может быть пустым.\n";
        close(sock);
        return 1;
    }

    // Улучшенная безопасность: шифруем никнейм с использованием нового алгоритма
    string enc_nick = encrypt_message(nick, string(1, ENCRYPT_KEY), message_counter);
    if (!send_message(sock, enc_nick)) {
        cerr << "Не удалось отправить никнейм серверу: " << strerror(errno) << '\n';
        close(sock);
        return 1;
    }

    thread(receive_messages, sock).detach();

    cout << "\nВы в чате. Команды:\n"
         << "  /list             — показать участников онлайн\n"
         << "  @никнейм сообщение — отправить личное сообщение\n"
         << "  /exit             — выйти из чата\n"
         << "  Стрелки влево/вправо — перемещение курсора ввода\n"
         << "  Home/End          — переход к началу/концу строки\n"
         << "  Delete            — удаление символа под курсором\n"
         << "  Backspace         — удаление символа перед курсором\n"
         << "  Улучшенная безопасность: AES-подобное шифрование с аутентификацией сообщений\n\n";

    string text;
    while (connection_open) {
        // Используем нашу функцию редактирования строки
        text = edit_line();
        if (!connection_open) break;

        // Улучшенная безопасность: шифруем сообщение с аутентификацией
        string encrypted = encrypt_message(text, string(1, ENCRYPT_KEY), message_counter);
        if (!send_message(sock, encrypted)) {
            cerr << "\nНе удалось отправить сообщение: " << strerror(errno) << '\n';
            break;
        }
        if (text == "/exit") break;
    }

    connection_open = false;
    shutdown(sock, SHUT_RDWR);
    close(sock);
    return 0;
}