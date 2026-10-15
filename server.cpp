#include <iostream>
#include <vector>
#include <thread> // For handling multiple clients concurrently
#include <mutex>
#include <map>
#include <fstream>
#include <cerrno>
#include <cstdint>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iomanip>
#include <ctime> // For time formatting
#include <sstream> // For stringstream
#include <cstring> // For memcpy

using namespace std;

map<int,  string> clients;
map<int, uint64_t> server_nonces;
mutex mtx;
ofstream history_file;
const char ENCRYPT_KEY = 'K';
const uint32_t MAX_MESSAGE_SIZE = 1024 * 1024;
mutex send_mtx;

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

bool send_message(int socket_fd, const string& message) {
    if (message.size() > MAX_MESSAGE_SIZE) return false;

    lock_guard<mutex> lock(send_mtx);
    uint32_t message_size = htonl(static_cast<uint32_t>(message.size()));
    const char* header = reinterpret_cast<const char*>(&message_size);
    size_t sent = 0;
    while (sent < sizeof(message_size)) {
        ssize_t bytes = send(socket_fd, header + sent, sizeof(message_size) - sent, MSG_NOSIGNAL);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        sent += static_cast<size_t>(bytes);
    }

    sent = 0;
    while (sent < message.size()) {
        ssize_t bytes = send(socket_fd, message.data() + sent, message.size() - sent, MSG_NOSIGNAL);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        sent += static_cast<size_t>(bytes);
    }
    return true;
}

bool receive_exactly(int socket_fd, char* buffer, size_t size) {
    size_t received = 0;
    while (received < size) {
        ssize_t bytes = recv(socket_fd, buffer + received, size - received, 0);
        if (bytes < 0 && errno == EINTR) continue;
        if (bytes <= 0) return false;
        received += static_cast<size_t>(bytes);
    }
    return true;
}

bool receive_message(int socket_fd, string& message) {
    uint32_t message_size = 0;
    if (!receive_exactly(socket_fd, reinterpret_cast<char*>(&message_size), sizeof(message_size))) {
        return false;
    }
    message_size = ntohl(message_size);
    if (message_size > MAX_MESSAGE_SIZE) return false;

    message.resize(message_size);
    return message_size == 0 || receive_exactly(socket_fd, &message[0], message_size);
}

// Функция для получения текущего времени в формате строки
string get_current_time() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    tm now_tm = *localtime(&now_time);

    stringstream ss;
    ss << put_time(&now_tm, "%H:%M:%S");
    return ss.str();
}

void log_and_broadcast( string msg, int sender_fd, bool save = true) {
    if (save) {
        lock_guard< mutex> lock(mtx);
        if (history_file.is_open()) {
            string timestamp = get_current_time();
            history_file << "[" << timestamp << "] " << msg << endl;
            history_file.flush(); // Ensure immediate write to file
        }
    }

    lock_guard< mutex> lock(mtx);
    for (map<int, string>::iterator it = clients.begin(); it != clients.end(); ++it) {
        if (it->first != sender_fd) {
            string encrypted_msg = encrypt_message(
                msg, string(1, ENCRYPT_KEY), server_nonces[it->first]);
            send_message(it->first, encrypted_msg);
        }
    }
}

void handle_client(int client_fd) {
    // Улучшенная безопасность: каждый клиент имеет свой счетчик сообщений для предотвращения атак повтора
    static map<int, uint64_t> client_nonces;
    static mutex nonce_mutex;

    // Инициализируем счетчик для этого клиента
    {
        lock_guard<mutex> lock(nonce_mutex);
        client_nonces[client_fd] = 0;
    }

    // Получаем никнейм (первое сообщение от клиента зашифровано)
    string encrypted_nickname;
    if (!receive_message(client_fd, encrypted_nickname)) {
        close(client_fd);
        return;
    }

    // Расшифровываем никнейм
    string nickname;
    {
        lock_guard<mutex> lock(nonce_mutex);
        if (!decrypt_message(encrypted_nickname, string(1, ENCRYPT_KEY), nickname, client_nonces[client_fd])) {
            close(client_fd);
            return;
        }
    }

    {
        lock_guard< mutex> lock(mtx);
        clients[client_fd] = nickname;
        server_nonces[client_fd] = 0;
        cout << "[" << get_current_time() << "] Подключился участник: " << nickname << endl;
    }

    log_and_broadcast(">>> " + nickname + " вошел в чат", client_fd);

    while (true) {
        string encrypted_content;
        if (!receive_message(client_fd, encrypted_content)) break;

        // Расшифровываем сообщение
        string content;
        {
            lock_guard<mutex> lock(nonce_mutex);
            if (!decrypt_message(encrypted_content, string(1, ENCRYPT_KEY), content, client_nonces[client_fd])) {
                // Если не удалось расшифровать, прерываем соединение
                break;
            }
        }

        if (content == "/exit") break;

        if (content == "/list") {
            string list_msg = "В сети: ";
            lock_guard< mutex> lock(mtx);
            for (map<int, string>::iterator it = clients.begin(); it != clients.end(); ++it) {
                list_msg += it->second + " ";
            }
            string encrypted_list = encrypt_message(
                list_msg, string(1, ENCRYPT_KEY), server_nonces[client_fd]);
            send_message(client_fd, encrypted_list);
            continue;
        }

        if (!content.empty() && content[0] == '@') {
            size_t space_pos = content.find(' ');
            if (space_pos !=  string::npos) {
                string target_name = content.substr(1, space_pos - 1);
                string p_msg = content.substr(space_pos + 1);
                bool sent_private = false;
                {
                    lock_guard< mutex> lock(mtx);
                    for (map<int, string>::iterator it = clients.begin(); it != clients.end(); ++it) {
                        if (it->second == target_name) {
                            string formatted = "[Шепот от " + nickname + "]: " + p_msg;
                            string enc_p = encrypt_message(
                                formatted, string(1, ENCRYPT_KEY), server_nonces[it->first]);
                            send_message(it->first, enc_p);
                            sent_private = true;
                            break;
                        }
                    }
                }
                if (sent_private) continue;
            }
        }

        log_and_broadcast(nickname + ": " + content, client_fd);
    }

    string name;
    {
        lock_guard< mutex> lock(mtx);
        map<int, string>::iterator it = clients.find(client_fd);
        if (it != clients.end()) {
            name = it->second;
            clients.erase(it);
            server_nonces.erase(client_fd);
        }

        // Очищаем счетчик nonce для этого клиента
        {
            lock_guard<mutex> lock(nonce_mutex);
            client_nonces.erase(client_fd);
        }

        close(client_fd);
        if (!name.empty()) cout << "[" << get_current_time() << "] Участник отключился: " << name << endl;
    }
    if (!name.empty()) {
        log_and_broadcast("<<< " + name + " покинул чат", -1);
    }
}

int main() {
    history_file.open("history.txt",  ios::app);
    if (!history_file.is_open()) {
        cerr << "Не удалось открыть history.txt для записи истории чата.\n";
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        cerr << "Не удалось создать серверный сокет: " << strerror(errno) << '\n';
        return 1;
    }

    int reuse_address = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address,
                   sizeof(reuse_address)) < 0) {
        cerr << "Не удалось настроить повторное использование порта: "
             << strerror(errno) << '\n';
        close(server_fd);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        cerr << "Не удалось занять порт 8080: " << strerror(errno)
             << ". Возможно, сервер уже запущен.\n";
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 10) < 0) {
        cerr << "Не удалось начать прослушивание порта 8080: "
             << strerror(errno) << '\n';
        close(server_fd);
        return 1;
    }

    cout << "========================================\n"
         << "             Сервер чата\n"
         << "========================================\n"
         << "Статус: запущен\n"
         << "Порт: 8080 (прослушиваются все сетевые интерфейсы)\n"
         << "История сообщений: history.txt (с таймстампами)\n"
         << "Шифрование: Улучшенная безопасность с аутентификацией и защитой от атак повтора\n"
         << "Для остановки нажмите Ctrl+C.\n\n";

    while (true) {
        int c_fd = accept(server_fd, nullptr, nullptr);
        if (c_fd < 0) {
            if (errno == EINTR) continue;
            cerr << "Ошибка при ожидании подключения: " << strerror(errno) << '\n';
            continue;
        }
        // Создаем отдельный поток для обработки каждого клиента
        thread(handle_client, c_fd).detach();
    }
    return 0;
}