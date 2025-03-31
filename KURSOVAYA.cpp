#include <iostream>
#include <filesystem>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <openssl/sha.h>
#include <fstream>
#include <chrono>
#include <system_error>

using namespace std;
atomic<bool> shouldStop{false};

// Добавить класс конфигурации
class Config {
public:
    filesystem::path watchDirectory;
    int checkInterval;
    size_t scanThreads;
    bool verboseLogging;
    
    static Config loadFromFile(const filesystem::path& configPath) {
         Config config;
    config.watchDirectory = "./test_files";
    config.checkInterval = 5;
    config.scanThreads = thread::hardware_concurrency();
    config.verboseLogging = true;
    return config;
    }
};

// Улучшенное логгирование
class Logger {
    mutex logMtx;
    bool verbose;
public:
    Logger(bool verbose) : verbose(verbose) {}
    
    void log(const string& message) {
        lock_guard<mutex> lock(logMtx);
        cout << "[INFO] " << message << endl;
    }
    
    void error(const string& message) {
        lock_guard<mutex> lock(logMtx);
        cerr << "[ERROR] " << message << endl;
    }
    
    void debug(const string& message) {
        if (verbose) {
            lock_guard<mutex> lock(logMtx);
            cout << "[DEBUG] " << message << endl;
        }
    }
};

class FileMonitorException : public runtime_error {
public:
    using runtime_error::runtime_error;
};

class FileHashException : public FileMonitorException {
public:
    using FileMonitorException::FileMonitorException;
};

// 1. Модуль сканирования и хэширования
class FileHasher {
public:
    static string calculateSHA256(const filesystem::path& filepath) {
        try {
            ifstream file(filepath, ios::binary);
            if (!file) {
                throw FileHashException("Cannot open file: " + filepath.string());
            }

            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256_CTX sha256;
            if (!SHA256_Init(&sha256)) {
                throw FileHashException("SHA256 initialization failed");
            }

            char buffer[4096];
            while (file.read(buffer, sizeof(buffer))) {
                if (!SHA256_Update(&sha256, buffer, file.gcount())) {
                    throw FileHashException("SHA256 update failed");
                }
            }

            if (!file.eof() && file.fail()) {
                throw FileHashException("Error reading file: " + filepath.string());
            }

            if (!SHA256_Final(hash, &sha256)) {
                throw FileHashException("SHA256 finalization failed");
            }

            string result;
    result.reserve(SHA256_DIGEST_LENGTH * 2); // Предварительное выделение памяти
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned char i : hash) {
        result += hex[i >> 4];
        result += hex[i & 0x0F];
    }
    return result;
        } catch (const exception& e) {
            throw FileHashException(string("Failed to calculate hash: ") + e.what());
        }
    }
};

// 2. Хранилище состояний и мониторинг
class FileMonitor {
private:
    unordered_map<string, string> fileHashes;
    mutex mtx;
    atomic<bool> running{false};
    thread monitorThread;
    Logger logger;
    Config config;

void safeAddFile(const filesystem::path& path) {
        try {
            string hash = FileHasher::calculateSHA256(path);
            lock_guard<mutex> lock(mtx);
            fileHashes[path.string()] = hash;
            cout << "Added: " << path << " [Hash: " << hash << "]\n";
        } catch (const FileHashException& e) {
            cerr << "Error adding file " << path << ": " << e.what() << endl;
        }
    }

public:
 FileMonitor(const Config& cfg) : config(cfg), logger(cfg.verboseLogging) {}
    
    void startMonitoring() {
        try {
            if (!filesystem::exists(config.watchDirectory)) {
                throw FileMonitorException("Directory does not exist: " + config.watchDirectory.string());
            }

            running = true;
            logger.log("Starting monitoring of: " + config.watchDirectory.string());
            
            if (config.scanThreads > 1) {
                parallelScanDirectory(config.watchDirectory, config.scanThreads);
            } else {
                scanDirectory(config.watchDirectory);
            }
            
            monitorThread = thread([this]() {
                while (running) {
                    auto start = chrono::steady_clock::now();
                    
                    try {
                        checkForChanges();
                    } catch (const exception& e) {
                        logger.error("Error in monitoring thread: " + string(e.what()));
                    }
                    
                    auto end = chrono::steady_clock::now();
                    auto elapsed = chrono::duration_cast<chrono::milliseconds>(end - start);
                    auto sleepTime = chrono::milliseconds(config.checkInterval * 1000) - elapsed;
                    
                    if (sleepTime.count() > 0) {
                        this_thread::sleep_for(sleepTime);
                    } else {
                        logger.debug("Monitoring iteration took longer than interval");
                    }
                }
            });
            
            logger.log("Monitoring started successfully");
        } catch (const exception& e) {
            running = false;
            throw FileMonitorException(string("Monitoring start failed: ") + e.what());
        }
    }
    void addFile(const filesystem::path& path) {
        safeAddFile(path);
    }



// Добавить проверку на символические ссылки для предотвращения циклов
void scanDirectory(const filesystem::path& dir) {
    try {
        for (const auto& entry : filesystem::recursive_directory_iterator(dir)) {
            try {
                if (entry.is_symlink()) {
                    cerr << "Skipping symlink: " << entry.path() << endl;
                    continue;
                }
                if (entry.is_regular_file()) {
                    safeAddFile(entry.path());
                }
            } catch (const filesystem::filesystem_error& e) {
                cerr << "Filesystem error processing " << entry.path() << ": " << e.what() << endl;
            }
        }
    } catch (const exception& e) {
        throw FileMonitorException(string("Directory scan failed: ") + e.what());
    }
}

// Добавить возможность параллельного хэширования файлов
void parallelScanDirectory(const filesystem::path& dir, size_t threadCount = thread::hardware_concurrency()) {
    // 1. Сбор всех файлов
    vector<filesystem::path> files;
    try {
        for (const auto& entry : filesystem::recursive_directory_iterator(dir)) {
            try {
                if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            } catch (const filesystem::filesystem_error& e) {
                logger.error("Skipping inaccessible file: " + string(e.path1().string()) + 
                           " - " + e.what());
            }
        }
    } catch (const exception& e) {
        throw FileMonitorException("Failed to list directory: " + string(e.what()));
    }

    // 2. Оптимизация для малого количества файлов
    if (files.empty()) {
        logger.debug("No files found in directory");
        return;
    }
    if (files.size() < threadCount * 4) { // Эмпирическое правило
        threadCount = max(size_t(1), (files.size() + 3) / 4);
        logger.debug("Reduced thread count to " + to_string(threadCount) + 
                    " for " + to_string(files.size()) + " files");
    }

    // 3. Подготовка результатов
    vector<string> hashes(files.size());
    vector<exception_ptr> exceptions(threadCount, nullptr);
    
    // 4. Параллельное хеширование
    vector<thread> workers;
    size_t filesPerThread = (files.size() + threadCount - 1) / threadCount;

    for (size_t i = 0; i < threadCount; ++i) {
        workers.emplace_back([this, i, filesPerThread, &files, &hashes, &exceptions]() {
            size_t start = i * filesPerThread;
            size_t end = min(start + filesPerThread, files.size());
            
            try {
                for (size_t j = start; j < end; ++j) {
                    hashes[j] = FileHasher::calculateSHA256(files[j]);
                }
            } catch (...) {
                exceptions[i] = current_exception();
            }
        });
    }

    // 5. Ожидание завершения и обработка ошибок
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }

    // 6. Проверка ошибок в потоках
    for (size_t i = 0; i < exceptions.size(); ++i) {
        if (exceptions[i]) {
            try {
                rethrow_exception(exceptions[i]);
            } catch (const exception& e) {
                logger.error("Thread " + to_string(i) + " failed: " + e.what());
                throw FileMonitorException("Parallel hashing failed");
            }
        }
    }

    // 7. Атомарное обновление fileHashes
    {
        lock_guard<mutex> lock(mtx);
        for (size_t i = 0; i < files.size(); ++i) {
            fileHashes[files[i].string()] = move(hashes[i]);
            logger.debug("Added: " + files[i].string());
        }
    }
}

void checkForChanges() {
        lock_guard<mutex> lock(mtx);
        vector<string> toRemove;
        
        for (const auto& [path, oldHash] : fileHashes) {
            try {
                string currentHash = FileHasher::calculateSHA256(path);
                if (currentHash != oldHash) {
                    cout << "CHANGED: " << path 
                         << "\nOld hash: " << oldHash 
                         << "\nNew hash: " << currentHash << "\n";
                    fileHashes[path] = currentHash;
                }
            } catch (const FileHashException& e) {
                cerr << "Error checking file " << path << ": " << e.what() << endl;
                toRemove.push_back(path);
            }
        }
        
        for (const auto& path : toRemove) {
            fileHashes.erase(path);
            cerr << "Removed inaccessible file from monitoring: " << path << endl;
        }
    }

void stop() noexcept {
        try {
            running = false;
            if (monitorThread.joinable()) {
                monitorThread.join();
            }
        } catch (const exception& e) {
            cerr << "Error during stop: " << e.what() << endl;
        }
    }

    ~FileMonitor() noexcept {
        stop();
    }
};

// 3. Интерфейс и конфигурация
int main(int argc, char* argv[]) {
    try {
        // Чтение конфигурации
        filesystem::path configPath = (argc > 1) ? argv[1] : "config.json";
        Config config = Config::loadFromFile(configPath);
        
        FileMonitor monitor(config);
        monitor.startMonitoring();
        
        // Ожидание сигнала завершения (Ctrl+C)
        signal(SIGINT, [](int) { shouldStop = true; });
        signal(SIGTERM, [](int) { shouldStop = true; });
        
        FileMonitor monitor(config);
    monitor.startMonitoring();
    
    while (!shouldStop) {
        this_thread::sleep_for(chrono::seconds(1));
    }
    
    monitor.stop();
    return 0;
}
