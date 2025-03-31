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
#include <csignal>

using namespace std;
namespace fs = std::filesystem;

atomic<bool> shouldStop{false};

class Config {
public:
    fs::path watchDirectory;
    int checkInterval;
    size_t scanThreads;
    bool verboseLogging;
    
    static Config loadFromFile(const fs::path& configPath) {
        Config config;
        config.watchDirectory = "./test_files";
        config.checkInterval = 5;
        config.scanThreads = thread::hardware_concurrency();
        config.verboseLogging = true;
        return config;
    }
};

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

class FileHasher {
public:
    static string calculateSHA256(const fs::path& filepath) {
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
            result.reserve(SHA256_DIGEST_LENGTH * 2);
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

class FileMonitor {
private:
    unordered_map<string, string> fileHashes;
    mutex mtx;
    atomic<bool> running{false};
    thread monitorThread;
    Logger logger;
    Config config;

    void safeAddFile(const fs::path& path) {
        try {
            string hash = FileHasher::calculateSHA256(path);
            lock_guard<mutex> lock(mtx);
            fileHashes[path.string()] = hash;
            logger.log("Added: " + path.string() + " [Hash: " + hash + "]");
        } catch (const FileHashException& e) {
            logger.error("Error adding file " + path.string() + ": " + e.what());
        }
    }

public:
    FileMonitor(const Config& cfg) : config(cfg), logger(cfg.verboseLogging) {}
    
    void startMonitoring() {
        try {
            if (!fs::exists(config.watchDirectory)) {
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
                while (running && !shouldStop) {
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

    void addFile(const fs::path& path) {
        safeAddFile(path);
    }

    void scanDirectory(const fs::path& dir) {
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                try {
                    if (entry.is_symlink()) {
                        logger.debug("Skipping symlink: " + entry.path().string());
                        continue;
                    }
                    if (entry.is_regular_file()) {
                        safeAddFile(entry.path());
                    }
                } catch (const fs::filesystem_error& e) {
                    logger.error("Filesystem error processing " + entry.path().string() + ": " + e.what());
                }
            }
        } catch (const exception& e) {
            throw FileMonitorException(string("Directory scan failed: ") + e.what());
        }
    }

    void parallelScanDirectory(const fs::path& dir, size_t threadCount = thread::hardware_concurrency()) {
        vector<fs::path> files;
        try {
            for (const auto& entry : fs::recursive_directory_iterator(dir)) {
                try {
                    if (entry.is_regular_file()) {
                        files.push_back(entry.path());
                    }
                } catch (const fs::filesystem_error& e) {
                    logger.error("Skipping inaccessible file: " + string(e.path1().string()) + 
                               " - " + e.what());
                }
            }
        } catch (const exception& e) {
            throw FileMonitorException("Failed to list directory: " + string(e.what()));
        }

        if (files.empty()) {
            logger.debug("No files found in directory");
            return;
        }
        if (files.size() < threadCount * 4) {
            threadCount = max(size_t(1), (files.size() + 3) / 4);
            logger.debug("Reduced thread count to " + to_string(threadCount) + 
                        " for " + to_string(files.size()) + " files");
        }

        vector<string> hashes(files.size());
        vector<exception_ptr> exceptions(threadCount, nullptr);
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

        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }

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
                    logger.log("CHANGED: " + path + 
                             "\nOld hash: " + oldHash + 
                             "\nNew hash: " + currentHash);
                    fileHashes[path] = currentHash;
                }
            } catch (const FileHashException& e) {
                logger.error("Error checking file " + path + ": " + e.what());
                toRemove.push_back(path);
            }
        }
        
        for (const auto& path : toRemove) {
            fileHashes.erase(path);
            logger.error("Removed inaccessible file from monitoring: " + path);
        }
    }

    void stop() noexcept {
        try {
            running = false;
            if (monitorThread.joinable()) {
                monitorThread.join();
            }
        } catch (const exception& e) {
            logger.error("Error during stop: " + string(e.what()));
        }
    }

    ~FileMonitor() noexcept {
        stop();
    }
};

int main(int argc, char* argv[]) {
    try {
        fs::path configPath = (argc > 1) ? argv[1] : "config.json";
        Config config = Config::loadFromFile(configPath);
        
        FileMonitor monitor(config);
        monitor.startMonitoring();
        
        signal(SIGINT, [](int) { shouldStop = true; });
        signal(SIGTERM, [](int) { shouldStop = true; });
        
        while (!shouldStop) {
            this_thread::sleep_for(chrono::seconds(1));
        }
        
        monitor.stop();
        return 0;
    } catch (const FileMonitorException& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    } catch (const exception& e) {
        cerr << "Unexpected error: " << e.what() << endl;
        return 2;
    }
}
