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
            for (unsigned char i : hash) {
                char buf[3];
                sprintf(buf, "%02x", i);
                result += buf;
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
    void addFile(const filesystem::path& path) {
        safeAddFile(path);
    }

    void scanDirectory(const filesystem::path& dir) {
        try {
            for (const auto& entry : filesystem::recursive_directory_iterator(dir)) {
                try {
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

    void startMonitoring(const filesystem::path& dir, int intervalSec) {
        try {
            if (!filesystem::exists(dir)) {
                throw FileMonitorException("Directory does not exist: " + dir.string());
            }

            running = true;
            scanDirectory(dir);
            
            monitorThread = thread([this, dir, intervalSec]() {
                while (running) {
                    try {
                        this_thread::sleep_for(chrono::seconds(intervalSec));
                        checkForChanges();
                    } catch (const exception& e) {
                        cerr << "Error in monitoring thread: " << e.what() << endl;
                    }
                }
            });
        } catch (const exception& e) {
            running = false;
            throw FileMonitorException(string("Monitoring start failed: ") + e.what());
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
int main() {
    try {
        FileMonitor monitor;
        
        filesystem::path directoryToWatch = "./test_files";
        int checkInterval = 5;

        cout << "Starting monitoring of: " << directoryToWatch << "\n";
        monitor.startMonitoring(directoryToWatch, checkInterval);

        this_thread::sleep_for(chrono::seconds(30));
        
        cout << "Monitoring stopped.\n";
        return 0;
    } catch (const FileMonitorException& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    } catch (const exception& e) {
        cerr << "Unexpected error: " << e.what() << endl;
        return 2;
    }
}