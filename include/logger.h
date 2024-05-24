#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

class Logger {
public:
    // 单例模式
    static Logger& getInstance();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // 设置日志文件路径
    void setLogFile(const std::string& filePath);

    void log(const std::string& message) ;

private:
    Logger() = default;
    ~Logger() ;

    bool is_file=false;
    std::ofstream logFile_;
    std::mutex mutex_;
};


int log_test();

#endif