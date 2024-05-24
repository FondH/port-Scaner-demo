#include "../include/logger.h"

Logger& Logger::getInstance() {
        static Logger instance;
        return instance;
    }




void Logger::setLogFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logFile_.is_open()) {
        logFile_.close();
    }
    logFile_.open(filePath, std::ios::out | std::ios::app);
    is_file = true;
    if (!logFile_.is_open()) {
        std::cerr << "Failed to open log file: " << filePath << std::endl;
    }
}

// 写日志
void Logger::log(const std::string& message) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout <<message<<std::endl;
    if(is_file){

        if (logFile_.is_open()) {
            logFile_ << message << std::endl;
        } else {
            std::cerr << "Log file is not open." << std::endl;
        }
    }

}

Logger::~Logger() {
    if (logFile_.is_open()) {
        logFile_.close();
    }
}

int log_test() {
    Logger& logger = Logger::getInstance();
    logger.setLogFile("log.txt");
    logger.log("This is a log message.");
    logger.log("Logging another message.");

    return 0;
}
