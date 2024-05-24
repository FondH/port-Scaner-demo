#ifndef SCANER_H
#define SCANER_H


#include<iostream>
#include<cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <thread>
#include <sys/time.h>
#include <chrono>
#include <mutex>
#include <sstream>
#include <netinet/in.h>
#include "logger.h"

unsigned short in_cksum(unsigned short *addr, int len);

struct pseudo_header {
    u_int32_t saddr;
    u_int32_t daddr;
    u_int8_t useless;
    u_int8_t protocol;
    u_int16_t length;
};

class Scaner{

public:
    enum METHOD {
        PING,
        CONNECT,
        SYN,
        FIN,
        UDP,
    };

private:
    std::string local_ip_s;
    unsigned int local_ip;
    int local_port;
    int max_threads;
    Logger& logger = Logger::getInstance();


public:

    Scaner();
    Scaner(const std::string localIpStr);
    Scaner(const std::string localIpStr, const int port, const int max_threads=10, const std::string& log_path="");

    // detect methods factory:  Multithreading is implemented in various methods
    bool _detect(METHOD t,const std::string tarIpStr, const int st,const int ed);
    
    /**
     * return 1 reachable
     *        0 timeout
    */
    int _PingHost(const std::string tarIpStr, const int p=0);
    
    int _ConnectHost(const std::string tarIpStr, const int port);
    bool ConnectHost(const std::string tarIpStr, const int st, const int ed);

    int _SynHost(const std::string tarIpStr, const int port);
    bool SynHost(const std::string tarIpStr, const int st, const int ed);
    
    int _FinHost(const std::string tarIpStr, const int port);
    bool FinHost(const std::string tarIpStr, const int st, const int ed);

    int _UdpHost(const std::string tarIpStr, const int port);
    bool UdpHost(const std::string tarIpStr, const int st, const int ed);


};

void lock_thread(Scaner *scanner, 
                       const std::string tarIpStr, int port, 
                       int (Scaner::*selectFunction)(const std::string, const int),
                       std::mutex &mtx,
                       int &active_threads);

unsigned short in_cksum(unsigned short *addr, int len);

void test();

#endif