#include "../include/scaner.h"
#include "../include/logger.h"




bool Scaner::_detect(METHOD t,const std::string tarIpStr, const int st,const int ed){

    std::stringstream ss; 
    ss << "target'addr: "<<tarIpStr<<" detect_scope: "<<st<<"——"<<ed << std::endl;
    ss << "method: ";
    int (Scaner::*method)(const std::string, const int) = nullptr;

    switch (t){
        case PING:
            ss << "PING"; method = &Scaner::_PingHost; break;
        case CONNECT:
            ss << "CONNECT"; method = &Scaner::_ConnectHost; break;
        case SYN:
            ss << "SYN"; method = &Scaner::_SynHost; break;
        case FIN:
            ss << "FIN"; method = &Scaner::_FinHost; break;
        case UDP:
            ss << "UDP"; method = &Scaner::_UdpHost; break;
        default: 
            break;
    }
    this->logger.log(ss.str());

    // threads crew
    std::mutex mtx;
    int active_threads = 0;
    const int max_threads = this->max_threads; 

    for (int port = st; port <= ed; ++port) {
        {
            std::unique_lock<std::mutex> lock(mtx);
            while (active_threads >= max_threads) {
                // busy-wait loop
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                lock.lock();
            }
            ++active_threads;
        }

        std::thread(lock_thread, this, tarIpStr, port, method, std::ref(mtx), std::ref(active_threads)).detach();
    }

    while (true) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (active_threads == 0)
                break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    this->logger.log("Dectect finished\n");
    return true;
}

Scaner::Scaner(const std::string localIpStr):local_ip_s(localIpStr), local_ip(ntohl(inet_addr(local_ip_s.c_str()))), local_port(1918), max_threads(10){}

Scaner::Scaner(const std::string localIpStr, const int port, const int max_thread, const std::string& log_path){
    local_ip_s=localIpStr;
    local_port = port;
    max_threads = max_thread;
    local_ip = ntohl(inet_addr(local_ip_s.c_str()));

    if(log_path.length()){
        this->logger.setLogFile(log_path);
        this->logger.log("logs will dumps in '" + log_path +"'");
    }
}
Scaner::Scaner(){}

/**
 * return 1 reachable
 *        0 timeout
*/
int Scaner::_PingHost(const std::string tarIpStr, const int p){

    int pingSocket, on, ret,sendBufSize;
    char* sendBuffer, * recvBuffer;
    // socket setting
    pingSocket = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(pingSocket == -1){  perror("socket"); }
    on = 1;
    ret = setsockopt(pingSocket,0,IP_HDRINCL,&on,sizeof(on));

    // ICMP 报文
    sendBufSize = sizeof(struct iphdr)+ sizeof(struct icmphdr) + sizeof(std::tm);
    sendBuffer = (char*)malloc(sendBufSize);
    memset(sendBuffer,0,sendBufSize);

    // ip header init
    struct iphdr* ip = (struct iphdr*)sendBuffer;
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sendBufSize);
    ip->id = rand();
    ip->ttl = 64;
    ip->frag_off = 0x40;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = htonl(local_ip);
    ip->daddr = inet_addr(tarIpStr.c_str());
   
    // icmp header init
    struct icmphdr* icmp = (struct icmphdr*)(ip+1);
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = htonl(local_port);
    icmp->un.echo.sequence = 0;

    // timeval init
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm *tp = std::localtime(&now_c);
    std::memcpy((char*)(icmp + 1), tp, sizeof(std::tm));

    // Calculate ICMP checksum
    icmp->checksum = in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + sizeof(std::tm));

    // 
    struct sockaddr_in taraddr;
    taraddr.sin_family = AF_INET;
    taraddr.sin_addr.s_addr = inet_addr(tarIpStr.c_str());

    // send to tarIp
    ret = sendto(pingSocket,sendBuffer,sendBufSize,0,(struct sockaddr*)&taraddr, sizeof(taraddr));

    if(fcntl(pingSocket, F_SETFL, O_NONBLOCK) == -1){
        perror("setsockopt");
    }

    struct ip* recvip;
    struct icmp* recvicmp;
    recvBuffer = (char*)malloc(1024);
    auto start = std::chrono::high_resolution_clock::now();


    while(true){
        ret =  recvfrom(pingSocket,recvBuffer,1024,0,NULL,NULL);
        if(ret){
            
            recvip = (struct ip*)recvBuffer;
            recvicmp = (struct icmp*)(recvBuffer+(recvip->ip_hl*4));
            unsigned int srcIP = (int32_t(recvip->ip_src.s_addr)), dstIP = ntohl(int32_t(recvip->ip_dst.s_addr)) ;
            
            if(srcIP == inet_addr(tarIpStr.c_str()) && dstIP == local_ip 
                                && recvicmp->icmp_type == ICMP_ECHOREPLY){
                this->logger.log("ping " + tarIpStr + ": success");
                
                //std::cout<<"recv icmp echo from("<<inet_ntoa(recvip->ip_src)<<std::endl;
                return 1;
            }
            
        }

        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
        if (duration.count() >= 3) {
            this->logger.log(tarIpStr + ": waf?");
            return 0 ; //timeout
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 忙等待
    }

}

int Scaner::_ConnectHost(const std::string tarIpStr, const int port){

    //std::cout<<"dectect "<<port<<" start"<<std::endl;
    int conSocket = socket(AF_INET,SOCK_STREAM,0), funcret=-1 ,ret;
    sockaddr_in tarAddr;

    if(conSocket == -1){
        perror("_ConnectHost()->socket init Error");
        funcret = -1;
    }

    memset(&tarAddr,0,sizeof(tarAddr));
    tarAddr.sin_family = AF_INET;
    tarAddr.sin_addr.s_addr = inet_addr(tarIpStr.c_str());
    tarAddr.sin_port = htons(port);

    ret = connect(conSocket,(struct sockaddr*)&tarAddr,sizeof(tarAddr));
    if(ret==-1){
        //perror("_ConnectHost()->connect Error");
        this->logger.log(tarIpStr + ":" + std::to_string(port) + " no");
        //std::cout<<tarIpStr<<":"<<port<<" no"<<std::endl;
        funcret = 0;
    }else{

        this->logger.log(tarIpStr + ":" + std::to_string(port) + " open");
        //std::cout<<tarIpStr<<":"<<port<<" open"<<std::endl;
        funcret = 1;
    }
    
    close(conSocket);
    return funcret;
}

bool Scaner::ConnectHost(const std::string tarIpStr, const int st, const int ed){
    std::stringstream ss; 
    ss<<"target'addr: "<<tarIpStr<<" detect_scope: "<<st<<"——"<<ed;
    this->logger.log(ss.str());

    std::mutex mtx;
    int active_threads = 0;
    const int max_threads = this->max_threads; 
    int (Scaner::*selectfunc)(const std::string, const int) = &Scaner::_ConnectHost;

    for (int port = st; port <= ed; ++port) {
        {
            std::unique_lock<std::mutex> lock(mtx);
            while (active_threads >= max_threads) {
                // busy-wait loop
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                lock.lock();
            }
            ++active_threads;
        }

        std::thread(lock_thread, this, tarIpStr, port, selectfunc, std::ref(mtx), std::ref(active_threads)).detach();
    }

    // 等待所有线程完成
    while (true) {
        {
            std::lock_guard<std::mutex> lock(mtx);
            if (active_threads == 0) {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return true;
}

int Scaner::_SynHost(const std::string tarIpStr, const int port){
  
    int synSocket = socket(AF_INET,SOCK_RAW, IPPROTO_TCP), ret;
    char* sendBuffer, * recvBuffer;
    sockaddr_in tarAddr;

    if(synSocket == -1){
        perror("_SynHost()->socket init Error");
    }
    memset(&tarAddr,0,sizeof(tarAddr));
    tarAddr.sin_family = AF_INET;
    tarAddr.sin_addr.s_addr = inet_addr(tarIpStr.c_str());
    tarAddr.sin_port = htons(port);


    sendBuffer = (char*)malloc(sizeof(struct tcphdr)+ sizeof(struct pseudo_header));
    struct pseudo_header *ptcph = (struct pseudo_header*)sendBuffer;
    //struct ip *iph = (struct ip *) sendBuffer;
    struct tcphdr *tcph = (struct tcphdr *) (sendBuffer + sizeof(struct pseudo_header));

    // 伪头部
    ptcph->saddr = htonl(local_ip);
    ptcph->daddr = inet_addr(tarIpStr.c_str());
    ptcph->useless = 0;
    ptcph->protocol = IPPROTO_TCP;
    ptcph->length = htons(sizeof(struct tcphdr));
    //tcp
    tcph->th_sport=htons(local_port);
    tcph->th_dport=htons(port);
    tcph->th_seq=htonl(123456);
    tcph->th_ack=0;
    tcph->th_x2=0;
    tcph->th_off=5;
    tcph->th_flags=TH_SYN;
    tcph->th_win=htons(65535);
    tcph->th_sum=0;
    tcph->th_urp=0;
    tcph->th_sum=in_cksum((unsigned short*)ptcph, 20+12);

    //sendto
    ret = sendto(synSocket, tcph, 20, 0, (struct sockaddr *)&tarAddr,sizeof(tarAddr));

    if(fcntl(synSocket, F_SETFL, O_NONBLOCK) == -1){
        perror("setsockopt");
    }

    struct ip* recvip;
    struct tcphdr* recvtcp;
    recvBuffer = (char*)malloc(1024);
    auto start = std::chrono::high_resolution_clock::now();

    while(true){
        ret =  recvfrom(synSocket,recvBuffer,1024,0,NULL,NULL);
        if(ret){
            
            recvip = (struct ip*)recvBuffer;
            recvtcp = (struct tcphdr*)(recvBuffer+(recvip->ip_hl*4));
            unsigned int srcIP = (int32_t(recvip->ip_src.s_addr)), dstIP = ntohl(int32_t(recvip->ip_dst.s_addr)) ;
            
            //std::cout<<dstIP<<"|"<< local_ip << " "<<srcIP<<" | "<< inet_addr(tarIpStr.c_str())<<std::endl;
            //std::cout<<"Dst IP "<<inet_ntoa(recvip->ip_dst)<<":" <<ntohs(recvtcp->th_dport)<< " Src IP "<< inet_ntoa(recvip->ip_src)<<":" <<ntohs(recvtcp->th_sport)<<std::endl;
            if(srcIP == inet_addr(tarIpStr.c_str()) 
                                && dstIP == local_ip 
                                && port == ntohs(recvtcp->th_sport)
                                && local_port == ntohs(recvtcp->th_dport)
                                ) {
                if (recvtcp->th_flags == 0x14){ //SYN|ACK
                    this->logger.log(tarIpStr + ":" + std::to_string(port) + " open");
                    //std::cout<<"recv icmp echo from("<<inet_ntoa(recvip->ip_src)<<std::endl;
                    return 1;
                }else if(recvtcp->th_flags == 0x12){ //RST
                    this->logger.log(tarIpStr + ":" + std::to_string(port) + " No");
                    return 2;
                }
            }
            
        }

        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
        if (duration.count() >= 2) {
            this->logger.log(tarIpStr + ":" + std::to_string(port) + " waf?");
            //std::cout<<"timeout"<<std::endl;
            return 0 ; //timeout
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 忙等待
    }

}

bool Scaner::SynHost(const std::string tarIpStr, const int st, const int ed){

    if(_PingHost(tarIpStr))
        return _detect(SYN, tarIpStr, st, ed);
    else
        return 0;
}

int Scaner::_FinHost(const std::string tarIpStr, const int port){
    int finSocket = socket(AF_INET,SOCK_RAW, IPPROTO_TCP) ,ret;
    char* sendBuffer, * recvBuffer;
    sockaddr_in tarAddr;

    if(finSocket == -1){
        perror("_SynHost()->socket init Error");
    }
    memset(&tarAddr,0,sizeof(tarAddr));
    tarAddr.sin_family = AF_INET;
    tarAddr.sin_addr.s_addr = inet_addr(tarIpStr.c_str());
    tarAddr.sin_port = htons(port);


    sendBuffer = (char*)malloc(sizeof(struct tcphdr) +  sizeof(struct pseudo_header));
    struct pseudo_header *ptcph = (struct pseudo_header*)sendBuffer;
    //struct ip *iph = (struct ip *) sendBuffer;
    struct tcphdr *tcph = (struct tcphdr *) (sendBuffer + sizeof(struct pseudo_header));


    // 伪头部
    ptcph->saddr = htonl(local_ip);
    ptcph->daddr = inet_addr(tarIpStr.c_str());
    ptcph->useless = 0;
    ptcph->protocol = IPPROTO_TCP;
    ptcph->length = htons(sizeof(struct tcphdr));
    //tcp
    tcph->th_sport=htons(local_port);
    tcph->th_dport=htons(port);
    tcph->th_seq=htonl(123456);
    tcph->th_ack=0;
    tcph->th_x2=0;
    tcph->th_off=5;
    tcph->th_flags=TH_FIN;
    tcph->th_win=htons(65535);
    tcph->th_sum=0;
    tcph->th_urp=0;
    tcph->th_sum=in_cksum((unsigned short*)ptcph, 20+12);

    //sendto
    ret = sendto(finSocket, tcph, 20, 0, (struct sockaddr *)&tarAddr,sizeof(tarAddr));

    if(fcntl(finSocket, F_SETFL, O_NONBLOCK) == -1){
        perror("setsockopt");
    }

    struct ip* recvip;
    struct tcphdr* recvtcp;
    recvBuffer = (char*)malloc(1024);
    auto start = std::chrono::high_resolution_clock::now();

    while(true){
        ret =  recvfrom(finSocket,recvBuffer,1024,0,NULL,NULL);
        if(ret){
            
            recvip = (struct ip*)recvBuffer;
            recvtcp = (struct tcphdr*)(recvBuffer+(recvip->ip_hl*4));
            unsigned int srcIP = (int32_t(recvip->ip_src.s_addr)), dstIP = ntohl(int32_t(recvip->ip_dst.s_addr)) ;
            
            //std::cout<<dstIP<<"|"<< local_ip << " "<<srcIP<<" | "<< inet_addr(tarIpStr.c_str())<<std::endl;
            //std::cout<<"Dst IP "<<inet_ntoa(recvip->ip_dst)<<":" <<ntohs(recvtcp->th_dport)<< " Src IP "<< inet_ntoa(recvip->ip_src)<<":" <<ntohs(recvtcp->th_sport)<<std::endl;
            if(srcIP == inet_addr(tarIpStr.c_str()) 
                                && dstIP == local_ip 
                                && port == ntohs(recvtcp->th_sport)
                                && local_port == ntohs(recvtcp->th_dport)
                                ) {
                if (recvtcp->th_flags == TH_RST){ //RST
                    this->logger.log(tarIpStr + ":" + std::to_string(port) + " No");
                    //std::cout<<"recv icmp echo from("<<inet_ntoa(recvip->ip_src)<<std::endl;
                    return 2;
                }
            }
            
        }

        auto now = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
        if (duration.count() >= 5) { //未响应 则开放
            this->logger.log(tarIpStr + ":" + std::to_string(port) + " open");
            //std::cout<<"timeout"<<std::endl;
            return 1 ; 
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 忙等待
    }

}

bool Scaner::FinHost(const std::string tarIpStr, const int st ,const int ed){

    if(_PingHost(tarIpStr)){
        this->logger.log("(Fin This method of detection is only applicable for Unix/Linux)");
        return _detect(FIN, tarIpStr, st, ed);
    }else{
        return 0;
    }

}

int Scaner::_UdpHost(const std::string tarIpStr, const int port){

    int ret = -1, on=1;
    char* sendBuffer, * recvBuffer;
    sockaddr_in tarAddr;

    // socket
    int udpSocket=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(udpSocket == -1){
        perror("_SynHost()->socket init Error");

    }
    ret = setsockopt(udpSocket,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

    // tar addr_in
    memset(&tarAddr,0,sizeof(tarAddr));
    tarAddr.sin_family = AF_INET;
    tarAddr.sin_addr.s_addr = inet_addr(tarIpStr.c_str());
    tarAddr.sin_port = htons(port);
    ret = setsockopt(udpSocket,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));

    // udp packetage
    sendBuffer = (char*)malloc(sizeof(struct iphdr) + sizeof(struct udphdr));
    memset(sendBuffer, 0x00, sizeof(struct iphdr) + sizeof(struct udphdr));
    struct iphdr* ip = (struct iphdr *)sendBuffer;
    struct udphdr* udp = (struct udphdr *)(sendBuffer + sizeof(struct iphdr));
    struct pseudo_header *ptcph = (struct pseudo_header *)(sendBuffer + sizeof(struct iphdr) - sizeof(struct pseudo_header));
    // udp header
    udp->source = htons(local_port);
    udp->dest = htons(port);
    udp->len = htons(sizeof(struct udphdr));
    udp->check = 0;

    // calc checksum & 伪头部
    ptcph->saddr = htonl(local_ip);
    ptcph->daddr = inet_addr(tarIpStr.c_str());
    ptcph->useless = 0;
    ptcph->protocol = IPPROTO_UDP;
    ptcph->length = udp->len;
    udp->check = in_cksum((u_short *)ptcph,sizeof(struct udphdr)+sizeof(struct pseudo_header));

    // ip header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0x10;
    ip->tot_len = sizeof(sendBuffer);
    ip->frag_off = 0;
    ip->ttl = 69;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = htonl(local_ip);
    ip->daddr = inet_addr(tarIpStr.c_str());

    // sendto 
    for(int t=0;t<2;t++){
 
        ret = sendto(udpSocket, sendBuffer, ip->tot_len, 0,(struct sockaddr *)&tarAddr, sizeof(tarAddr));

        
        if(fcntl(udpSocket, F_SETFL, O_NONBLOCK) == -1){
            perror("setsockopt");
        }

        struct ip* recvip;
        struct icmp* recvicmp;
        recvBuffer = (char*)malloc(1024);
        auto start = std::chrono::high_resolution_clock::now();

        while(true){
            ret =  recvfrom(udpSocket,recvBuffer,1024,0,NULL,NULL);
            if(ret){
                
                recvip = (struct ip*)recvBuffer;
                recvicmp = (struct icmp*)(recvBuffer+(recvip->ip_hl*4));
                unsigned int srcIP = (int32_t(recvip->ip_src.s_addr)), dstIP = ntohl(int32_t(recvip->ip_dst.s_addr)) ;
                
                if(srcIP == inet_addr(tarIpStr.c_str()) && dstIP == local_ip 
                                    && recvicmp->icmp_type == ICMP_DEST_UNREACH
                                    && recvicmp->icmp_code == ICMP_PORT_UNREACH){
                
                    this->logger.log(tarIpStr + ":" + std::to_string(port) + " No");
                    //std::cout<<"recv icmp echo from("<<inet_ntoa(recvip->ip_src)<<std::endl;
                    return 2;
                    
                }
                
            }

            auto now = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start);
            if (duration.count() >= 3) { //未响应 则开放
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 忙等待
        }
    }
    this->logger.log(tarIpStr + ":" + std::to_string(port) + " open(may be lost)");
    return 0 ; 
   
}

bool Scaner::UdpHost(const std::string tarIpStr, const int st, const int ed){
    this->logger.log("(Udp: the res of this detection is subject to network fluctuations)");
     return _detect(UDP, tarIpStr, st, ed);
}

unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

void lock_thread(Scaner *scanner,  const std::string tarIpStr, int port, int (Scaner::*selectFunction)(const std::string, const int), std::mutex &mtx, int &active_threads){
    (scanner->*selectFunction)(tarIpStr, port);

    std::lock_guard<std::mutex> lock(mtx);
    --active_threads;
}

void test(){
    
    std::cout<<"Local ip: 192.168.137.132 Local port: 1918"<<std::endl;
    Scaner sc("192.168.137.132");

    std::cout<<"------- Test Ping ------"<<std::endl;
    std::cout<<"./scaner 192.168.137.1"<<std::endl;
    sc._PingHost("192.168.137.1");  
    std::cout<<"./scaner 192.168.127.123"<<std::endl;
    sc._PingHost("192.168.127.123");  

    std::cout<<std::endl;
    
    std::cout<<"------- Test SYN -------"<<std::endl;
    std::cout<<"./scaner 192.168.137.1 -s 8080 -m syn"<<std::endl;
    sc._SynHost("192.168.137.1", 8080);
    std::cout<<"./scaner 192.168.117.645 -s 7980 -m syn"<<std::endl;
    sc.SynHost("192.168.117.645", 7980, 7980);
    std::cout<<"./scaner 192.168.137.1 -s 8076-8082 -m syn"<<std::endl;
    sc.SynHost("192.168.137.1", 8076, 8080);

    std::cout<<std::endl;

    std::cout<<"------- Test FIN --------"<<std::endl;
    std::cout<<"./scaner 192.168.137.1 -s 8080 -m fin"<<std::endl;
    sc._FinHost("192.168.137.1", 8080);
    std::cout<<"./scaner 192.168.117.645 -s 7980 -m fin"<<std::endl;
    sc.FinHost("192.168.117.645", 7980, 7980);
    std::cout<<"./scaner 192.168.137.1 -s 8076-8080 -m fin"<<std::endl;
    sc.FinHost("192.168.137.1", 8076, 8080);

    std::cout<<std::endl;

    std::cout<<"------- Test UDP --------"<<std::endl;
    std::cout<<"./scaner 192.168.137.1 -s 8080 -m udp"<<std::endl;
    sc._UdpHost("192.168.137.1", 8080);
    std::cout<<"./scaner 192.168.117.645 -s 7980 -m udp"<<std::endl;
    sc.UdpHost("192.168.117.645", 7980, 7980);
    std::cout<<"./scaner 192.168.137.1 -s 8076-8080 -m udp"<<std::endl;
    sc.UdpHost("192.168.137.1", 8076, 8080);

};

