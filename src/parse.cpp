#include "../include/parse.h"


void print_usage() {
    std::cout << "Usage: ./scaner [target url] -o [output file path][option] -s [8080 or 8080-9012] -m [scan method: udp, syn, fin, conn]" << std::endl;
}

bool is_valid_scope(const std::string& scope) {
    // 匹配单个端口或端口范围
    std::regex scope_regex(R"(^(\d+)(?:-(\d+))?$)");
    return std::regex_match(scope, scope_regex);
}

void split_scope(const std::string& scope, int& start, int& end) {
    size_t dash_pos = scope.find('-');
    if (dash_pos != std::string::npos) {
        // 提取并转换成数字
        start = std::stoi(scope.substr(0, dash_pos));
        end = std::stoi(scope.substr(dash_pos + 1));
    } else {
        // 如果没有找到 '-', 默认 start 和 end 相同
        start = std::stoi(scope);
        end = start;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string target_url;
    std::string output_file="";
    std::string scope;
    std::string method;
    bool Isicmp = false;

    target_url = argv[1];

    // 定义长选项
    struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"scope", required_argument, 0, 's'},
        {"method", required_argument, 0, 'm'},
        {0, 0, 0, 0}
    };

    int opt;
    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "io:s:m:", long_options, &long_index)) != -1) {
        switch (opt) {
            case 'i':
                Isicmp = true;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 's':
                scope = optarg;
                break;
            case 'm':
                method = optarg;
                break;
            default:
                print_usage();
                return 1;
        }
    }

    Scaner scaner("192.168.137.132",1918, 10, output_file);

    if(Isicmp){
        scaner._PingHost(target_url);
        return 0;
    }

    // 验证所有必需的参数是否已提供
    if (target_url.empty() || scope.empty() || method.empty()) {
        std::cerr << "parameter missing "<<std::endl;
        print_usage();
        return 1;
    }

    // 验证 scope 格式是否有效
    if (!is_valid_scope(scope)) {
        std::cerr << "Invalid scope: " << scope << std::endl;
        std::cout<<"-s --scope like: 20-100" <<std::endl;
        return 1;
    }


    int st, ed;
    split_scope(scope, st,ed);
    // 验证扫描方法是否有效
    if(method == "udp"){
        scaner.UdpHost(target_url,st, ed);
        
    }else if(method=="syn"){
        scaner.SynHost(target_url,st, ed);

    }else if(method=="fin"){
        scaner.FinHost(target_url,st, ed);

    }else if(method == "conn"){
        scaner.ConnectHost(target_url,st, ed);

    }else{
        std::cerr << "Invalid scan method: " << method << std::endl;
        std::cout << "-m --method: udp syn fin conn"<<std::endl;
    }




    return 0;
}
