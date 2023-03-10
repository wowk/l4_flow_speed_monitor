#include <pcap.h>
#include <unistd.h>
#include <signal.h>
#include <mutex>
#include <thread>
#include "flow.h"


static std::mutex lock;
static bool done = false;
static pcap_t *handle = nullptr;
static Layer4FlowTable FlowTable;


std::string speed_to_str(uint64_t speed) {
    std::stringstream ss;
    uint32_t mb = speed / (1024 * 1024);
    uint32_t kb = (speed % (1024 * 1024)) / 1024;
    uint32_t b = speed % 1024;
    if (mb) {
        ss << mb << "MB ";
        if (kb) {
            ss << kb << "KB ";
        }
    } else if (kb) {
        ss << kb << "KB ";
    }
    if (b) {
        ss << b << "Bytes";
    }

    return ss.str();
}

void dump_thread_func(void) {
    int interval = 1;
    while(1) {
        bool has_valid = false;
        {
        std::unique_lock<std::mutex> ulock(lock);
        FlowTable.update();
        auto flow_table = FlowTable.flowTable();
        for (auto & p : FlowTable.flowTable()) {
            auto & flow_name = p.first;
            auto & flow = p.second;
            auto sp = flow->newSize();
            if (sp == 0) {
                continue;
            }
            printf("Flow: %s, Speed: ", flow_name.c_str());
            has_valid = true;

            printf("%s\n", speed_to_str(sp).c_str());
        }
        
        if (has_valid) {
            printf("\n\n\n");
        }
        }
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr packet_header;
    const u_char *packet_data;

    if (!argv[1] || std::string(argv[1]) == "-h") {
        printf("Usage: %s <ifname> [bpf filter rule]\n", argv[0]);
        exit(0);
    }

    handle = pcap_open_live(argv[1], 64, 0, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap: %s\n", error_buffer);
        return 1;
    }

    signal(SIGINT, [](int sig) {
        pcap_breakloop(handle);
    });


    if (argv[2]) {
        bpf_program filter;
        if (pcap_compile(handle, &filter, argv[2], 0, PCAP_NETMASK_UNKNOWN)) {
            fprintf(stderr, "failed to compile filter rule\n");
            pcap_close(handle);
            return 1;
        }

        pcap_setfilter(handle, &filter);
    }

    std::thread dump_thread(dump_thread_func);
    dump_thread.detach();

    auto pcap_process = [](u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        static Packet pkt;
        if (!pkt.load(args, header, packet)) {
            return;
        }
        std::unique_lock<std::mutex> ulock(lock);
        FlowTable.add(pkt);
    };
    pcap_loop(handle, 0, pcap_process, (u_char*)handle);
    
    pcap_close(handle);
    printf("Exit\n");

    return 0;
} 
