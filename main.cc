#include <pcap.h>
#include <unistd.h>
#include <signal.h>
#include <mutex>
#include <atomic>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <sstream>
#include <stack>
#include <iostream>
#include <thread>
#include <memory>


class Packet {
public:
    Packet(void) {}

    bool load(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
        const struct ethhdr * ethhdr_ = nullptr;
        const struct iphdr * iphdr_ = nullptr;
        const struct udphdr * udphdr_ = nullptr;
        const struct tcphdr * tcphdr_ = nullptr;

        ethhdr_ = (struct ethhdr*)(packet);
        if (ethhdr_->h_proto != ntohs(ETH_P_IP)) {
            return false;
        }

        iphdr_ = (struct iphdr*)(sizeof(*ethhdr_) + (u_char*)ethhdr_);
        if (ntohs(iphdr_->frag_off) & IP_MF) {
            // uint16_t offset = 8 * (ntohs(iphdr->frag_off) & IP_OFFMASK);
            // printf("frag: %u\n", offset);
            return false;
        }
        
        protocol_ = iphdr_->protocol;
        if (protocol_ == IPPROTO_TCP) {
            tcphdr_ = (struct tcphdr*)(4 * iphdr_->ihl + (u_char*)iphdr_);
            sport_    = ntohs(tcphdr_->source);
            dport_    = ntohs(tcphdr_->dest);
        } else if (protocol_ == IPPROTO_UDP) {
            udphdr_ = (struct udphdr*)(4 * iphdr_->ihl + (u_char*)iphdr_);
            sport_    = ntohs(udphdr_->source);
            dport_    = ntohs(udphdr_->dest);
        } else {
            return false;
        }

        char addr[64] = "";
        int af = (ethhdr_->h_proto == ntohs(ETH_P_IP)) ? AF_INET : AF_INET6;
        inet_ntop(af, &iphdr_->saddr, addr, sizeof(addr));
        saddr_ = addr;

        inet_ntop(af, &iphdr_->daddr, addr, sizeof(addr));
        daddr_ = addr;
        
        size_ = header->len;

        std::stringstream ss;
        if (protocol_ == IPPROTO_TCP)
            ss << "TCP: " << saddr_ << ":" << sport_ << " -> " << daddr_ << ":" << dport_;
        else
            ss << "UDP: " << saddr_ << ":" << sport_ << " -> " << daddr_ << ":" << dport_;
        flow_name_ = ss.str();

        return true;
    }

    const std::string & flowName(void) const {
        return flow_name_;
    }

    size_t size(void) const {
        return size_;
    }

private:
    size_t size_;
    std::string saddr_;
    std::string daddr_;
    uint16_t sport_;
    uint16_t dport_;
    uint8_t protocol_;
    std::string flow_name_;
};

class Layer4Flow {
public:
    Layer4Flow(const Packet & packet) : flow_info_(packet) {
        size_ = 0;
        new_size_ = 0;
        count_ = 0;
        add(packet);
    }

    ~Layer4Flow(void) {
        // printf("Destroy Flow: %s\n", flow_info_.flowName().c_str());
    }

    const std::string & flowName(void) const {
        return flow_info_.flowName();
    }

    void add(const Packet & packet) {
        expired_ = 5;
        count_ ++;
        new_size_ += packet.size();
        size_ += packet.size();
    }

    uint64_t newSize(void) {
        uint64_t tmp = new_size_;
        if (expired_ > 0) {
            expired_ --;
        }
        new_size_= 0;
        return tmp;
    }

    bool expired(void) const {
        return expired_ == 0;
    }
private:
    uint8_t expired_;
    uint64_t new_size_;
    uint64_t size_;
    uint64_t count_;
    Packet flow_info_;
};


class Layer4FlowTable {
public:
    bool add(Packet & packet) {
        std::shared_ptr<Layer4Flow> flow;
        if (!get(packet.flowName(), flow)) {
            flow_table_[packet.flowName()] = std::make_shared<Layer4Flow>(packet);
        } else {
            flow->add(packet);
        }

        return true;
    }

    bool get(const std::string & flow_name, std::shared_ptr<Layer4Flow> & flow) {
        auto itr = flow_table_.find(flow_name);
        if (itr == flow_table_.end()) {
            return false;
        }
        flow = itr->second;
        return true;
    }

    void update(void) {
        auto itr = flow_table_.begin();
        while (itr != flow_table_.end()) {
            if (!itr->second->expired()) {
                itr ++;
                continue;
            }
            auto & ptr = itr->second;
            itr = flow_table_.erase(itr);
        }
    }

    const std::unordered_map<std::string, std::shared_ptr<Layer4Flow>> flowTable(void) const {
        return flow_table_;
    }

    ~Layer4FlowTable(void) {
        // printf("Clean Flow table\n");
    }

private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<Layer4Flow>> flow_table_;
};


static std::mutex lock;
static bool done = false;
static pcap_t *handle = nullptr;
static Layer4FlowTable FlowTable;


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

    auto speed_to_str = [](uint64_t speed) -> std::string {
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
    };

    std::thread dump_thread([&](void) {
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
    });
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
