#ifndef FLOW_H_
#define FLOW_H_

#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <memory>
#include <mutex>
#include <string>
#include <sstream>
#include <unordered_map>


class Packet {
public:
    Packet(void) {}

    bool load(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    inline const std::string & flowName(void) const {
        return flow_name_;
    }

    inline size_t size(void) const {
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
    Layer4Flow(const Packet & packet);

    ~Layer4Flow(void) {
        // printf("Destroy Flow: %s\n", flow_info_.flowName().c_str());
    }

    inline const std::string & flowName(void) const {
        return flow_info_.flowName();
    }

    void add(const Packet & packet);

    uint64_t newSize(void);

    inline bool expired(void) const {
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
    bool add(Packet & packet);

    bool get(const std::string & flow_name, std::shared_ptr<Layer4Flow> & flow);

    void update(void);

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


#endif  // FLOW_H_