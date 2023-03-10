#include "flow.h"

bool Packet::load(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
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

Layer4Flow::Layer4Flow(const Packet & packet) : flow_info_(packet) {
    size_ = 0;
    new_size_ = 0;
    count_ = 0;
    add(packet);
}

void Layer4Flow::add(const Packet & packet) {
    expired_ = 5;
    count_ ++;
    new_size_ += packet.size();
    size_ += packet.size();
}

uint64_t Layer4Flow::newSize(void) {
    uint64_t tmp = new_size_;
    if (expired_ > 0) {
        expired_ --;
    }
    new_size_= 0;
    return tmp;
}

bool Layer4FlowTable::add(Packet & packet) {
    std::shared_ptr<Layer4Flow> flow;
    if (!get(packet.flowName(), flow)) {
        flow_table_[packet.flowName()] = std::make_shared<Layer4Flow>(packet);
    } else {
        flow->add(packet);
    }

    return true;
}

bool Layer4FlowTable::get(const std::string & flow_name, std::shared_ptr<Layer4Flow> & flow) {
    auto itr = flow_table_.find(flow_name);
    if (itr == flow_table_.end()) {
        return false;
    }
    flow = itr->second;
    return true;
}

void Layer4FlowTable::update(void) {
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