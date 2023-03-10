APP := l4_flow_speed_monitor
OBJS := main.o flow.o
PKG_CONFIG ?= pkg-config
CXXFLAGS ?= -I. $(shell $(PKG_CONFIG) --cflags libpcap)
LDXXFLAGS ?= $(shell $(PKG_CONFIG) --libs libpcap)

all : $(APP)

-include *.d

$(APP) : $(OBJS)
	$(CXX) -o $@ $^ $(LDXXFLAGS)

%.o : %.cc
	$(CXX) $(CXXFLAGS) -M $< -o ${@}.d
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	-rm -rf *.o *.d $(APP)

.PHONY: all clean
