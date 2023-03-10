APP := l4_flow_speed_monitor
OBJS := main.cc

all : $(APP)

PKG_CONFIG=pkg-config
CXXFLAGS=$(shell $(PKG_CONFIG) --cflags libpcap)
LDXXFLAGS=$(shell $(PKG_CONFIG) --libs libpcap)

#-include .deps/*.d

$(APP) : $(OBJS)
	$(CXX) -o $@ $^ $(LDXXFLAGS)

%.o : %.cc
	mkdir -p .deps
	$(CXX) $(CXXFLAGS) -M $< -o ${@}.d
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	-rm -rf *.o .deps $(APP)

.PHONY: all clean
