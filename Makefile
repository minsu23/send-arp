TARGET = send-arp
SRCS = send-arp.cpp ip.cpp mac.cpp ethhdr.cpp arphdr.cpp

all:
	g++ -o $(TARGET) $(SRCS) -lpcap

clean:
	rm -f $(TARGET)