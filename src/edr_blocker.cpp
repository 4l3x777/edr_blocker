#include <iostream>
#include <edr_blocker.h>

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    EdrSocketPacketSniffer& socket_sniffer = EdrSocketPacketSniffer::getInstance();
    
    // start sniffing
    if (socket_sniffer.startSniffing()) {
        while (true) {
            Sleep(5000);
        }
    }

    return 0;
}

