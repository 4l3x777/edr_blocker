#pragma once
#include <vector>
#include <string>
#include <thread>
#include <logger.h>
#include <socket_connection.h>

#include <Windows.h>

// singleton class
class EdrSocketPacketSniffer {

    HANDLE windivert_handle{ NULL };
    std::vector<std::thread*> monitor_threads;
    int monitor_threads_count{ 5 };
    std::string filter;

    EdrSocketPacketSniffer(const std::string& _filter = "true") : filter(_filter) { filter = _filter; };

    ~EdrSocketPacketSniffer() {
        if (instance) delete instance;
    };

    static EdrSocketPacketSniffer* instance;

public:
    static EdrSocketPacketSniffer& getInstance() {
        // if the instance doesn't exists, create it
        if (!instance) {
            // init logger
            logger::InitBoostLogFilter();
            // create instance
            instance = new EdrSocketPacketSniffer();
        }
        return *instance;
    }

    bool stopSniffing() {
        if (!monitor_threads.empty()) {
            for (auto threadAgent : monitor_threads) {
                // set monitor_threads to stop list
                socket_connection::SetThreadId(std::hash<std::thread::id>{}(threadAgent->get_id()));
            }
            // clear monitor_threads
            monitor_threads.clear();
            // close listen WFP connection
            WinDivertClose(windivert_handle);
            // set windivert handle to null
            windivert_handle = NULL;
            return true;
        }
        return false;
    }

    bool startSniffing() {
        if (!monitor_threads.empty()) return true;
        const char* err_str;
        // Close WinDivert SOCKET handle:
        if (windivert_handle) WinDivertClose(windivert_handle);
        // Open WinDivert SOCKET handle:
        windivert_handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_SOCKET, 0, (FALSE ? 0 : WINDIVERT_FLAG_SNIFF) | WINDIVERT_FLAG_RECV_ONLY);
        if (windivert_handle == INVALID_HANDLE_VALUE)
        {
            if (GetLastError() == ERROR_INVALID_PARAMETER &&
                !WinDivertHelperCompileFilter(
                    filter.c_str(),
                    WINDIVERT_LAYER_SOCKET,
                    NULL,
                    0,
                    &err_str,
                    NULL)
            ) {
                LOG_MSG().log_block_failed(-1, "invalid filter " + std::string(err_str));
            }
            LOG_MSG().log_block_failed(GetLastError(), "failed to open the device");
            return false;
        }
        else {
            for (auto i = 0; i < monitor_threads_count; i++) {
                monitor_threads.push_back(
                    new std::thread(
                        [this]() {
                            LOG_MSG().log_socket_sniffer("start sniffing");
                            socket_connection::GetEdrConnectionsPattern(windivert_handle);
                        }
                    )
                );
            }
            return true;
        }
    }
    
};

// initialize static instance to nullptr
EdrSocketPacketSniffer* EdrSocketPacketSniffer::instance{ nullptr };