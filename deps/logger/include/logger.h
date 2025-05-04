#pragma once 
#include <ostream>
#include <iostream>
#include <mutex>
#include <string>
#include <boost/json.hpp>
#include <boost/system.hpp>

#define LOG() logger::Log::GetInstance()
#define LOG_MSG() logger::LogMessage::GetInstance()

namespace logger {

namespace sys = boost::system;
namespace json = boost::json;
    
void InitBoostLogFilter();

class ConnectionInfo {
public:
    std::string event_type;
    size_t process_id;
    std::string process_name;
    size_t endpoint;
    size_t parent_endpoint;
    std::string protocol;
    std::string src_address;
    std::string dst_address;
};

class Log {
    Log() = default;
    Log(const Log&) = delete;
public:
    static Log& GetInstance() {
        static Log obj;
        return obj;
    }

    void print(const boost::json::object& data, const std::string& message);
private:
    std::ostream& os_ {std::cout};
    std::mutex mutex_;
};

class LogMessage {
private:
    Log& log_; 
    LogMessage() : log_(Log::GetInstance()) {}
public:

    static LogMessage& GetInstance() {
        static LogMessage obj;
        return obj;
    }

    void log_block_accept(const ConnectionInfo& connection);
    void log_block_failed(size_t err_c, const std::string& msg);
    void log_socket_sniffer(const std::string& msg);
    void log_block_remove_filter(const std::string& filter);
    void log_block_add_filter(const std::string& filter);
    void log_block_filtered(const ConnectionInfo& connection);
};



} // namespace logger