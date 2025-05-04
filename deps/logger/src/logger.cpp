#include "logger.h"
#include <boost/log/trivial.hpp> 
#include <boost/log/core.hpp>        
#include <boost/log/expressions.hpp> 
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/manipulators/add_value.hpp>
#include <boost/date_time.hpp>
#include <string>

namespace logger {
using namespace std::literals;
namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;

BOOST_LOG_ATTRIBUTE_KEYWORD(timestamp, "TimeStamp", boost::posix_time::ptime)
BOOST_LOG_ATTRIBUTE_KEYWORD(data, "Data", boost::json::object)
BOOST_LOG_ATTRIBUTE_KEYWORD(msg, "Msg", std::string)
BOOST_LOG_ATTRIBUTE_KEYWORD(task_id, "TaskID", std::string)

static void log_json(logging::record_view const& rec, logging::formatting_ostream& strm) {
    auto ts = *rec[timestamp];
    boost::json::object log_data;
    log_data["timestamp"] = to_iso_extended_string(ts);
    log_data["data"] = *rec[data];
    log_data["message"] = *rec[msg];
    log_data["thread_id"] = *rec[task_id];
    strm << boost::json::serialize(log_data) << std::endl;
}

void InitBoostLogFilter() {
    logging::core::get()->set_filter(
        logging::trivial::severity >= logging::trivial::info
    );
    logging::add_common_attributes();
    //log to file filter
    logging::add_file_log(
        keywords::file_name = "C:\\Windows\\Temp\\sample_log_%N.log",
        keywords::format = &log_json,
        keywords::open_mode = std::ios_base::app | std::ios_base::out,
        keywords::rotation_size = 10 * 1024 * 1024,
        keywords::time_based_rotation = sinks::file::rotation_at_time_point(12, 0, 0)
    );
    //log to console filter
    logging::add_console_log(
        std::cout,
        keywords::format = &log_json,
        keywords::auto_flush = true
    );
}

void Log::print(const boost::json::object& data_, const std::string& message_) {
    std::lock_guard<std::mutex> mutex{mutex_};
    BOOST_LOG_TRIVIAL(info) 
        << logging::add_value(data, data_) 
        << logging::add_value(task_id, std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()))) 
        << logging::add_value(msg, message_);
}

void LogMessage::log_block_accept(const ConnectionInfo& connection) {
    /*
    boost::json::object log_data;
    log_data["event_type"] = connection.event_type;
    log_data["process_id"] = connection.process_id;
    log_data["process_name"] = connection.process_name;
    log_data["endpoint"] = connection.endpoint;
    log_data["parent_endpoint"] = connection.parent_endpoint;
    log_data["protocol"] = connection.protocol;
    log_data["src_address"] = connection.src_address;
    log_data["dst_address"] = connection.dst_address;

    log_.print(log_data, "connection information");
    */
    return;
}

void LogMessage::log_block_filtered(const ConnectionInfo& connection) {
    boost::json::object log_data;
    log_data["event_type"] = connection.event_type;
    log_data["process_id"] = connection.process_id;
    log_data["process_name"] = connection.process_name;
    log_data["endpoint"] = connection.endpoint;
    log_data["parent_endpoint"] = connection.parent_endpoint;
    log_data["protocol"] = connection.protocol;
    log_data["src_address"] = connection.src_address;
    log_data["dst_address"] = connection.dst_address;

    log_.print(log_data, "edr connection filtered");
}

void LogMessage::log_block_failed(size_t err_c, const std::string& msg) {
    /*
    boost::json::object log_data;
    log_data["error_code"] = err_c;
    log_.print(log_data, msg);
    */
    return;
}

void LogMessage::log_block_add_filter(const std::string& filter) {
    boost::json::object log_data;
    log_data["filter"] = filter;
    log_.print(log_data, "edr filter add");
}

void LogMessage::log_block_remove_filter(const std::string& filter) {
    boost::json::object log_data;
    log_data["filter"] = filter;
    log_.print(log_data, "edr filter remove");
}

void LogMessage::log_socket_sniffer(const std::string& msg) {
    boost::json::object log_data;
    log_data["socket sniffer info"] = msg;
    log_.print(log_data, msg);
}
}