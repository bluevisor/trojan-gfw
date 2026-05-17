/*
 * This file is part of the trojan project.
 */

#ifdef ENABLE_SOCKET_AUTH

#include "socket_authenticator.h"

#include <chrono>
#include <iostream>
#include <istream>
#include <ostream>
#include <utility>
#include <boost/asio/connect.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <boost/json.hpp>
#include "core/log.h"

namespace asio = boost::asio;
namespace local = boost::asio::local;
namespace json = boost::json;

SocketAuthenticator::SocketAuthenticator(asio::io_context &io_context, std::string socket_path)
    : io_context_(io_context),
      socket_path_(std::move(socket_path)),
      socket_(io_context),
      reconnect_timer_(io_context),
      report_timer_(io_context) {}

void SocketAuthenticator::start() {
    connect();
}

void SocketAuthenticator::connect() {
    boost::system::error_code ec;
    socket_.close(ec);
    socket_.connect(local::stream_protocol::endpoint(socket_path_), ec);
    if (ec) {
        Log::log_with_date_time("socket auth: connect to " + socket_path_ + " failed: " + ec.message(), Log::WARN);
        schedule_reconnect();
        return;
    }
    connected_ = true;
    Log::log_with_date_time("socket auth: connected to " + socket_path_, Log::INFO);
    send_hello();
    schedule_report();
    read_loop();
}

void SocketAuthenticator::schedule_reconnect() {
    connected_ = false;
    reconnect_timer_.expires_after(std::chrono::seconds(RECONNECT_DELAY_SECONDS));
    reconnect_timer_.async_wait([this](const boost::system::error_code &ec) {
        if (!ec) connect();
    });
}

void SocketAuthenticator::send_hello() {
    json::object hello;
    hello["type"] = "hello";
    json::object data;
    data["version"] = "trojan-revive";
    data["hostname"] = ""; // TODO: gethostname()
    hello["data"] = std::move(data);

    std::string line = json::serialize(hello);
    line.push_back('\n');
    boost::system::error_code ec;
    asio::write(socket_, asio::buffer(line), ec);
    if (ec) {
        Log::log_with_date_time("socket auth: write hello failed: " + ec.message(), Log::WARN);
        schedule_reconnect();
    }
}

void SocketAuthenticator::read_loop() {
    asio::async_read_until(socket_, in_buf_, '\n',
        [this](const boost::system::error_code &ec, std::size_t /*n*/) {
            if (ec) {
                Log::log_with_date_time("socket auth: read failed: " + ec.message(), Log::WARN);
                schedule_reconnect();
                return;
            }
            std::istream is(&in_buf_);
            std::string line;
            std::getline(is, line);
            handle_line(line);
            read_loop();
        });
}

void SocketAuthenticator::handle_line(const std::string &line) {
    boost::system::error_code ec;
    json::value v = json::parse(line, ec);
    if (ec || !v.is_object()) {
        Log::log_with_date_time("socket auth: bad json: " + ec.message(), Log::WARN);
        return;
    }
    const auto &obj = v.as_object();
    auto type_it = obj.find("type");
    if (type_it == obj.end() || !type_it->value().is_string()) return;
    std::string type{type_it->value().as_string()};
    auto data_it = obj.find("data");
    std::string data_str = (data_it != obj.end()) ? json::serialize(data_it->value()) : "";

    if (type == "users_snapshot") {
        apply_snapshot(data_str);
    } else if (type == "users_delta") {
        apply_delta(data_str);
    } else {
        // Unknown / not for us
    }
}

void SocketAuthenticator::apply_snapshot(const std::string &json_data) {
    boost::system::error_code ec;
    json::value v = json::parse(json_data, ec);
    if (ec || !v.is_object()) return;

    auto users_it = v.as_object().find("users");
    if (users_it == v.as_object().end() || !users_it->value().is_array()) return;

    std::unordered_set<std::string> next;
    for (const auto &u : users_it->value().as_array()) {
        if (!u.is_object()) continue;
        const auto &uo = u.as_object();
        auto pw = uo.find("pw_sha224");
        auto en = uo.find("enabled");
        if (pw == uo.end() || !pw->value().is_string()) continue;
        bool enabled = (en != uo.end() && en->value().is_bool()) ? en->value().as_bool() : true;
        if (enabled) {
            next.emplace(pw->value().as_string());
        }
    }
    {
        std::lock_guard<std::mutex> lock(users_mutex_);
        valid_passwords_.swap(next);
    }
    Log::log_with_date_time("socket auth: snapshot applied", Log::INFO);
}

void SocketAuthenticator::apply_delta(const std::string &json_data) {
    boost::system::error_code ec;
    json::value v = json::parse(json_data, ec);
    if (ec || !v.is_object()) return;
    const auto &obj = v.as_object();

    std::lock_guard<std::mutex> lock(users_mutex_);

    auto apply_array = [&](const char *key, bool add) {
        auto it = obj.find(key);
        if (it == obj.end() || !it->value().is_array()) return;
        for (const auto &u : it->value().as_array()) {
            if (add && u.is_object()) {
                auto pw = u.as_object().find("pw_sha224");
                if (pw == u.as_object().end() || !pw->value().is_string()) continue;
                valid_passwords_.emplace(pw->value().as_string());
            } else if (!add && u.is_string()) {
                valid_passwords_.erase(std::string(u.as_string()));
            }
        }
    };
    apply_array("added", true);
    apply_array("updated", true);

    auto rm = obj.find("removed");
    if (rm != obj.end() && rm->value().is_array()) {
        for (const auto &s : rm->value().as_array()) {
            if (s.is_string()) valid_passwords_.erase(std::string(s.as_string()));
        }
    }
}

bool SocketAuthenticator::auth(const std::string &password) {
    if (password.length() != PASSWORD_LENGTH) return false;
    std::lock_guard<std::mutex> lock(users_mutex_);
    return valid_passwords_.count(password) > 0;
}

void SocketAuthenticator::record(const std::string &password, std::uint64_t download, std::uint64_t upload) {
    if (password.length() != PASSWORD_LENGTH) return;
    std::lock_guard<std::mutex> lock(usage_mutex_);
    auto &acc = pending_usage_[password];
    acc.upload += upload;
    acc.download += download;
    acc.sessions += 1;
}

void SocketAuthenticator::schedule_report() {
    report_timer_.expires_after(std::chrono::seconds(REPORT_INTERVAL_SECONDS));
    report_timer_.async_wait([this](const boost::system::error_code &ec) {
        if (ec) return;
        flush_usage();
        if (connected_) schedule_report();
    });
}

void SocketAuthenticator::flush_usage() {
    std::unordered_map<std::string, UsageAccum> snapshot;
    {
        std::lock_guard<std::mutex> lock(usage_mutex_);
        snapshot.swap(pending_usage_);
    }
    if (snapshot.empty() || !connected_) return;

    json::array stats;
    for (const auto &kv : snapshot) {
        json::object o;
        o["pw_sha224"] = kv.first;
        o["upload"] = static_cast<std::int64_t>(kv.second.upload);
        o["download"] = static_cast<std::int64_t>(kv.second.download);
        o["sessions"] = static_cast<std::int64_t>(kv.second.sessions);
        stats.emplace_back(std::move(o));
    }
    json::object data;
    data["since_ts"] = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    data["stats"] = std::move(stats);

    json::object env;
    env["type"] = "usage_report";
    env["data"] = std::move(data);

    std::string line = json::serialize(env);
    line.push_back('\n');
    boost::system::error_code ec;
    asio::write(socket_, asio::buffer(line), ec);
    if (ec) {
        Log::log_with_date_time("socket auth: usage_report write failed: " + ec.message(), Log::WARN);
        schedule_reconnect();
    }
}

#endif // ENABLE_SOCKET_AUTH
