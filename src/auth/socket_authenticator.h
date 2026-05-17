/*
 * This file is part of the trojan project.
 *
 * SocketAuthenticator: connects to the trojan-manager UNIX socket and
 * maintains an in-memory set of valid user passwords. Updated by
 * users_snapshot and users_delta messages pushed from the manager.
 * Usage bytes are batched and reported back via usage_report.
 *
 * Wire format: newline-delimited JSON. See trojan2/internal/socket/protocol.go.
 */

#ifndef _SOCKET_AUTHENTICATOR_H_
#define _SOCKET_AUTHENTICATOR_H_

#ifdef ENABLE_SOCKET_AUTH

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/streambuf.hpp>

class SocketAuthenticator {
public:
    SocketAuthenticator(boost::asio::io_context &io_context, std::string socket_path);

    // Connect (and auto-reconnect on failure). Non-blocking; returns immediately.
    void start();

    // Hot-path auth check. Safe to call from any io_context strand without
    // additional synchronization.
    bool auth(const std::string &password);

    // Accumulate usage bytes for the next report flush. Lock-free fast path.
    void record(const std::string &password, std::uint64_t download, std::uint64_t upload);

private:
    enum {
        PASSWORD_LENGTH = 56,
        REPORT_INTERVAL_SECONDS = 30,
        RECONNECT_DELAY_SECONDS = 2,
    };

    struct UsageAccum {
        std::uint64_t upload = 0;
        std::uint64_t download = 0;
        std::uint64_t sessions = 0;
    };

    void connect();
    void schedule_reconnect();
    void send_hello();
    void read_loop();
    void handle_line(const std::string &line);
    void apply_snapshot(const std::string &json);
    void apply_delta(const std::string &json);
    void schedule_report();
    void flush_usage();

    boost::asio::io_context &io_context_;
    std::string socket_path_;
    boost::asio::local::stream_protocol::socket socket_;
    boost::asio::streambuf in_buf_;
    boost::asio::steady_timer reconnect_timer_;
    boost::asio::steady_timer report_timer_;
    std::atomic<bool> connected_{false};

    mutable std::mutex users_mutex_;
    std::unordered_set<std::string> valid_passwords_;

    std::mutex usage_mutex_;
    std::unordered_map<std::string, UsageAccum> pending_usage_;
};

#endif // ENABLE_SOCKET_AUTH
#endif // _SOCKET_AUTHENTICATOR_H_
