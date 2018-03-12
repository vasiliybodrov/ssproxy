/* *****************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Vasiliy V. Bodrov aka Bodro, Ryazan, Russia
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ************************************************************************** */

/* *****************************************************************************
 * Program name: ssproxy
 * Description: Simple SQL Proxy server
 * Version: 1.0
 * Date: March, 2018
 * Author: Vasiliy V. Bodrov aka Bodro (also called IPBSoftware or IPBS)
 *         +7 (930) 783-0-783 (Russia)
 * ************************************************************************** */

#include <map>
#include <deque>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <ostream>
#include <iostream>
#include <sstream>
#include <ios>
#include <iomanip>
#include <memory>
#include <new>
#include <chrono>
#include <random>
#include <functional>
#include <thread>
#include <mutex>
#include <exception>
#include <stdexcept>

#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cerrno>

#include <boost/shared_ptr.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/bind.hpp>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef PROXY_TCP_PORT
    #define PROXY_TCP_PORT 4880
#endif // PROXY_TCP_PORT

#ifndef SERVER_TCP_PORT
    #define SERVER_TCP_PORT 3306
#endif // SERVER_TCP_PORT

#ifndef SERVER_IP
    #define SERVER_IP "127.0.0.1"
#endif // SERVER_IP

#ifndef BUFFER_SIZE
    //#define BUFFER_SIZE 2048
    //#define BUFFER_SIZE 6
    #define BUFFER_SIZE 200
#endif // BUFFER_SIZE

#ifndef POLL_TIMEOUT
    #define POLL_TIMEOUT 1000
#endif // POLL_TIMEOUT

#ifndef MAX_SOCKET_COUNT
    #define MAX_SOCKET_COUNT 200
#endif // MAX_SOCKET_COUNT

namespace {
namespace config_ns {
    template<class PT, class AT>
    struct config {
    private:
        typedef config self;
    public:
        virtual ~config(void) = default;
        config(const config&) = default;
        config(config&&) = default;
        config& operator=(config&&) = default;
        config& operator=(config const&) = default;

        PT proxy_port;
        PT server_port;
        AT server_addr;

        ///
        /// \brief config
        /// \param pp
        /// \param sp
        /// \param sip
        ///
        explicit config(PT pp = PROXY_TCP_PORT,
                        PT sp = SERVER_TCP_PORT,
                        AT sip = SERVER_IP) :
        proxy_port(pp),
        server_port(sp),
        server_addr(sip) {
        }

        ///
        /// \brief get_default_proxy_port
        /// \return
        ///
        constexpr static inline PT get_default_proxy_port(void) noexcept {
            return PROXY_TCP_PORT;
        }

        ///
        /// \brief get_default_server_port
        /// \return
        ///
        constexpr static inline PT get_default_server_port(void) noexcept {
            return SERVER_TCP_PORT;
        }

        ///
        /// \brief get_default_server_addr
        /// \return
        ///
        constexpr static inline AT get_default_server_addr(void) noexcept {
            return SERVER_IP;
        }

        ///
        /// \brief set_proxy_port
        /// \param value
        ///
        void set_proxy_port(PT value) noexcept {
            this->proxy_port = value;
        }

        ///
        /// \brief set_server_port
        /// \param value
        ///
        void set_server_port(PT value) noexcept {
            this->server_port = value;
        }

        ///
        /// \brief set_server_addr
        /// \param value
        ///
        void set_server_addr(AT const& value) noexcept {
            this->server_addr = value;
        }

        ///
        /// \brief get_proxy_port
        /// \return
        ///
        PT get_proxy_port(void) const noexcept {
            return this->proxy_port;
        }

        ///
        /// \brief get_server_port
        /// \return
        ///
        PT get_server_port(void) const noexcept {
            return this->server_port;
        }

        ///
        /// \brief get_server_addr
        /// \return
        ///
        AT get_server_addr(void) const noexcept {
            return this->server_addr;
        }

//        friend std::ostream& operator<<(std::ostream& os,
//                                        config<PT,AT> const& cfg);
    };
} // namespace config_ns

///
/// \brief The addr_container class
///
class addr_container {
public:
    ///
    /// \brief addr_container
    /// \param address
    ///
    explicit addr_container(struct sockaddr_in address) : addr(address) {
    }

    friend bool operator==(addr_container const& l,
                           addr_container const& r);

    friend bool operator<(addr_container const& l,
                          addr_container const& r);

    friend bool operator>(addr_container const& l,
                          addr_container const& r);

    ~addr_container(void) = default;
    addr_container(addr_container const&) = default;
    addr_container(addr_container&&) = default;
    addr_container& operator=(addr_container&&) = default;
    addr_container& operator=(addr_container const&) = default;
private:
    struct sockaddr_in addr;
};

inline bool operator==(addr_container const& l,
                       addr_container const& r) {
    return (l.addr.sin_addr.s_addr == r.addr.sin_addr.s_addr) &&
           (l.addr.sin_port == r.addr.sin_port);
}

inline bool operator<(addr_container const& l,
                      addr_container const& r) {
    return (l.addr.sin_addr.s_addr < r.addr.sin_addr.s_addr) &&
           (l.addr.sin_port < r.addr.sin_port);
}

inline bool operator>(addr_container const& l,
                      addr_container const& r) {
    return (l.addr.sin_addr.s_addr > r.addr.sin_addr.s_addr) &&
           (l.addr.sin_port > r.addr.sin_port);
}

///
///
///
namespace proxy_ns {

typedef boost::uint16_t port_t;
typedef std::string addr_t;

typedef config_ns::config<port_t, addr_t> proxy_config;

///
/// \brief The Iproxy class
///
class Iproxy {
public:
    ///
    /// \brief run
    /// \return
    ///
    virtual int run(void) = 0;

    virtual ~Iproxy(void) = default;
    Iproxy(const Iproxy&) = delete;
    Iproxy(Iproxy&&) = delete;
    Iproxy& operator=(Iproxy&&) = delete;
    Iproxy& operator=(Iproxy const&) = delete;
protected:
    Iproxy(void) = default;
};

///
/// \brief The proxy class
///
class proxy : public Iproxy {
public:
    typedef proxy self;

    proxy(void) = delete;

    ///
    /// \brief ~proxy
    ///
    virtual ~proxy(void) {
        this->logger.join();
    }

    ///
    /// \brief proxy
    ///
    explicit proxy(proxy_config const& cfg) :
        proxy_addr({}),
        server_addr({}),
        proxy_addr_len(sizeof(this->proxy_addr)),
        server_addr_len(sizeof(this->server_addr)),
        listen_sd(-1),
        nfds(0),
        timeout(POLL_TIMEOUT),
        proxy_port(cfg.get_proxy_port()),
        server_port(cfg.get_server_port()),
        server_ip(cfg.get_server_addr()),
        compress_array(false),
        end_work(false),
        underloads({}),
        client_counter_sent({}),
        client_counter_recv({}),
        server_counter_sent({}),
        server_counter_recv({}),
        data({}),
        data_mutex(),
        logger(boost::bind(&self::logger_handler, this)) {

        int flags = 0;
        int on = 1;
        int rc = 0;

        // We have a warning if we use 'Release mode'
        boost::ignore_unused(rc);

        std::fill_n(reinterpret_cast<char*>(&server_addr),
                    proxy_addr_len, '\0');

        std::fill_n(reinterpret_cast<char*>(&proxy_addr),
                    server_addr_len, '\0');

        this->proxy_addr.sin_family = AF_INET;
        this->proxy_addr.sin_port = htons(proxy_port);
        this->proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);

        this->server_addr.sin_family = AF_INET;
        this->server_addr.sin_port = htons(server_port);
        this->server_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());

        this->listen_sd = ::socket(AF_INET, SOCK_STREAM, 0);
        rc = ::setsockopt(this->listen_sd, SOL_SOCKET, SO_REUSEADDR,
                          reinterpret_cast<char*>(&on), sizeof(on));
        assert(rc >= 0);

        rc = ::ioctl(this->listen_sd, FIONBIO, reinterpret_cast<char*>(&on));
        assert(rc >= 0);

        flags = ::fcntl(this->listen_sd, F_GETFL, 0);
        rc = ::fcntl(this->listen_sd, F_SETFL, flags | O_NONBLOCK);
        assert(rc >= 0);

        rc = ::bind(this->listen_sd,
                    reinterpret_cast<struct sockaddr*>(&this->proxy_addr),
                    sizeof(this->proxy_addr));
        assert(rc >= 0);

        rc = ::listen(this->listen_sd, 1);
        assert(rc >= 0);

        std::fill_n(reinterpret_cast<char*>(this->fds),
                    sizeof(this->fds), '\0');

        this->nfds = 0;

        this->fds[this->nfds].fd = this->listen_sd;
        this->fds[this->nfds].events = POLLIN;
        this->nfds++;
    }

    ///
    /// \brief run
    /// \return
    ///
    virtual int run(void) {
        do {
            int rc = ::poll(fds, nfds, timeout);
            assert(rc >= 0);

            if(rc) {
                nfds_t current_size = nfds;
                for(nfds_t i = 0; i < current_size; i++) {
                    if(0 == fds[i].revents) {
                        continue;
                    }
                    else if(!((fds[i].revents & POLLIN) ||
                              (fds[i].revents & POLLOUT) ||
                              (fds[i].revents & POLLHUP) ||
                              (fds[i].revents & POLLERR))) {
                        std::cout << ">>> Unknown event! Exit! ("
                                  << "revents = 0x" << std::hex
                                  << fds[i].revents
                                  << std::dec << " [" << fds[i].revents << "]"
                                  << ")" << std::endl;
                        ::exit(EXIT_SUCCESS);
                    }
                    else if((fds[i].revents & POLLHUP) ||
                            (fds[i].revents & POLLERR)) {
                        std::cout << ">>> Event ("
                                  << "revents = 0x" << std::hex
                                  << fds[i].revents
                                  << std::dec << " [" << fds[i].revents
                                  << "]"
                                  << ") is POLLHUP or POLLERR."
                                  << std::endl;
                        if(i % 2) {
                            // Client
                            std::cout << "> "
                                      << "Connection close due to error "
                                      << "(client): "
                                      << fds[i].fd << ":"
                                      << fds[i + 1].fd
                                      << "."
                                      << std::endl;
                            close_socket_client(i);
                        }
                        else {
                            // Server
                            std::cout << "> "
                                      << "Connection closed due to error "
                                      << "(server): "
                                      << fds[i - 1].fd << ":"
                                      << fds[i].fd
                                      << "."
                                    << std::endl;
                            close_socket_server(i);
                        }

                        break;
                    }
                    else {
                        if(fds[i].fd == -1) {
                            continue;
                        }
                        else if(fds[i].fd == listen_sd) {
                            this->new_connect();
                        }
                        else {
                            if(i % 2) {
                                // Client
                                if(!this->client_handler(i)) {
                                    break;
                                }
                            }
                            else {
                                // Server
                                if(!this->server_handler(i)) {
                                    break;
                                }
                            }
                        }
                    }
                }

                this->compress();
            }
        }
        while(!this->end_work);

        return EXIT_SUCCESS;
    }

    proxy(proxy const&) = delete;
    proxy(proxy&&) = delete;
    proxy& operator=(proxy&&) = delete;
    proxy& operator=(proxy const&) = delete;
protected:
    typedef std::map<addr_container, boost::int32_t> underloads_t;

    typedef std::map<int, boost::uint32_t> counter_t;

    typedef unsigned char data_value_t;
    typedef std::vector<unsigned char> data_value_container_t;
    typedef std::deque<data_value_container_t> data_t;

    ///
    /// \brief get_addr
    /// \param sd
    /// \param addr
    /// \return
    ///
    inline bool get_addr(int sd, struct sockaddr_in& addr) const noexcept {
        socklen_t addr_len  = sizeof(addr);

        int rc = ::getsockname(sd,
                               reinterpret_cast<struct sockaddr*>(&addr),
                               &addr_len);

        return (rc >= 0);
    }

    ///
    /// \brief client_handler
    /// \param i
    /// \return
    ///
    inline bool client_handler(nfds_t i) {
        return this->common_handler(i, i + 1,
                             this->client_counter_recv,
                             this->server_counter_sent,
                             boost::bind(&self::close_socket_client, this, i),
                             boost::bind(&self::send_to_logger,
                                         this, _1, _2, _3));
    }

    ///
    /// \brief server_handler
    /// \param i
    /// \return
    ///
    inline bool server_handler(nfds_t i) {
        return this->common_handler(i, i - 1,
                             this->server_counter_recv,
                             this->client_counter_sent,
                             boost::bind(&self::close_socket_server, this, i),
                             boost::bind(&self::send_to_logger_mock,
                                         this, _1, _2, _3));
    }

    ///
    /// \brief common_handler
    /// \param i1
    /// \param i2
    /// \param crecv
    /// \param csent
    /// \param fc
    /// \return
    ///
    template<class FC, class FL>
    inline bool common_handler(nfds_t i1, nfds_t i2,
                               counter_t& crecv,
                               counter_t& csent,
                               FC fc, FL fl) {
        if((fds[i1].revents & POLLIN) &&
           (fds[i2].revents & POLLOUT)) {

            int rc = 0;
            size_t len = 0;
            unsigned char buffer[BUFFER_SIZE] = { 0 };
            static constexpr size_t const buffer_size = sizeof(buffer);

            std::fill_n(reinterpret_cast<char*>(buffer),
                        buffer_size, '\0');

            rc = ::recv(fds[i1].fd, buffer, buffer_size, 0);
            if(rc < 0) {
                if(errno != EWOULDBLOCK &&
                   errno != EAGAIN) {
                    std::cout << "ERROR: recv "<< i1 <<" ("
                              << fds[i1].fd << "): "
                              << strerror(errno)
                              << std::endl;
                    return false;
                }
                else {
                    std::cout << ">>> EWOULDBLOCK or EAGAIN"
                              << " (server)"
                              << std::endl;
                }
            }
            else if(0 == rc) {
                std::cout << "> "
                          << "Connection close (server): "
                          << fds[i2].fd << ":"
                          << fds[i1].fd
                          << "."
                          << std::endl;
                fc();
                return false;
            }
            else {
                struct sockaddr_in addr;
                constexpr socklen_t const addr_size = sizeof(addr);

                std::fill_n(reinterpret_cast<char*>(&addr), addr_size, '\0');

                len = rc;

                crecv[fds[i1].fd] += len;

                this->get_addr(fds[i2].fd, addr);

                fl(addr, buffer, len);

                this->send_data(fds[i2].fd, buffer, len, csent);
            }
        }

        return true;
    }

    ///
    /// \brief close_socket_client
    /// \param i
    ///
    inline void close_socket_client(nfds_t i) {
        (void) ::close(fds[i].fd);
        (void) ::close(fds[i + 1].fd);

        this->client_counter_sent.erase(fds[i].fd);
        this->client_counter_recv.erase(fds[i].fd);

        this->server_counter_sent.erase(fds[i + 1].fd);
        this->server_counter_recv.erase(fds[i + 1].fd);

        this->fds[i].fd = -1;
        this->fds[i + 1].fd = -1;

        this->compress_array = true;
    }

    ///
    /// \brief close_socket_server
    /// \param i
    ///
    inline void close_socket_server(nfds_t i) {
        (void) ::close(fds[i].fd);
        (void) ::close(fds[i - 1].fd);

        this->client_counter_sent.erase(fds[i - 1].fd);
        this->client_counter_recv.erase(fds[i - 1].fd);

        this->server_counter_sent.erase(fds[i].fd);
        this->server_counter_recv.erase(fds[i].fd);

        this->fds[i].fd = -1;
        this->fds[i - 1].fd = -1;

        this->compress_array = true;
    }

    ///
    /// \brief new_connect
    ///
    inline void new_connect(void) {
        if(nfds < (2 * MAX_SOCKET_COUNT + 1)) {
            int rc = 0;
            int on = 1;
            int flags = 0;
            int new_sd = 0;
            int new_server_sd = 0;

            // We have a warning if we use 'Release mode'
            boost::ignore_unused(rc);

            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);

            int keep_alive_value = 1;
            socklen_t keep_alive_value_size =
                    sizeof(keep_alive_value);

            int tcp_no_delay_value = 0;
            socklen_t tcp_no_delay_value_size =
                    sizeof(tcp_no_delay_value);

            struct linger linger_value = {0, 0};
            socklen_t linger_value_size =
                    sizeof(linger_value);

            std::fill_n(reinterpret_cast<char*>(&client_addr),
                        client_addr_len, '\0');

            new_sd = ::accept(listen_sd,
                           reinterpret_cast<struct sockaddr*>(
                               &client_addr), &client_addr_len);
            assert(new_sd > 0);

            new_server_sd = ::socket(AF_INET, SOCK_STREAM, 0);
            assert(new_server_sd > 0);

            rc = ::connect(new_server_sd,
                           reinterpret_cast<struct sockaddr*>(
                               &this->server_addr),
                           this->server_addr_len);
            assert(rc >= 0);

            std::cout << "> "
                      << "New connection: "
                      << new_sd
                      << ":"
                      << new_server_sd
                      << " ("
                      << "sd(client)=" << new_sd
                      << "; sd(server)=" << new_server_sd
                      << "). Client: "
                      << inet_ntoa(client_addr.sin_addr)
                      << ":"
                      << ntohs(client_addr.sin_port)
                      << "."
                      << std::endl;

            rc = ::ioctl(new_sd, FIONBIO,
                         reinterpret_cast<char*>(&on));
            assert(rc >= 0);

            flags = ::fcntl(new_sd, F_GETFL, 0);
            rc = ::fcntl(new_sd, F_SETFL, flags | O_NONBLOCK);
            assert(rc >= 0);

            rc = ::setsockopt(new_sd, SOL_SOCKET,
                              SO_KEEPALIVE,
                              &keep_alive_value,
                              keep_alive_value_size);
            assert(rc >= 0);

            rc = ::setsockopt(new_sd, IPPROTO_TCP,
                              TCP_NODELAY,
                              &tcp_no_delay_value,
                              tcp_no_delay_value_size);
            assert(rc >= 0);

            rc = ::setsockopt(new_sd, SOL_SOCKET,
                              SO_LINGER, &linger_value,
                              linger_value_size);
            assert(rc >= 0);

            this->fds[this->nfds].fd = new_sd;
            this->fds[this->nfds].events = POLLIN | POLLOUT;
            this->nfds++;

            this->fds[this->nfds].fd = new_server_sd;
            this->fds[this->nfds].events = POLLIN | POLLOUT;
            this->nfds++;

            this->client_counter_sent[new_sd] = 0;
            this->client_counter_recv[new_sd] = 0;

            this->server_counter_sent[new_server_sd] = 0;
            this->server_counter_recv[new_server_sd] = 0;
        }
        else {
            std::cout << "> "
                      << "Can't add new connection!"
                      << std::endl;
        }
    }

    ///
    /// \brief send_data
    /// \param sd
    /// \param buf
    /// \param len
    /// \param counter
    ///
    inline void send_data(int sd, unsigned char const* buf,
                   size_t len, counter_t& counter) {
        int index = 0;

        do {
            ssize_t rc = ::send(sd, &buf[index], len, 0);
            if(rc < 0) {
                if(errno != EWOULDBLOCK &&
                   errno != EAGAIN) {
                    std::cout << "ERROR: 'sent' failed (socket=" << sd << "): "
                              << ::strerror(errno) << std::endl;
                    break;
                }
                else {
                    std::cout << ">>> EWOULDBLOCK or EAGAIN (server)."
                              << std::endl;

                    std::this_thread::sleep_for(std::chrono::milliseconds(200));

                    continue;
                }
            }
            else {
                assert(rc >= 0);
                counter[sd] += rc;
                if(static_cast<size_t>(rc) != len) {
                    len = len - rc;
                    index += rc;
                    continue;
                }
            }

            break;
        }
        while(true);
    }

    ///
    /// \brief compress
    ///
    inline void compress(void) {
        if(this->compress_array) {
            this->compress_array = false;
            for(nfds_t i = 0; i < this->nfds;) {
                if(this->fds[i].fd == -1) {
                    for(nfds_t j = i; j < this->nfds; j++) {
                        this->fds[j].fd = this->fds[j + 1].fd;
                    }
                    this->nfds--;
                }
                else {
                    i++;
                }
            }
        }
    }

    ///
    /// \brief send_to_logger_mock
    /// \param client
    /// \param buffer
    /// \param size
    ///
    inline void send_to_logger_mock(struct sockaddr_in const& client,
                                    unsigned char const* buffer,
                                    size_t size) {
        boost::ignore_unused(client, buffer, size);
    }

    ///
    /// \brief send_to_logger
    /// \param client
    /// \param buffer
    /// \param size
    ///
    inline void send_to_logger(struct sockaddr_in const& client,
                               unsigned char const* buffer,
                               size_t size) {
        std::lock_guard<std::mutex> lock(this->data_mutex);

        data_value_container_t v;
        constexpr size_t const sc = sizeof(client);
        char const* const c = reinterpret_cast<char const* const>(&client);

        std::copy(c, c + sc, std::back_inserter(v));
        std::copy(buffer, buffer + size, std::back_inserter(v));
        this->data.push_back(std::move(v));
    }

    ///
    /// \brief send_to_logger_back
    /// \param client
    /// \param buffer
    /// \param size
    ///
    inline void send_to_logger_back(struct sockaddr_in const& client,
                                    unsigned char const* buffer,
                                    size_t size) {
        std::lock_guard<std::mutex> lock(this->data_mutex);

        data_value_container_t v;
        constexpr size_t const sc = sizeof(client);
        char const* const c = reinterpret_cast<char const* const>(&client);

        std::copy(c, c + sc, std::back_inserter(v));
        std::copy(buffer, buffer + size, std::back_inserter(v));
        this->data.push_front(std::move(v));
    }

    ///
    /// \brief logger_handler
    ///
    void logger_handler(void) {
        std::ofstream log("log.txt", std::ofstream::out);

        do {
            data_value_container_t v;

            [](auto p, auto t, auto f) {
                p() ? t() : f();
            }(
            // predicate (p)
            [this, &v]() -> bool {
                std::lock_guard<std::mutex> lock(this->data_mutex);
                if(!this->data.empty()) {
                    typename data_t::const_reference _v = this->data.front();
                    v = std::move(_v);
                    this->data.pop_front();
                    return true;
                }
                return false;
            },
            // Do it if predicate is true (t)
            [this, &v, &log](){
                this->data_parser(log, v.data(), v.size());
            },
            // Do it if predicate is false (f)
            [](){
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            });
        }
        while(!this->end_work);

        log.close();
    }

    ///
    /// \brief is_underload
    /// \param addr
    /// \return
    ///
    inline bool is_underload(struct sockaddr_in const& addr,
                             boost::int32_t& len) const {
        addr_container a(addr);
        auto res = this->underloads.find(a);

        if(res != this->underloads.end()) {
            len = res->second;
            return true;
        }
        len = 0;
        return false;
    }

    ///
    /// \brief set_no_underload
    /// \param addr
    ///
    inline void set_no_underload(struct sockaddr_in const& addr) {
        addr_container a(addr);
        this->underloads.erase(a);
    }

    ///
    /// \brief set_yes_underload
    /// \param addr
    ///
    inline void set_yes_underload(struct sockaddr_in const& addr,
                                  boost::int32_t len) {
        addr_container a(addr);
        this->underloads[a] = len;
    }

    ///
    /// \brief data_parser
    /// \param l
    /// \param d
    /// \param s
    ///
    inline void data_parser(std::ofstream& l,
                            unsigned char const* d,
                            size_t s) {
        typedef struct packet_header_s {
            struct sockaddr_in addr;
            char payload_length[3];
            char sequence_id[1];
            char command[1];
            char payload;

            constexpr inline boost::uint16_t get_addr_len(void)
            const noexcept {
                return sizeof(struct sockaddr_in);
            }

            inline struct sockaddr_in get_sockaddr(void)
            const noexcept {
                return this->addr;
            }

            inline char* get_address(void)
            const noexcept {
                return inet_ntoa(this->addr.sin_addr);
            }

            inline boost::uint16_t get_port(void)
            const noexcept {
                return ntohs(this->addr.sin_port);
            }

            constexpr inline boost::uint16_t get_mysql_header_length(void)
            const noexcept {
                return 4;
            }

            inline boost::uint32_t get_payload_length(void)
            const noexcept {
                return (0x00FF0000 & (this->payload_length[2] << 0x10)) |
                       (0x0000FF00 & (this->payload_length[1] << 0x08)) |
                       (0x000000FF & (this->payload_length[0] << 0x00));
            }

            inline boost::uint16_t get_sequence_id(void)
            const noexcept {
                return static_cast<boost::uint16_t>(this->sequence_id[0]);
            }

            inline boost::uint16_t get_command(void)
            const noexcept {
                return static_cast<boost::uint16_t>(this->command[0]);
            }

            constexpr inline boost::uint32_t get_start_data(void)
            const noexcept {
                return sizeof(struct packet_header_s);
            }

            inline boost::uint32_t get_data_len(void)
            const noexcept {
                return this->get_payload_length() - sizeof(this->command);
            }
        } __attribute__((packed)) packet_header_t;

        packet_header_t const* pkt_hdr =
                reinterpret_cast<packet_header_t const*>(d);

        bool flag_underload = false;
        boost::int32_t under_len = 0;
        boost::uint32_t _start = 0;
        boost::uint32_t _end = 0;
        boost::int32_t overunderload = 0; // Недополученные данные mysql
        boost::int32_t useful_size = s - pkt_hdr->get_addr_len(); // Реальные данные
        boost::int32_t useful_data_size = 0; // Реальные mysql данные
        boost::int32_t output_data_size = 0; // Сколько данных выводится

        // TODO!!! Проблема с одним байтом!!!
        // Попробовать разнгые размеры буффера
        if(this->is_underload(pkt_hdr->get_sockaddr(), under_len)) {
            flag_underload = true;
            _start = pkt_hdr->get_addr_len();

            useful_data_size = useful_size;

            overunderload = under_len + useful_data_size;

            output_data_size = (overunderload < 0) ?
                        useful_data_size :
                        (useful_data_size - overunderload);

            _end = pkt_hdr->get_addr_len() +
                   output_data_size;

            if(overunderload >= 0) {
                this->set_no_underload(pkt_hdr->get_sockaddr());
            }
        }
        else {
            _start = pkt_hdr->get_start_data();

            useful_data_size = useful_size - pkt_hdr->get_mysql_header_length();

            overunderload = useful_data_size - pkt_hdr->get_payload_length();

            output_data_size = (overunderload < 0) ?
                        useful_data_size :
                        (useful_data_size - overunderload);

            _end = pkt_hdr->get_addr_len() +
                   pkt_hdr->get_mysql_header_length() +
                   output_data_size + 1;
        }

        if(overunderload > 0) {
            // Overload
            // Данных пришло больше, чем у нас в mysql пакете.
            // Надо отправить их обратно
            this->send_to_logger_back(pkt_hdr->get_sockaddr(),
                                      d + _end, s - _end);
        }
        else if(overunderload < 0) {
            // Underload
            this->set_yes_underload(pkt_hdr->get_sockaddr(),
                                    (overunderload));
        }

//        std::cout << "Underload: " << overunderload << std::endl;
//        exit(0);

        if(flag_underload) {
            std::cout          << pkt_hdr->get_address() << ":"
                                << std::dec << pkt_hdr->get_port()
                                << ": [" << _end - _start << "]: ";
        }
        else {
            /*
            l << pkt_hdr->get_address() << ":"
              << std::dec << pkt_hdr->get_port()
              << " ("
              << "Len: " << std::dec << pkt_hdr->get_payload_length() << "; "
              << "Seq: " << std::dec << pkt_hdr->get_sequence_id() << "; "
              << "Command: " << std::hex << "0x" << pkt_hdr->get_command()
              << "): ";
*/
            std::cout          << pkt_hdr->get_address() << ":"
                                << std::dec << pkt_hdr->get_port()
                                << " ("
                                << "Len: " << std::dec << pkt_hdr->get_payload_length() << "; "
                                << "Seq: " << std::dec << pkt_hdr->get_sequence_id() << "; "
                                << "Command: " << std::hex << "0x" << pkt_hdr->get_command()
                                << "): [" << _end - _start << "]: ";
        }

        std::for_each(d + _start, d + _end, [&l](auto x) {
            l << x;
            std::cout << x;
        });

        l << std::endl << std::flush;
        std::cout << std::endl << std::flush;
    }
private:
    struct sockaddr_in proxy_addr;
    struct sockaddr_in server_addr;

    socklen_t const proxy_addr_len;
    socklen_t const server_addr_len;

    int listen_sd;
    struct pollfd fds[2 * MAX_SOCKET_COUNT + 1];
    nfds_t nfds;
    int timeout;
    boost::uint16_t proxy_port;
    boost::uint16_t server_port;
    std::string server_ip;
    bool compress_array;
    bool end_work;
    underloads_t underloads;

    counter_t client_counter_sent;
    counter_t client_counter_recv;

    counter_t server_counter_sent;
    counter_t server_counter_recv;

    data_t data;
    mutable std::mutex data_mutex;
    std::thread logger;
};

} // namespace proxy_ns

///
/// \brief The IEproxy class
///
class IEproxy : public std::exception {
protected:
    IEproxy(void) = default;
public:
    virtual char const* what(void) const noexcept {
        static std::string const msg("IEproxy");
        return msg.c_str();
    }

    virtual ~IEproxy(void) = default;
    IEproxy(const IEproxy&) = default;
    IEproxy(IEproxy&&) = default;
    IEproxy& operator=(IEproxy&&) = default;
    IEproxy& operator=(IEproxy const&) = default;
};

///
/// \brief The EInvalidArgument class
///
class EInvalidArgument : public IEproxy {
public:
    virtual char const* what(void) const noexcept {
        static std::string const msg("Invalid argument!");
        return msg.c_str();
    }

    EInvalidArgument(void) = default;
    virtual ~EInvalidArgument(void) = default;
    EInvalidArgument(const EInvalidArgument&) = default;
    EInvalidArgument(EInvalidArgument&&) = default;
    EInvalidArgument& operator=(EInvalidArgument&&) = default;
    EInvalidArgument& operator=(EInvalidArgument const&) = default;
};

///
///
///
template <class TSrcValue, class TResValue, class TSetter, class TResult = bool>
TResult set_value(TSrcValue value, TSetter setter, TResValue default_value) {
    TResValue res_value = default_value;
    TResult res = true;

    try {
        res_value = boost::lexical_cast<TResValue>(value);
    }
    catch(boost::bad_lexical_cast const& ex) {
        std::cerr << "Can't set value! ("
                  << __FILE__
                  << ":"
                  << __LINE__
                  << ")"
                  << std::endl;
        std::cerr << ex.what() << std::endl;

        res = false;

        throw;
    }

    setter(res_value);

    return res;
}

template<class TArgs, class TCfg = proxy_ns::proxy_config>
void set_cfg_values1(TCfg& cfg, TArgs values) {
    ::set_value(values[1], boost::bind(&TCfg::set_proxy_port, &cfg, _1),
            TCfg::get_default_proxy_port());
}

template<class TArgs, class TCfg = proxy_ns::proxy_config>
void set_cfg_values2(TCfg& cfg, TArgs values) {
    ::set_cfg_values1(cfg, values);
    ::set_value(values[2], boost::bind(&TCfg::set_server_port, &cfg, _1),
            TCfg::get_default_server_port());
}

template<class TArgs, class TCfg = proxy_ns::proxy_config>
void set_cfg_values3(TCfg& cfg, TArgs values) {
    ::set_cfg_values2(cfg, values);
    ::set_value(values[3], boost::bind(&TCfg::set_server_addr, &cfg, _1),
            TCfg::get_default_server_addr());
}

std::ostream& operator<<(std::ostream& os, proxy_ns::proxy_config const& cfg) {
    os << "PROXY_PORT=" << cfg.proxy_port << "; "
       << "SERVER_PORT=" << cfg.server_port << "; "
       << "SERVER_ADDR=" << cfg.server_addr;
    return os;
}

} // namespace

///
/// \brief main
/// \return
/// \note
///     argv[0] - program name
///     argv[1] - proxy port
///     argv[2] - server port
///     argv[3] - server ip address
int main(int argc, char** argv) {
    using namespace std;
    namespace prx = proxy_ns;

    prx::proxy_config cfg;

    switch(argc) {
    case 1:
        cout << "NOTE: You can use: " << argv[0]
             << " [<PROXY_PORT>"
             << " <SERVER_PORT>"
             << " <SERVER_IP>]"
             << endl << endl;
        break;
    case 2:
        ::set_cfg_values1(cfg, argv);
        break;
    case 3:
        ::set_cfg_values2(cfg, argv);
        break;
    case 4:
        ::set_cfg_values3(cfg, argv);
        break;
    default:
        throw EInvalidArgument();
    }

    cout << "Args: (" << cfg << ")" << endl << endl;

    boost::scoped_ptr<prx::Iproxy> $(new prx::proxy(cfg));

    return $.get()->run();
}

/* *****************************************************************************
 * End of file
 * ************************************************************************** */
