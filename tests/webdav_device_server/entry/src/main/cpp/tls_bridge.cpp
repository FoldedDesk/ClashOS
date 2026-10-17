// Removable device fixture only. TLS terminates here and relays exclusively to
// the independent ArkTS fixture at 127.0.0.1:18099; no arbitrary destination API.
// This avoids TLSSocketServer's first-record callback race on the PC simulator.
#include <napi/native_api.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <psa/crypto.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <poll.h>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <cerrno>

namespace {
struct Bridge {
    std::atomic<bool> running{false};
    int listener=-1;
    std::thread acceptor;
    std::mutex mutex;
    std::condition_variable idle;
    std::set<int> sockets;
    int workers=0;
    mbedtls_ssl_config config;
    mbedtls_x509_crt certificate;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context rng;
    struct Bio { int fd; bool nonblocking=false; };
    Bridge() { mbedtls_ssl_config_init(&config);mbedtls_x509_crt_init(&certificate);mbedtls_pk_init(&key);mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_init(&rng); }
    ~Bridge() { stop();mbedtls_ssl_config_free(&config);mbedtls_x509_crt_free(&certificate);mbedtls_pk_free(&key);mbedtls_ctr_drbg_free(&rng);mbedtls_entropy_free(&entropy); }
    static void timeout(int fd) { timeval value{6,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&value,sizeof(value));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&value,sizeof(value)); }
    static int sendBio(void* context,const unsigned char* data,size_t size) {
        auto* bio=static_cast<Bio*>(context);ssize_t n;
        do {n=send(bio->fd,data,size,MSG_NOSIGNAL);}while(n<0&&errno==EINTR);
        return n<0?MBEDTLS_ERR_NET_SEND_FAILED:static_cast<int>(n);
    }
    static int readBio(void* context,unsigned char* data,size_t size) {
        auto* bio=static_cast<Bio*>(context);ssize_t n;
        do {n=recv(bio->fd,data,size,bio->nonblocking?MSG_DONTWAIT:0);}while(n<0&&errno==EINTR);
        if(n<0)return (errno==EAGAIN||errno==EWOULDBLOCK)?(bio->nonblocking?MBEDTLS_ERR_SSL_WANT_READ:MBEDTLS_ERR_SSL_TIMEOUT):MBEDTLS_ERR_NET_RECV_FAILED;
        return static_cast<int>(n);
    }
    static bool sendPlain(int fd,const unsigned char* bytes,size_t size) {
        while(size){const auto n=send(fd,bytes,size,MSG_NOSIGNAL);if(n<0&&errno==EINTR)continue;if(n<=0)return false;bytes+=n;size-=static_cast<size_t>(n);}return true;
    }
    void handle(int client) {
        mbedtls_ssl_context ssl;mbedtls_ssl_init(&ssl);Bio bio{client};int upstream=-1;
        bool ok=mbedtls_ssl_setup(&ssl,&config)==0;mbedtls_ssl_set_bio(&ssl,&bio,sendBio,readBio,nullptr);
        if(ok){int result;do{result=mbedtls_ssl_handshake(&ssl);}while(result==MBEDTLS_ERR_SSL_WANT_READ||result==MBEDTLS_ERR_SSL_WANT_WRITE);ok=result==0;}
        if(ok){
            upstream=socket(AF_INET,SOCK_STREAM,0);timeout(upstream);sockaddr_in target{};target.sin_family=AF_INET;target.sin_addr.s_addr=htonl(INADDR_LOOPBACK);target.sin_port=htons(18099);
            {std::lock_guard<std::mutex> lock(mutex);if(running&&upstream>=0)sockets.insert(upstream);else ok=false;}
            if(ok)ok=connect(upstream,reinterpret_cast<sockaddr*>(&target),sizeof(target))==0;
        }
        bio.nonblocking=true;unsigned char bytes[16384];
        while(ok&&running){
            const bool buffered=mbedtls_ssl_check_pending(&ssl)!=0;
            pollfd fds[2]={{client,POLLIN,0},{upstream,POLLIN,0}};const int ready=poll(fds,2,buffered?0:1000);
            if(ready<0){if(errno==EINTR)continue;break;}
            if(buffered||fds[0].revents){
                const int n=mbedtls_ssl_read(&ssl,bytes,sizeof(bytes));
                if(n==MBEDTLS_ERR_SSL_WANT_READ||n==MBEDTLS_ERR_SSL_WANT_WRITE||n==MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET){}
                else if(n<=0)break;
                else if(!sendPlain(upstream,bytes,static_cast<size_t>(n)))break;
            }
            if(fds[1].revents){
                const auto n=recv(upstream,bytes,sizeof(bytes),0);if(n<=0)break;
                size_t offset=0;
                while(offset<static_cast<size_t>(n)&&running){
                    const int sent=mbedtls_ssl_write(&ssl,bytes+offset,static_cast<size_t>(n)-offset);
                    if(sent==MBEDTLS_ERR_SSL_WANT_READ||sent==MBEDTLS_ERR_SSL_WANT_WRITE){pollfd retry{client,static_cast<short>(sent==MBEDTLS_ERR_SSL_WANT_READ?POLLIN:POLLOUT),0};if(poll(&retry,1,6000)<=0){ok=false;break;}continue;}
                    if(sent<=0){ok=false;break;}offset+=static_cast<size_t>(sent);
                }
            }
        }
        mbedtls_ssl_close_notify(&ssl);mbedtls_ssl_free(&ssl);
        {std::lock_guard<std::mutex> lock(mutex);sockets.erase(client);if(upstream>=0)sockets.erase(upstream);close(client);if(upstream>=0)close(upstream);--workers;idle.notify_all();}
    }
    bool start(const std::string& cert,const std::string& pem) {
        if(running)return true;
        if(cert.empty()||pem.empty()||psa_crypto_init()!=PSA_SUCCESS||mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,nullptr,0)!=0||
           mbedtls_x509_crt_parse(&certificate,reinterpret_cast<const unsigned char*>(cert.c_str()),cert.size()+1)!=0||
           mbedtls_pk_parse_key(&key,reinterpret_cast<const unsigned char*>(pem.c_str()),pem.size()+1,nullptr,0,mbedtls_ctr_drbg_random,&rng)!=0||
           mbedtls_ssl_config_defaults(&config,MBEDTLS_SSL_IS_SERVER,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT)!=0)return false;
        mbedtls_ssl_conf_rng(&config,mbedtls_ctr_drbg_random,&rng);mbedtls_ssl_conf_authmode(&config,MBEDTLS_SSL_VERIFY_NONE);
        static const char* alpn[]={"http/1.1",nullptr};
        if(mbedtls_ssl_conf_alpn_protocols(&config,alpn)!=0||mbedtls_ssl_conf_own_cert(&config,&certificate,&key)!=0)return false;
        listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)return false;int reuse=1;setsockopt(listener,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(18098);
        if(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))!=0||listen(listener,8)!=0){close(listener);listener=-1;return false;}
        running=true;acceptor=std::thread([this]{
            while(running){pollfd watch{listener,POLLIN,0};if(poll(&watch,1,500)<=0)continue;
                const int client=accept(listener,nullptr,nullptr);if(client<0)continue;timeout(client);
                {std::lock_guard<std::mutex> lock(mutex);if(!running||workers>=16){close(client);continue;}sockets.insert(client);++workers;}
                try{std::thread([this,client]{handle(client);}).detach();}catch(...){std::lock_guard<std::mutex> lock(mutex);sockets.erase(client);close(client);--workers;}
            }
        });return true;
    }
    void stop(){
        if(!running.exchange(false))return;
        if(listener>=0)shutdown(listener,SHUT_RDWR);if(acceptor.joinable())acceptor.join();if(listener>=0)close(listener);listener=-1;
        std::unique_lock<std::mutex> lock(mutex);for(int fd:sockets)shutdown(fd,SHUT_RDWR);idle.wait(lock,[this]{return workers==0;});
    }
} bridge;
std::string stringArg(napi_env env,napi_value value){size_t size=0;if(napi_get_value_string_utf8(env,value,nullptr,0,&size)!=napi_ok||size>16384)return {};std::vector<char> bytes(size+1);if(napi_get_value_string_utf8(env,value,bytes.data(),bytes.size(),&size)!=napi_ok)return {};return {bytes.data(),size};}
napi_value start(napi_env env,napi_callback_info info){size_t count=2;napi_value args[2]{};napi_get_cb_info(env,info,&count,args,nullptr,nullptr);napi_value result;napi_get_boolean(env,count==2&&bridge.start(stringArg(env,args[0]),stringArg(env,args[1])),&result);return result;}
napi_value stop(napi_env env,napi_callback_info){bridge.stop();napi_value result;napi_get_undefined(env,&result);return result;}
napi_value init(napi_env env,napi_value exports){napi_property_descriptor methods[]={{"start",nullptr,start,nullptr,nullptr,nullptr,napi_default,nullptr},{"stop",nullptr,stop,nullptr,nullptr,nullptr,napi_default,nullptr}};napi_define_properties(env,exports,2,methods);return exports;}
}
NAPI_MODULE(vlessfixture,init)
