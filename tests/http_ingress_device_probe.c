/* Public fixed-origin integration client. Build with the HarmonyOS SDK clang.
 * No app storage, private profile, node credentials or Internet host is read. */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static const unsigned char body[]="data\0xyz";
static const unsigned char chunks[]="4;ext=\"a,b\"\r\ndata\r\n4\r\n\0xyz\r\n0\r\nX-Trailer: ok\r\n\r\n";
static int connect_local(unsigned port) {
    int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return -1;
    struct timeval timeout={4,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof timeout);setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof timeout);
    struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_port=htons(port);inet_pton(AF_INET,"127.0.0.1",&endpoint.sin_addr);
    if(connect(fd,(struct sockaddr*)&endpoint,sizeof endpoint)){close(fd);return -1;}return fd;
}
static int connect_proxy(void) {return connect_local(7890);}
static int write_all(int fd,const void* data,size_t size) {
    const unsigned char* bytes=data;
    while(size){ssize_t count=send(fd,bytes,size,0);if(count<0&&errno==EINTR)continue;if(count<=0)return 0;bytes+=count;size-=(size_t)count;}return 1;
}
static int exact(int fd,void* data,size_t size) {
    unsigned char* bytes=data;
    while(size){ssize_t count=recv(fd,bytes,size,0);if(count<0&&errno==EINTR)continue;if(count<=0)return 0;bytes+=count;size-=(size_t)count;}return 1;
}
static int head(int fd,char* output,size_t capacity) {
    size_t used=0;
    while(used+1<capacity){if(!exact(fd,output+used,1))return 0;used++;output[used]=0;if(used>=4&&!memcmp(output+used-4,"\r\n\r\n",4))return 1;}return 0;
}
static int pipeline(void) {
    int fd=connect_proxy();if(fd<0)return 0;
    const char* wire="GET http://origin1.fixture.test:18105/1 HTTP/1.1\r\nHost: origin1.fixture.test:18105\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\n\r\n"
        "GET http://origin2.fixture.test:18105/2 HTTP/1.1\r\nHost: origin2.fixture.test:18105\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\nConnection: close\r\n\r\n";
    char header[8192],payload[8];int ok=write_all(fd,wire,strlen(wire));
    ok=ok&&head(fd,header,sizeof header)&&strstr(header,"200 OK")&&strstr(header,"Connection: keep-alive")&&exact(fd,payload,8)&&!memcmp(payload,"origin-1",8);
    ok=ok&&head(fd,header,sizeof header)&&strstr(header,"200 OK")&&exact(fd,payload,8)&&!memcmp(payload,"origin-2",8);close(fd);return ok;
}
static int upload(int mode) {
    int fd=connect_proxy();if(fd<0)return 0;
    char header[8192],request[2048],payload[8];
    snprintf(request,sizeof request,"POST http://origin.fixture.test:18105/upload HTTP/1.1\r\nHost: wrong.fixture.test\r\nConnection: close, X-Hop\r\nX-Hop: public-hop\r\nProxy-Authorization: Basic cHVibGljOnNlY3JldA==\r\n%s\r\n",mode==1?"Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n":mode==2?"Content-Length: 65536\r\n":"Content-Length: 8,8\r\n");
    int ok=write_all(fd,request,strlen(request));
    if(mode==2){unsigned char block[1024];for(size_t at=0;ok&&at<65536;at+=sizeof block){for(size_t i=0;i<sizeof block;i++)block[i]=(unsigned char)((at+i)*13+7);ok=write_all(fd,block,sizeof block);}}
    else if(mode==1){for(size_t i=0;ok&&i<sizeof chunks-1;i++)ok=write_all(fd,chunks+i,1);}
    else ok=ok&&write_all(fd,body,sizeof body-1);
    ok=ok&&head(fd,header,sizeof header)&&strstr(header,"200 OK")&&exact(fd,payload,8)&&!memcmp(payload,"uploaded",8);close(fd);return ok;
}
static int chunked_response(int legacy) {
    int fd=connect_proxy();if(fd<0)return 0;
    char request[512],header[8192];unsigned char payload[sizeof chunks];
    snprintf(request,sizeof request,"GET http://origin.fixture.test:18105/chunked HTTP/1.%d\r\nHost: origin.fixture.test:18105\r\nConnection: close\r\n\r\n",legacy?0:1);
    int ok=write_all(fd,request,strlen(request))&&head(fd,header,sizeof header)&&strstr(header,"200 OK")&&!strstr(header,"Content-Length")&&!strstr(header,"X-Hop");
    if(legacy)ok=ok&&!strstr(header,"Transfer-Encoding")&&exact(fd,payload,sizeof body-1)&&!memcmp(payload,body,sizeof body-1);
    else ok=ok&&strstr(header,"Transfer-Encoding: chunked")&&exact(fd,payload,sizeof chunks-1)&&!memcmp(payload,chunks,sizeof chunks-1);
    close(fd);return ok;
}
static int expect_continue(void) {
    int fd=connect_proxy();if(fd<0)return 0;
    const char* request="POST http://origin.fixture.test:18105/expect HTTP/1.1\r\nHost: origin.fixture.test:18105\r\nExpect: 100-continue\r\nContent-Length: 8\r\nConnection: close\r\n\r\n";
    char header[8192],payload[8];int ok=write_all(fd,request,strlen(request));
    ok=ok&&head(fd,header,sizeof header)&&strstr(header,"103 Early Hints")&&head(fd,header,sizeof header)&&strstr(header,"100 Continue");
    ok=ok&&write_all(fd,body,sizeof body-1)&&head(fd,header,sizeof header)&&strstr(header,"200 OK")&&exact(fd,payload,8)&&!memcmp(payload,"uploaded",8);close(fd);return ok;
}
static int websocket(void) {
    int fd=connect_proxy();if(fd<0)return 0;
    const char* request="GET http://origin.fixture.test:18105/socket HTTP/1.1\r\nHost: origin.fixture.test:18105\r\nConnection: Upgrade, X-Hop\r\nX-Hop: public-hop\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const unsigned char frame[]={129,130,1,2,3,4,105,107},expected[]={129,5,104,101,108,108,111,136,2,3,232};
    unsigned char wire[2048],payload[sizeof expected];size_t size=strlen(request);memcpy(wire,request,size);memcpy(wire+size,frame,sizeof frame);
    char header[8192];int ok=write_all(fd,wire,size+sizeof frame)&&head(fd,header,sizeof header)&&strstr(header,"101 Switching Protocols")&&strstr(header,"Connection: Upgrade")&&strstr(header,"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    ok=ok&&exact(fd,payload,sizeof payload)&&!memcmp(payload,expected,sizeof expected);close(fd);return ok;
}
static int release_origin(void) {
    int fd=connect_local(18088);if(fd<0)return 0;
    const char* request="POST /test-admin/http/release HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    char header[8192],body[2];int ok=write_all(fd,request,strlen(request))&&head(fd,header,sizeof header)&&strstr(header,"200 Fixture")&&exact(fd,body,2)&&!memcmp(body,"{}",2);close(fd);return ok;
}
static int early_final(int mode) {
    int fd=connect_proxy();if(fd<0)return 0;
    char request[1024],header[8192],body[32];const char* kind=mode==0?"length":mode==1?"chunked":"eof";
    snprintf(request,sizeof request,"POST http://origin.fixture.test:18105/early-%s HTTP/1.1\r\nHost: origin.fixture.test:18105\r\nExpect: 100-continue\r\n%s\r\n",kind,mode==1?"Transfer-Encoding: chunked\r\n":"Content-Length: 1024\r\n");
    int ok=write_all(fd,request,strlen(request))&&head(fd,header,sizeof header)&&strstr(header,"413 Payload Too Large")&&strstr(header,"Connection: close");
    if(mode==1)ok=ok&&write_all(fd,"not-a-chunk\r\n",13);
    if(mode==2)ok=ok&&write_all(fd,"ignored-upload",14);
    shutdown(fd,SHUT_WR);
    ok=release_origin()&&ok;
    const char* expected=mode==1?"8\r\ndenied!!\r\n0\r\n\r\n":"denied!!";
    ok=ok&&exact(fd,body,strlen(expected))&&!memcmp(body,expected,strlen(expected));close(fd);return ok;
}
static int invalid_framing(void) {
    int fd=connect_proxy();if(fd<0)return 0;
    const char* request="POST http://origin.fixture.test:18105/upload HTTP/1.1\r\nHost: origin.fixture.test:18105\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    char header[8192];int ok=write_all(fd,request,strlen(request))&&head(fd,header,sizeof header)&&strstr(header,"400 Bad Request");close(fd);return ok;
}
static int report(const char* name,int passed) {printf("{\"case\":\"%s\",\"passed\":%s}\n",name,passed?"true":"false");fflush(stdout);return !passed;}
int main(int argc,char** argv) {
    signal(SIGPIPE,SIG_IGN);int failed=0;
    if(argc==2&&!strcmp(argv[1],"pipeline"))return report("pipeline",pipeline());
    if(argc==2&&!strcmp(argv[1],"websocket"))return report("websocket",websocket());
    if(argc==2&&!strcmp(argv[1],"early-final")){failed+=report("early-length",early_final(0));failed+=report("early-chunked",early_final(1));failed+=report("early-eof",early_final(2));return failed?1:0;}
    failed+=report("pipeline",pipeline());failed+=report("length-upload-and-authority",upload(0));failed+=report("chunked-upload",upload(1));
    failed+=report("large-upload",upload(2));failed+=report("chunked-response",chunked_response(0));failed+=report("http10-dechunk",chunked_response(1));
    failed+=report("expect-continue",expect_continue());failed+=report("websocket",websocket());failed+=report("ambiguous-request-rejected",invalid_framing());
    failed+=report("early-length",early_final(0));failed+=report("early-chunked",early_final(1));failed+=report("early-eof",early_final(2));return failed?1:0;
}
