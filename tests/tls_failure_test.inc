void tlsFailureTests()
{
    const auto roots=readTestFile(std::string(CLAHSOS_TEST_ROOT)+"/fixtures/vmess/ca.pem");
    for(const int code:{MBEDTLS_ERR_SSL_CONN_EOF,MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY,MBEDTLS_ERR_SSL_TIMEOUT,MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE,MBEDTLS_ERR_SSL_INVALID_RECORD,MBEDTLS_ERR_NET_RECV_FAILED,MBEDTLS_ERR_NET_SEND_FAILED}) {
        const auto failure=tlsHandshakeFailure(code,UINT32_MAX);
        require(!failure.message.empty()&&failure.message.find("certificate")==std::string::npos,"A pre-certificate failure must not claim bad trust");
    }
    require(tlsHandshakeFailure(MBEDTLS_ERR_NET_RECV_FAILED,UINT32_MAX,ECONNRESET).code==ECONNRESET,"TLS resets retain their actual transport cause");
    require(tlsHandshakeFailure(MBEDTLS_ERR_NET_RECV_FAILED,0,EBADMSG).message.find("authentication")!=std::string::npos,"Proxy authentication differs from TLS trust");
    for(const auto& item:std::vector<std::pair<uint32_t,std::string>>{{MBEDTLS_X509_BADCERT_CN_MISMATCH,"hostname"},{MBEDTLS_X509_BADCERT_EXPIRED,"expired"},{MBEDTLS_X509_BADCERT_FUTURE,"not valid yet"},{MBEDTLS_X509_BADCERT_NOT_TRUSTED,"not trusted"}})
        require(tlsHandshakeFailure(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,item.first).message.find(item.second)!=std::string::npos,"Known certificate failures need the correct cause");
    for(const std::string mode:{"eof","timeout","alert","invalid","untrusted","wronghost","valid"}) {
        VmessReferencePeer peer(0,mode,"","tls_failure_reference_peer.py");const int fd=peer.take();socketTimeout(fd,mode=="timeout"?150:3000);
        std::string error;int cause=0;bool started=false;
        {
            TlsChannel channel(fd);started=channel.start(mode=="wronghost"?"wrong.test":"vmess.test",false,error,mode=="untrusted"?nullptr:roots.c_str());cause=errno;
            if(started){require(channel.writeBytes(reinterpret_cast<const unsigned char*>("done"),4),"Trusted TLS write failed");unsigned char reply[2];require(channel.readBytes(reply,2)==2&&std::string(reinterpret_cast<char*>(reply),2)=="ok","Trusted TLS response failed");}
        }
        close(fd);peer.finish();
        if(mode=="valid")require(started&&error.empty(),"Diagnostics must preserve verified TLS success");
        else {
            require(!started&&!error.empty(),"Independent TLS failure must reject");
            if(mode=="eof")require(error.find("peer closed")!=std::string::npos&&cause==ECONNRESET,"Premature EOF must not appear as a certificate error");
            else if(mode=="timeout")require(error.find("timed out")!=std::string::npos&&cause==ETIMEDOUT,"TLS timeout must retain its cause");
            else if(mode=="alert")require(error.find("rejected")!=std::string::npos,"TLS alerts need a peer-rejection error");
            else if(mode=="untrusted")require(error.find("not trusted")!=std::string::npos,"Untrusted TLS remains rejected");
            else if(mode=="wronghost")require(error.find("hostname mismatch")!=std::string::npos,"Wrong-host TLS remains rejected");
            else require(error.find("certificate")==std::string::npos,"A plaintext peer is not a trust problem");
        }
    }
}
