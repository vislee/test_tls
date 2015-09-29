#include <stdio.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define MAXBUF 1024
using namespace std;
int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("input:%s %s\n",argv[0], "url port certfile");
        exit(1);
    }
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;
    
    std::string ssl_file(argv[3]);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    SSL_CTX_set_options(ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
    SSL_CTX_set_options(ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

    // 加载证书
    BIO     *bio;
    X509    *x509;
    bio = BIO_new_file((char *) ssl_file.c_str(), "r");
    if (bio == NULL) {
        printf("%s\n", "BIO_new_file");
        return 2;
    }

    x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (x509 == NULL) {
        printf("%s\n", "PEM_read_bio_X509_AUX");
        BIO_free(bio);
        return 2;
    }

    // 校验过期
    time_t tcheck=time(NULL);
    if (X509_cmp_time(X509_get_notAfter(x509), &tcheck) < 0) {
        printf("%s\n", "expire");
        return 4;
    }

    X509_STORE_CTX *x509ctx;
    x509ctx = X509_STORE_CTX_new();
    if (x509ctx == NULL) {
        printf("X509_STORE_CTX_new \n");
        return 3;
    }

    X509_LOOKUP *lookup;
    X509_STORE *cert_store;
    cert_store= X509_STORE_new (); 
    if (cert_store == NULL) {
        printf("X509_STORE_CTX_new \n");
        return 3;
    }
    // 设置检测的项
    X509_STORE_set_flags (cert_store, X509_V_FLAG_IGNORE_CRITICAL|X509_V_FLAG_ALLOW_PROXY_CERTS);
    lookup=X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
    if (lookup == NULL) {
        printf("%s\n", "X509_STORE_add_lookup file");
        return 3;
    }
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    lookup=X509_STORE_add_lookup(cert_store, X509_LOOKUP_hash_dir());
    if (lookup == NULL) {
        printf("%s\n", "X509_STORE_add_lookup dir");
        return 3;
    }
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);


    X509_STORE_CTX_init(x509ctx, cert_store, x509, NULL);
    int xret = 0;
    if ((xret=X509_verify_cert(x509ctx))!=1) {
        printf("X509_verify_cert %d -- %d:%s\n", xret, x509ctx->error, X509_verify_cert_error_string(x509ctx->error));
        return 3;
    }

    X509_STORE_free(cert_store);


    if (SSL_CTX_use_certificate(ctx, x509) == 0) {
        printf("%s\n", "SSL_CTX_use_certificate");
        X509_free(x509);
        BIO_free(bio);
        return 2;
    }
    X509_free(x509);
    BIO_free(bio);


    if (SSL_CTX_use_PrivateKey_file(ctx, ssl_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        printf("Use private key fail\n");
        return 0;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("Private key does not match the certificate public key\n");
        return 0;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");
    struct timeval t;
    t.tv_sec = 1;
    t.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) != 0) {
        printf("setsocketopt error %d", errno);
        return 3;
    }

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    struct hostent* hent = gethostbyname(argv[1]);
    if (hent) {
        dest.sin_addr = *reinterpret_cast<in_addr*>(hent->h_addr);
    }

    printf("address created %s\n", inet_ntoa(dest.sin_addr));


    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");

    ssl = SSL_new(ctx);

    SSL_set_fd(ssl, sockfd);
    SSL_set_connect_state(ssl);

    int con_ret=0;
    while((con_ret=SSL_do_handshake(ssl))!=1) {
    if(con_ret==1) {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    } else {
        int err_no=SSL_get_error(ssl,con_ret);
        if (err_no == SSL_ERROR_SYSCALL) {
            int ee = ERR_get_error();
            printf("SSL_ERROR_SYSCALL, %d %d %d %d\n", con_ret, err_no, ee, errno);
        } else if (err_no == SSL_ERROR_SSL){
            int n = ERR_GET_REASON(ERR_peek_error());
            if (n == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED ||
                n == SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED) {
                printf("%s\n", "ALERT_CERTIFICATE");
            }
            printf("ERR_GET_REASON, %d %d %d %d\n", con_ret, err_no, n, errno);
            return 3;
        } else if (err_no == SSL_ERROR_WANT_READ) {
            while ((len = SSL_read(ssl, buffer, MAXBUF))>0) {
                buffer[len]=0;
            }
            printf("errmsg: %s\n", buffer);
        }

        ERR_print_errors_fp(stderr);
        printf("err_no:%d\n",err_no);
        printf("errmsg: %s\n", ERR_error_string(ERR_get_error(), NULL));
        printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));
        printf("errmsg msg: %s\n", ERR_reason_error_string(ERR_peek_error()));
        return 0;
    }
}

    std::string send_msg = "hello world";
    len = SSL_write(ssl, send_msg.c_str(), send_msg.size());
    if (len < 0) {
            printf("msg:%s ,code:%d errmsg:%s\n",
                 send_msg.c_str(), errno, strerror(errno));
    } else {
            printf("msg:%s send ok! send %d byte\n",
                   send_msg.c_str(), static_cast<int>(send_msg.size()));
    }

    sleep(2);
    int i=0;
    std::string recvmsg;
    while ((len = SSL_read(ssl, buffer, MAXBUF))>0) {
        printf("ssl_read %d %d\n",i++, len);
        buffer[len]=0;
        printf("errmsg: %s\n", buffer);
    }
    printf("errno: %d\n", errno);


    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
