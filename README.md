#### 测试自签名证书

##### 背景

+ apns push服务出问题

```

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

```

最近，当证书过期后，一直返回： `SSL_ERROR_SYSCALL, 0 5 0 0`


+ 用该命令`openssl x509 -text -in roch.pem` 查看了证书，证书过期了。 * 最近有个怪异的现象，过期的证书有时候是可以握手成功的。以前上述代码可以判断证书过期的。会输出 `ALERT_CERTIFICATE` *


+ 写了个简单的测试文件，用过期的证书测试，每次都报 `SSL_ERROR_SYSCALL, 0 5 0 0`.

+ 没招了，换个解决思路
  - `X509_verify_cert` : 这个函数目前我并没有测试出可以检测证书过期。可能需要设置忽略一些选项吧。

  - `X509_get_notAfter` : 这个目前是可以判断证书过期的。



##### 代码

+ 可以作为你写ssl client 的一个参考。

+ 可以检测你的证书
