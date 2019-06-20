#include <string.h>

#include <esp_wifi.h>
#include <esp_event_loop.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>

#include "tcpip_adapter.h"
#include "protocol_examples_common.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\n" \
    "Content-Type: text/html\r\n" \
    "\r\n" \
    "<h1>*very secure stuff*</h1>\r\n"

extern const uint8_t ca_crt_start[]     asm("_binary_ca_crt_start");
extern const uint8_t ca_crt_end[]       asm("_binary_ca_crt_end");

extern const uint8_t server_crt_start[] asm("_binary_server_crt_start");
extern const uint8_t server_crt_end[]   asm("_binary_server_crt_end");

extern const uint8_t server_key_start[] asm("_binary_server_key_start");
extern const uint8_t server_key_end[]   asm("_binary_server_key_end");

static const char *TAG = "esp32-https-server-certificate-auth";

static void server_task(void *pvParameters)
{

    int ret, len;
    unsigned char buf[1024];
    const char *pers = "some seed";

    mbedtls_net_context listen_fd, client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    // init stuff
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

    // parse server crt
    ret = mbedtls_x509_crt_parse(
        &srvcert,
        (const unsigned char *) server_crt_start,
        server_crt_end - server_crt_start
    );
    if(ret != 0)
    {
        ESP_LOGE(TAG, "unable to parse server crt. \
            mbedtls_x509_crt_parse returned %d", ret);
        return;
    }

    // parse ca crt
    ret = mbedtls_x509_crt_parse(
        &srvcert,
        (const unsigned char *) ca_crt_start,
        ca_crt_end - ca_crt_start
    );
    if(ret != 0)
    {

        ESP_LOGE(TAG, "unable to parse ca crt. \
            mbedtls_x509_crt_parse returned %d", ret);
        return;
    }

    // parse server key
    ret =  mbedtls_pk_parse_key(
        &pkey,
        (const unsigned char *) server_key_start,
        server_key_end - server_key_start,
        NULL, 0
    );
    if(ret != 0)
    {
        ESP_LOGE(TAG, "unable to parse server key. \
            mbedtls_x509_crt_parse returned %d", ret);
        return;
    }

    // tcp bind to port 442
    ret = mbedtls_net_bind(&listen_fd, NULL, "443", MBEDTLS_NET_PROTO_TCP);
    if(ret != 0)
    {
        ESP_LOGE(TAG, "unable to bind. \
            mbedtls_net_bind returned %d", ret);
        return;
    }

    // seed rng
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char *) pers, strlen(pers)
    );
    if(ret != 0)
    {
        ESP_LOGE(TAG, "unable to seed rng. \
            mbedtls_ctr_drbg_seed returned %d", ret);
        return;
    }

    // load configuration defaults
    ret = mbedtls_ssl_config_defaults(
        &conf,
        MBEDTLS_SSL_IS_SERVER,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    if(ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        return;
    }

    // the essential step: setting MBEDTLS_SSL_VERIFY_REQUIRED
    // this makes the server ask for client certificates
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    // configure some other stuff
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if(ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_conf_own_cert returned %d", ret);
        return;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if(ret != 0 )
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned %d", ret);
        return;
    }

    ESP_LOGI(TAG, "server started");

accept:

    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    // accept a client
    ret = mbedtls_net_accept(
        &listen_fd, &client_fd,
        NULL, 0, NULL
    );
    if(ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_accept returned %d", ret);
        return;
    }

    mbedtls_ssl_set_bio(
        &ssl, &client_fd, mbedtls_net_send,
        mbedtls_net_recv, NULL
    );

    while((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if(
            ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE
        )
        {
            ESP_LOGW(TAG, "mbedtls_ssl_handshake returned 0x%x\n", -ret);
            goto accept;
        }
    }

    do
    {

        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if(
            ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE
        ) continue;

        if(ret <= 0)
        {
            switch(ret)
            {

                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    ESP_LOGI(TAG, "connection was closed gracefully");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    ESP_LOGI(TAG, "connection was reset by peer");
                    break;

                default:
                    ESP_LOGW(TAG, "mbedtls_ssl_read returned 0x%x", -ret);
                    break;

            }
        }

        len = ret;
        if(ret > 0) break;

    }
    while(true);

    len = sprintf((char *) buf, HTTP_RESPONSE);
    ret = mbedtls_ssl_write(&ssl, buf, len);
    while(ret <= 0)
    {

        if(ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            ESP_LOGI(TAG, "peer closed the connection");
            goto accept;
        }

        if (
            ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE
        )
        {
            ESP_LOGW(TAG, "mbedtls_ssl_write returned %d", ret);
            goto accept;
        }

    }

    len = ret;

    ret = mbedtls_ssl_close_notify(&ssl);
    while (ret < 0)
    {
        if(
            ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE
        )
        {
            ESP_LOGW(TAG, "mbedtls_ssl_close_notify returned %d", ret);
            goto accept;
        }
    }

    ret = 0;

    goto accept;

}

void app_main()
{
    
    ESP_ERROR_CHECK(nvs_flash_init());
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    ESP_ERROR_CHECK(example_connect());
    
    xTaskCreate(&server_task, "server_task", 8192, NULL, 5, NULL);

}
