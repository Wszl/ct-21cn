package org.xdove.ctcloud.ct21cn;


import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.http.impl.client.HttpClients;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Map;
import java.util.Random;

public class ServiceRequestsTest {

    private ServiceRequests serviceRequests;

    @Before
    public void init() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        Config config = new Config(
                System.getenv("APPID"),
                System.getenv("SECRET"),
                System.getenv("RSA_PRIVATE_KEY"),
                System.getenv("RSA_PUBLIC_KEY"),
                "auth_code"
                );
        this.serviceRequests = new ServiceRequests(HttpClients.createDefault(), config);
//        this.serviceRequests.initAuth(System.getenv("authCode"));
        //mock
        this.serviceRequests.setAccessToken(System.getenv("ACCESS_TOKEN"));
        this.serviceRequests.setRefreshAccessToken(System.getenv("REFRESH_TOEKN"));
        this.serviceRequests.setRefreshAccessTokenExpireIn(Instant.now().plusSeconds(Long.parseLong(System.getenv("REFRESH_TOEKN_EXPIREIN"))));
    }


    public void testGetDeviceMediaUrl() {

    }

    @Test
    public void testSubscribe() {
        String deviceCode = System.getenv("DEVICE_CODE");
        String host = System.getenv("HOST");
//        String alertTypes = "1,2";
        String alertTypes = "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,26,26";
        Map<String, Object> ret = this.serviceRequests.subscribe(null, deviceCode, host + "/ai/callback/", null, alertTypes);
        System.out.println(ret);
    }

    @Test
    public void testUnsubscribe() {
        String deviceCode = System.getenv("DEVICE_CODE");
        String alertTypes = "1";
        Map<String, Object> ret = this.serviceRequests.unsubscribe(null, deviceCode, null, alertTypes);
        System.out.println(ret);
    }

    public static void main(String[] args) throws IOException {
        startHttpServer();
    }

    public static void startHttpServer() throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(18080), 10);
        httpServer.createContext("/callback", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                String body = IOUtils.toString(exchange.getRequestBody(), Charset.defaultCharset());
                String url = exchange.getRequestURI().toString();
                System.out.printf("%s \t %s \n", url, body);
            }
        });
        httpServer.createContext("/ai/callback", (e) ->{
            String body = IOUtils.toString(e.getRequestBody(), Charset.defaultCharset());
            String url = e.getRequestURI().toString();
            System.out.printf("%s \t %s \n", url, body);
        });
        httpServer.start();
    }

    @Test
    public void testGetAuthPageUrl() {
        String host = System.getenv("HOST");
        Map<String, Object> authPageUrl = this.serviceRequests.getAuthPageUrl(host + "/callback/", String.valueOf(new Random().nextInt()), 10010);
        System.out.println(authPageUrl);
    }

    @Test
    public void testGetAccessToken() {
        Map<String, Object> ret = this.serviceRequests.getAccessToken("auth_code", null, System.getenv("authCode").toString(), null);
        System.out.println(ret);
    }

    @Test
    public void testRefreshAccessToken() {
       this.serviceRequests.refreshAccessToken();
    }

    @Test
    public void testGetRegions() {
        Map<String, Object> regions = this.serviceRequests.getRegions(null, null);
        System.out.println(regions);
    }

    @Test
    public void testGetLastRegions() {
        Map<String, Object> ret = this.serviceRequests.getLastRegions(null);
        System.out.println(ret);
    }

    @Test
    public void testGetDevicesByRegionCode() {
        Map<String, Object> ret = this.serviceRequests.getDevicesByRegionCode(null, 1, 100, "xx");
        System.out.println(ret);
    }

    @Test
    public void testGetDevicesByRegionCon() {
        Map<String, Object> ret = this.serviceRequests.getDevicesByRegionCon(null, 1, 100, null, null);
        System.out.println(ret);
    }

    @Test
    public void testGetReginWithGroupList() {
        Map<String, Object> ret = this.serviceRequests.getReginWithGroupList(null, null);
        System.out.println(ret);
    }

    @Test
    public void testGetDeviceList() {
        Map<String, Object> ret = this.serviceRequests.getDeviceList(null, null, null);
        System.out.println(ret);
    }

    @Test
    public void testGetAllDeviceListNew() {
        Long lastId = 0l;
        Map<String, Object> ret = this.serviceRequests.getAllDeviceListNew(null, null, lastId, null);
        System.out.println(ret);
    }

    @Test
    public void testGetDeviceMediaUrlHls() {
        String deviceCode = System.getenv("DEVICE_CODE");
        Map<String, Object> ret = this.serviceRequests.getDeviceMediaUrlHls(null, deviceCode, 1, 1, 0);
        System.out.println(ret);
    }

    @Test
    public void testDecryptByXXTea() throws UnsupportedEncodingException, DecoderException {
        String dataStr = System.getenv("DATA_STR");
        String ret = this.serviceRequests.decryptByXXTea(Hex.decodeHex(dataStr));
        System.out.println(ret);
    }

    @Test
    public void testDecryptByRSA() throws DecoderException {
        String dataStr = System.getenv("RSA_DATA_STR");
        System.out.println(dataStr);
        String ret = this.serviceRequests.decryptByRSA(Hex.decodeHex(dataStr));
        System.out.println(ret);
    }


    @Test
    public void testInitAuth() throws InterruptedException {
        String accessToken = System.getenv("ACCESS_TOKEN");
        String refreshToken = System.getenv("REFRESH_TOKEN");
        Integer refreshExpiresIn = Integer.valueOf(System.getenv("REFRESH_TOEKN_EXPIREIN"));
        Integer expiresIn = Integer.valueOf(System.getenv("ACCESS_TOKEN_EXPIREIN"));
        this.serviceRequests.initAuth(accessToken, refreshToken, refreshExpiresIn, expiresIn);
        Thread.sleep(1000* 1000);
    }
}