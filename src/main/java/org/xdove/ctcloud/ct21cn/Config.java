package org.xdove.ctcloud.ct21cn;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 相关配置参数
 */
@Data
@AllArgsConstructor
public class Config {
    private final String apiUrl;
    private final String appid;
    private final String secret;
    /**
     * 服务端版本号(V1.0，1.1)，"v1.0" XXTea 加密；RSA 加密使用 "1.1"；默认使用 "1.1" 若使用 1.1 版本，版本号传入 "1.1"，前缀不需要加 "v"
     */
    private final String version;
    /**
     * 接入端类型，可选值：
     * 0-IOS
     * 1-Android
     * 2-Web/WAP/H5
     * 3-PC
     * 4-服务端
     */
    private final Integer clientType;
    private final String encoding;
    private final String uriPrefix;
    private final String signatureAlgorithm;
    private final String RSAPrivateKey;
    private final String RSAPublicKey;
    private final String apiVersion;
    /**
     * 根据应用类型选取下列4个值之一
     * "189_code" ：标准应用获取访问令牌
     * "vcp_189"：平台应用获取访问令牌
     * "auth_code"：授权码获取访问令牌
     * "refresh_token"： 标准应用刷新令牌
     * "refresh_vcp_token"：平台应用刷新令牌
     */
    private final String grantType;
    private final String rsaAlgorithmName;

    public Config(String appid, String secret, String RSAPrivateKey, String RSAPublicKey, String grantType) {
        this.appid = appid;
        this.secret = secret;
        this.uriPrefix = "";
        this.RSAPrivateKey = RSAPrivateKey;
        this.RSAPublicKey = RSAPublicKey;
        this.apiUrl = "https://vcp.21cn.com";
        this.version = "v1.0";
        this.clientType = 4;
        this.encoding = "utf8";
        this.signatureAlgorithm = "HmacSHA256";
        this.apiVersion = "2.0";
        this.grantType = grantType;
        this.rsaAlgorithmName = "RSA";
    }
}
