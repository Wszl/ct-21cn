package org.xdove.ctcloud.ct21cn;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.util.Strings;
import org.xxtea.XXTEA;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * 电信智能视频云服务
 * @author Wszl
 * @date 2023年05月21日
 */
@Setter
@Getter
public class ServiceRequests {

    private final static Logger log = LogManager.getLogger();

    private final HttpClient client;
    private final Config config;
    private final String urlPrefix;
    private final RequestConfig requestConfig;

    private String authCode;
    private String accessToken;
    private Integer accessTokenExpireInSec;
    private Timer accessToeknRefreshTimer;
    private String refreshAccessToken;
    private Integer refreshAccessTokenExpireInSec;
    private Instant refreshAccessTokenExpireIn;
    private Function<Map, Void> storageCallbackFunction;

    private RSAPrivateKey rsaPrivateKey;
    private Cipher rsaCipher;
    private int MAX_DECRYPT_BLOCK;

    /** 获取授权页面 */
    public static final String PATH_AUTH_GET_AUTH_PAGE_URL = "/open/oauth/login/getAuthPageUrl";
    /** 获取能力开放平台访问令牌 */
    public static final String PATH_AUTH_GET_ACCESS_TOKEN = "/open/oauth/getAccessToken";

    /** 获取监控目录树 */
    public static final String PATH_GET_REGIN_WITH_GROUP_LIST = "/open/token/device/getReginWithGroupList";
    /** 查询设备列表 */
    public static final String PATH_GET_DEVICE_LIST = "/open/token/device/getDeviceList";
    /** 查询子区域设备数、在线设备数 */
    public static final String PATH_GET_CUS_DEVICE_COUNT = "/open/token/vcpTree/getCusDeviceCount";
    /** 查询监控目录树设备数量、在线设备数量 */
    public static final String PATH_GET_CUS_TREE_DEVICE_COUNT = "/open/token/vcpTree/getCusTreeDeviceCount";
    /** 分页查询监控目录设备列表 */
    public static final String PATH_GET_ALL_DEVICE_LIST_NEW = "/open/token/device/getAllDeviceListNew";


    /** 查询设备树行政目录结构 */
    public static final String PATH_GET_REGIONS = "/open/token/vcpTree/getRegions";
    /** 获取设备树最后一层区域列表 */
    public static final String PATH_GET_LAST_REGIONS = "/open/token/vcpTree/getLastRegions";
    /** 根据区域码分页查询设备树下设备列表 */
    public static final String PATH_GET_DEVICES_BY_REGION_CODE = "/open/token/vcpTree/getDevicesByRegionCode";
    /** 根据条件查询设备列表 */
    public static final String PATH_GET_DEVICES_BY_REGION_CON = "/open/token/vcpTree/getDevicesByRegionCon";
    /** 获取设备的HLS直播链接 */
    public static final String PATH_GET_DEVICE_MEDIA_URL_HLS = "/open/token/cloud/getDeviceMediaUrlHls";
   /** AI单品消息分发订阅 */
    public static final String PATH_SUBSCRIBE = "/open/token/message/device/subscribe";
    /** AI单品消息分发退订 */
    public static final String PATH_UNSUBSCRIBE = "/open/token/message/device/unsubscribe";
    /** 行业应用消息分发订阅 */
    public static final String PATH_MESSAGE_SUBSCRIBE = "/open/token/ai/message/messageSubscribe";
    /** 行业应用消息分发退订 */
    public static final String PATH_CANCEL_MESSAGE_SUBSCRIBE = "/open/token/ai/message/cancelMessageSubscribe";

    /** 获取设备详细信息 */
    public static final String PATH_SHOW_DEVICE = "/open/token/device/showDevice";


    public ServiceRequests(Config config) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidKeySpecException {
        this(HttpClientBuilder.create().build(), RequestConfig.custom()
                .setConnectionRequestTimeout(10000)
                .setSocketTimeout(2000)
                .setConnectTimeout(5000)
                .build(),config);
    }

    public ServiceRequests(HttpClient client, RequestConfig requestConfig, Config config) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException {
        this.client = client;
        this.config = config;
        if (Objects.nonNull(config.getUriPrefix())) {
            this.urlPrefix = config.getUriPrefix();
        } else {
            this.urlPrefix = "";
        }
        this.accessToeknRefreshTimer = new Timer(true);
        this.requestConfig = requestConfig;
        KeyFactory keyFactory = KeyFactory.getInstance(config.getRsaAlgorithmName());
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(config.getRSAPrivateKey()));
        this.rsaPrivateKey =  (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        this.rsaCipher = Cipher.getInstance(config.getRsaAlgorithmName());
        this.rsaCipher.init(Cipher.DECRYPT_MODE, this.rsaPrivateKey);
        this.MAX_DECRYPT_BLOCK = 128;

    }

    public void initAuth(String authCode) {
        if (Objects.isNull(this.accessToken)) {
            this.authCode = authCode;
            Map<String, Object> ret = this.getAccessToken(config.getGrantType(), null, this.authCode, null);
            if (!Objects.equals(ret.get("code"), 0)) {
                log.warn("request accessToken failed. authCode is {}, ret is {}", this.authCode, ret);
                throw new RuntimeException("request accessToken failed");
            }
            Object data = ret.get("data");
            if (Objects.isNull(data)) {
                log.warn("request accessToken failed. result is empty, authCode is {}, ret is {}", this.authCode, ret);
                throw new RuntimeException("request accessToken failed, result is empty");
            }
            this.handleAccessToken((Map) data);
        } else {
            log.info("accessToken already exists. skip init.");
        }
    }

    public void initAuth(String accessToken, String refreshToken, Integer refreshExpiresIn, Integer expiresIn) {
        this.scheduleRefreshToken(accessToken, refreshToken, refreshExpiresIn, expiresIn);
    }

    public void setStorage(Function<Map, Void> f) {
        this.storageCallbackFunction = f;
    }
    private void handleAccessToken(Map data) {
        Integer expiresIn = (Integer) data.get("expiresIn");
        String accessToken = (String) data.get("accessToken");
        String refreshToken = (String) data.get("refreshToken");
        Integer refreshExpiresIn = (Integer) data.get("refreshExpiresIn");
        scheduleRefreshToken(accessToken, refreshToken, refreshExpiresIn, expiresIn);
        if (Objects.nonNull(this.storageCallbackFunction)) {
            log.info("accessToken storage enable, store auth data in {}", storageCallbackFunction.toString());
            storageCallbackFunction.apply(data);
        }
    }

    public Timer scheduleRefreshToken(String accessToken, String refreshToken, Integer refreshExpiresIn, Integer expiresIn) {
        this.accessToken = accessToken;
        this.refreshAccessToken = refreshToken;
        this.refreshAccessTokenExpireIn = Instant.now().plusSeconds(refreshExpiresIn);
        this.accessTokenExpireInSec = expiresIn;
        this.refreshAccessTokenExpireInSec = refreshExpiresIn;
        if (expiresIn <= 5000) {
            expiresIn = 5001;
        }
        Instant startDate = Instant.now().plusSeconds(5 * 24 * 60 * 60);
        log.info("scheduleRefreshToken in {}", startDate.toEpochMilli());
        accessToeknRefreshTimer.purge();
        accessToeknRefreshTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                refreshAccessToken();
            }
        }, new Date(startDate.toEpochMilli()));
        return accessToeknRefreshTimer;
    }

    public void refreshAccessToken() {
        if (this.refreshAccessTokenExpireIn.isBefore(Instant.now())) {
            log.info("refreshAccessToken expire in {} now is {}, please get authCode again.",
                    LocalDateTime.ofInstant(this.refreshAccessTokenExpireIn, ZoneId.systemDefault()).format(DateTimeFormatter.ISO_DATE_TIME),
                    LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
            return;
        }
        log.info("refreshAccessToken at {}", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME));
        Map<String, Object> ret = this.getAccessToken("refresh_token", null, null, this.refreshAccessToken);
        if (!Objects.equals(ret.get("code"), 0)) {
            log.warn("refresh accessToken failed. refreshAccessToken is {}, ret is {}", this.refreshAccessToken, ret);
            throw new RuntimeException("refresh accessToken failed");
        }
        Object data = ret.get("data");
        if (Objects.isNull(data)) {
            log.warn("refresh accessToken failed. result is empty, refreshAccessToken is {}, ret is {}", this.refreshAccessToken, ret);
            throw new RuntimeException("refresh accessToken failed, result is empty");
        }
        this.handleAccessToken((Map) data);
    }

    /**********************
     *       AUTH
     *       from: https://vcp.dlife.cn/portal/document-detail?group=1640621363576373250
     *
     *    能力开放accessToken获取流程说明
     *
     *     调取能力开放平台原子能力，需要先获取平台访问令牌（accessToken），当前能力开放平台提供三种获取访问令牌场景。
     *
     * 一、授权码方式获取能力开放平台访问令牌
     * 二、天翼账号TokenCode获取能力开放平台访问令牌
     * 三、IP白名单方式获取能力开放平台访问令牌
     *********************/

    /**
     * 获取授权页面
     * 一、授权码方式获取能力开放平台访问令牌
     * @param callbackUrl 合作方回调地址，用于接收authCode参数(用授权登录之后，能力开放会回调至该地址，地址上带有authCode和errorCode参数)
     * @param state 用于保持请求和回调的状态，登录请求后原样带回给第三方。该参数可用于防止csrf攻击（跨站请求伪造攻击），第三方需带上该参数，可设置为简单的随机数加session进行校验
     * @param loginClientType 登录端类型10010：web(PC)端20100：wap(H5)端
     * @return
     */
    public Map<String, Object> getAuthPageUrl(@NonNull String callbackUrl, @NonNull String state, @NonNull Integer loginClientType) {
        if (log.isDebugEnabled()) {
            log.debug("request getAuthPageUrl callbackUrl={} state={} loginClientType={}", callbackUrl, state, loginClientType);
        }
        Map<String, String> param = new HashMap<>();
        param.put("callbackUrl", callbackUrl);
        param.put("state", state);
        param.put("loginClientType", parseString(loginClientType));
        try {
            final String s = this.postRequest(PATH_AUTH_GET_AUTH_PAGE_URL, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }

    }

    /**
     * 获取天翼视联访问令牌
     * @param grantType
     * 根据应用类型选取下列4个值之一
     * "189_code" ：标准应用获取访问令牌
     * "vcp_189"：平台应用获取访问令牌
     * "auth_code"：授权码获取访问令牌
     * "refresh_token"： 标准应用刷新令牌
     * "refresh_vcp_token"：平台应用刷新令牌
     * @param tokenCode
     * 由天翼账号接口获得
     * 注：
     * 1）标准应用，必传（需要参考上文描述天翼账号获取访问令牌环节换取tokenCode）；
     * 2）平台应用，无需传此参数；
     * @param authCode
     * 授权码
     * 当grantType是authCode时，此字段必传
     * @param refreshToken 刷新token时，必传（非刷新token时参数不传）
     * @return
     */
    public Map<String, Object> getAccessToken(@NonNull String grantType, String tokenCode, String authCode, String refreshToken) {
        if (log.isDebugEnabled()) {
            log.debug("request getAccessToken grantType={} tokenCode={} authCode={} refreshToken={}",
                    grantType, tokenCode, authCode, refreshToken);
        }
        Map<String, String> param = new HashMap<>();
        param.put("grantType", grantType);
        param.put("tokenCode", tokenCode);
        param.put("authCode", authCode);
        param.put("refreshToken", refreshToken);
        try {
            final String s = this.postRequest(PATH_AUTH_GET_ACCESS_TOKEN, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }

    }

    /***************************
     *     查询监控目录
     ***************************/
    /**
     * 获取监控目录树
     * 获取当前账号所分配的区域，及其所有下级区域列表
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @param regionId 区域 id，为空时则返回首层目录树，为空传空字符串
     * @return
     */
    public Map<String, Object> getReginWithGroupList(String enterpriseUser, Long regionId) {
        if (log.isDebugEnabled()) {
            log.debug("request getReginWithGroupList enterpriseUser={}, regionId={}", enterpriseUser, regionId);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("regionId", parseString(regionId));
        try {
            final String s = this.postRequest(PATH_GET_REGIN_WITH_GROUP_LIST, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 查询设备列表
     * @param regionId 区域 id 或分组 id
     * @param pageNo 页码，默认 1
     * @param pageSize 分页大小，默认 10，最大值 50
     * @return
     */
    public Map<String, Object> getDeviceList(@NonNull Long regionId, Integer pageNo, Integer pageSize) {
        if (log.isDebugEnabled()) {
            log.debug("request getDeviceList regionId={}, pageNo={}, pageSize={}", regionId, pageNo, pageSize);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("regionId", parseString(regionId));
        param.put("pageNo", parseString(pageNo));
        param.put("pageSize", parseString(pageSize));
        try {
            final String s = this.postRequest(PATH_GET_DEVICE_LIST, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 查询子区域设备数、在线设备数
     * @param regionCode 区域编码，为空时查首层
     * @return
     */
    public Map<String, Object> getCusDeviceCount(String regionCode) {
        if (log.isDebugEnabled()) {
            log.debug("request getCusDeviceCount regionCode={}", regionCode);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("regionCode", regionCode);
        try {
            final String s = this.postRequest(PATH_GET_CUS_DEVICE_COUNT, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 查询监控目录树设备数量、在线设备数量
     * @param isClearCache 是否清除缓存：0 是1 否
     * @return
     */
    public Map<String, Object> getCusTreeDeviceCount(Integer isClearCache) {
        if (log.isDebugEnabled()) {
            log.debug("request getCusTreeDeviceCount isClearCache={}", isClearCache);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("isClearCache", parseString(isClearCache));
        try {
            final String s = this.postRequest(PATH_GET_CUS_TREE_DEVICE_COUNT, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 分页查询监控目录设备列表
     * 通过该接口分页查询账号下所有设备列表 lastId 参数首次必传，下一次分页查询传入接口返回lastId数值，当lastId返回-1时表示数据查询完毕。total 参数只在首次查询结果后返回，请留意保存。
     * @param enterpriseUser 企业主(应用为平台应用时，需要传此参数)
     * @param cusRegionId 指定自定义ID,不传查首层
     * @param lastId 最后的id，首次查传0
     * @param pageSize 每页显示数量，默认10(最大100)
     * @return
     */
    public Map<String, Object> getAllDeviceListNew(String enterpriseUser, Long cusRegionId, @NonNull Long lastId, Integer pageSize) {
        if (log.isDebugEnabled()) {
            log.debug("request getAllDeviceListNew enterpriseUser={} cusRegionId={} lastId={} pageSize={}",
                    enterpriseUser, cusRegionId, lastId, pageSize);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("cusRegionId", parseString(cusRegionId));
        param.put("lastId", parseString(lastId));
        param.put("pageSize", parseString(pageSize));
        try {
            final String s = this.postRequest(PATH_GET_ALL_DEVICE_LIST_NEW, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /***************************
     *     查询我的视频流
     ***************************/
    /**
     * 查询云眼设备树目录结构
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @param id 区域自增id，为空查首层区域
     * @return
     */
    public Map<String, Object> getRegions(String enterpriseUser, Integer id) {
        if (log.isDebugEnabled()) {
            log.debug("request getRegions enterpriseUser={}, id={}", enterpriseUser, id);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("id", parseString(id));
        try {
            final String s = this.postRequest(PATH_GET_REGIONS, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取设备树最后一层区域列表
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @return
     */
    public Map<String, Object> getLastRegions(String enterpriseUser) {
        if (log.isDebugEnabled()) {
            log.debug("request getRegions enterpriseUser={}", enterpriseUser);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        try {
            final String s = this.postRequest(PATH_GET_LAST_REGIONS, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 根据区域码分页查询设备树下设备列表
     * @param enterpriseUser    企业主 注：应用为平台应用时，需要传此参数
     * @param pageNo 当前页码，从1开始
     * @param pageSize 每页显示条数
     * @param regionCode 区域编码（18位全编码）
     * @return
     */
    public Map<String, Object> getDevicesByRegionCode(String enterpriseUser, @NonNull Integer pageNo,
                                                      @NonNull Integer pageSize,  @NonNull String regionCode) {
        if (log.isDebugEnabled()) {
            log.debug("request getDevicesByRegionCode enterpriseUser={} pageNo={} pageSize={} regionCode={}",
                    enterpriseUser, pageNo, pageSize, regionCode);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("pageNo", parseString(pageNo));
        param.put("pageSize", parseString(pageSize));
        param.put("regionCode", regionCode);
        try {
            final String s = this.postRequest(PATH_GET_DEVICES_BY_REGION_CODE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 根据条件查询设备列表
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @param pageNo 当前页码，从1开始
     * @param pageSize 每页显示条数
     * @param deviceCode 设备码
     * @param deviceName 设备名称
     * @return
     */
    public Map<String, Object> getDevicesByRegionCon(String enterpriseUser, @NonNull Integer pageNo, @NonNull Integer pageSize,
                                                     String deviceCode, String deviceName) {
        if (log.isDebugEnabled()) {
            log.debug("request getDevicesByRegionCon enterpriseUser={} pageNo={} pageSize={} deviceCode={} deviceName={}",
                    enterpriseUser, pageNo, pageSize, deviceCode, deviceName);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("pageNo", parseString(pageNo));
        param.put("pageSize", parseString(pageSize));
        param.put("deviceCode", deviceCode);
        param.put("deviceName", deviceName);
        try {
            final String s = this.postRequest(PATH_GET_DEVICES_BY_REGION_CON, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /***************************
     *     转码直播视频流
     ***************************/

    /**
     * 获取设备的HLS直播链接
     * @param enterpriseUser 企业主(应用为平台应用时，需要传此参数)
     * @param deviceCode 设备码
     * @param mediaType 直播类型（1.标清；0.高清）
     * @param supportDomain 是否支持跨域（0:不支持;1:支持）默认为0
     * @param mute 静音标识（0.非静音;1.静音）默认为0
     * @return
     */
    public Map<String, Object> getDeviceMediaUrlHls(String enterpriseUser, @NonNull String deviceCode, Integer mediaType,
                                                     Integer supportDomain, Integer mute) {
        if (log.isDebugEnabled()) {
            log.debug("request getDeviceMediaUrlHls enterpriseUser={} deviceCode={} mediaType={} supportDomain={} mute={}",
                    enterpriseUser, deviceCode, mediaType, supportDomain, mute);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("deviceCode", deviceCode);
        param.put("mediaType", parseString(mediaType));
        param.put("supportDomain", parseString(supportDomain));
        param.put("mute", parseString(mute));
        try {
            final String s = this.postRequest(PATH_GET_DEVICE_MEDIA_URL_HLS, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return decryptResp(jsonObject);
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    public Map<String, Object> decryptResp(JSONObject jsonObject) throws UnsupportedEncodingException, DecoderException {
        if (jsonObject.containsKey("data")) {
            String encryptStr = jsonObject.getString("data");
            String decryptStr = decryptByXXTea(Hex.decodeHex(encryptStr));
            if (log.isDebugEnabled()) {
                log.debug("decryptStr is {} origin str is {}", decryptStr, encryptStr);
            }
            if (Objects.isNull(decryptStr)) {
                log.warn("decrypt exception. result is null. origin str is {}", encryptStr);
                throw new RuntimeException("decrypt exception. result is null.");
            }
            Map<String, Object> innerMap = jsonObject.getInnerMap();
            innerMap.put("data", JSON.parseObject(decryptStr).getInnerMap());
            return innerMap;
        }
        return jsonObject.getInnerMap();
    }

    /*****************
     *      AI
     *****************/

    /**
     * AI单品消息分发订阅
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @param deviceCode 设备码
     * @param callbackUrl AI消息告警回调地址  Post请求 body为JSON格式 {"data":"RSA加密数据"}  callbackUrl不支持携带参数
     * @param username 订阅消息的账号信息（通常为通过能力开放平台开通appid的手机号）传入该参数只过滤获取本账号的ai消息，否则设备产生级联后ai消息存在多条
     * @param alertTypes 告警类型：订阅多个告警类型用","分隔 示例：alertTypes: "1,2,3,4 3、画面异常巡检 5、区域入侵 6、车牌布控 7、人脸布控
     *                   12、客流统计 13、厨帽识别 14、抽烟识别 15、口罩识别 16、店员玩手机识别 17、火情预警 21、动物识别 22、电动车识别
     *                   25、人群聚集检测 26、医用防护服检测 27、高空抛物 （大华，海康设备） 28、车辆违停占道
     * @return
     */
    public Map<String, Object> subscribe(String enterpriseUser, @NonNull String deviceCode, @NonNull String callbackUrl, String username,
                                                 @NonNull String alertTypes) {
        if (log.isDebugEnabled()) {
            log.debug("request subscribe enterpriseUser={} deviceCode={}, callbackUrl={}, username={}, alertTypes={}",
                    enterpriseUser, deviceCode, callbackUrl, username, alertTypes);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("callbackUrl", callbackUrl);
        param.put("deviceCode", deviceCode);
        param.put("username", username);
        param.put("alertTypes", alertTypes);
        try {
            final String s = this.postRequest(PATH_SUBSCRIBE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * AI单品消息分发退订
     * @param enterpriseUser 企业主 注：应用为平台应用时，需要传此参数
     * @param deviceCode 设备码
     * @param username 订阅消息的账号信息（通常为通过能力开放平台开通appid的手机号）传入该参数只过滤获取本账号的ai消息，否则设备产生级联后ai消息存在多条
     * @param alertTypes 告警类型：订阅多个告警类型用","分隔 示例：alertTypes: "1,2,3,4 3、画面异常巡检 5、区域入侵 6、车牌布控 7、人脸布控
     *                   12、客流统计 13、厨帽识别 14、抽烟识别 15、口罩识别 16、店员玩手机识别 17、火情预警 21、动物识别 22、电动车识别
     *                   25、人群聚集检测 26、医用防护服检测 27、高空抛物 （大华，海康设备） 28、车辆违停占道
     * @return
     */
    public Map<String, Object> unsubscribe(String enterpriseUser, @NonNull String deviceCode, String username, @NonNull String alertTypes) {
        if (log.isDebugEnabled()) {
            log.debug("request  unsubscribe enterpriseUser={} deviceCode={}, username={}, alertTypes={}",
                    enterpriseUser, deviceCode, username, alertTypes);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("deviceCode", deviceCode);
        param.put("username", username);
        param.put("alertTypes", alertTypes);
        try {
            final String s = this.postRequest(PATH_UNSUBSCRIBE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 行业应用消息分发订阅
     * @param enterpriseUser 企业主(应用为平台应用时，需要传此参数)
     * @param sceneId 场景ID,详见 字典说明- AI算法场景类型
     * @param deviceCode 设备码
     * @param callbackUrl AI消息告警回调地址
     * @return
     */
    public Map<String, Object> messageSubscribe(String enterpriseUser, @NonNull Long sceneId, @NonNull String deviceCode,
                                                @NonNull String callbackUrl) {
        if (log.isDebugEnabled()) {
            log.debug("request messageSubscribe enterpriseUser={} sceneId={}, deviceCode={}, callbackUrl={}",
                    enterpriseUser, sceneId, deviceCode, callbackUrl);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("sceneId", parseString(sceneId));
        param.put("deviceCode", deviceCode);
        param.put("callbackUrl", callbackUrl);
        try {
            final String s = this.postRequest(PATH_MESSAGE_SUBSCRIBE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * 行业应用消息分发退订
     * @param enterpriseUser 企业主(应用为平台应用时，需要传此参数)
     * @param sceneId 场景ID,详见 字典说明- AI算法场景类型
     * @param deviceCode 设备码
     * @return
     */
    public Map<String, Object> cancelMessageSubscribe(String enterpriseUser, @NonNull Long sceneId, @NonNull String deviceCode) {
        if (log.isDebugEnabled()) {
            log.debug("request cancelMessageSubscribe enterpriseUser={} sceneId={}, deviceCode={}",
                    enterpriseUser, sceneId, deviceCode);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("sceneId", parseString(sceneId));
        param.put("deviceCode", deviceCode);
        try {
            final String s = this.postRequest(PATH_CANCEL_MESSAGE_SUBSCRIBE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }


    /*******************************
     *          设备基础信息
     ****************************** /

    /**
     * 获取设备详细信息
     * @param enterpriseUser 企业主(应用为平台应用时，需要传此参数)
     * @param deviceCode 设备码
     * @return
     */
    public Map<String, Object> showDevice(String enterpriseUser, @NonNull String deviceCode) {
        if (log.isDebugEnabled()) {
            log.debug("request showDevice enterpriseUser={}, deviceCode={}",
                    enterpriseUser, deviceCode);
        }
        Map<String, String> param = new HashMap<>();
        param.put("accessToken", this.accessToken);
        param.put("enterpriseUser", enterpriseUser);
        param.put("deviceCode", deviceCode);
        try {
            final String s = this.postRequest(PATH_SHOW_DEVICE, param);
            final JSONObject jsonObject = JSONObject.parseObject(s);
            return jsonObject.getInnerMap();
        } catch (Exception e) {
            log.info(e.getLocalizedMessage());
            throw new RuntimeException(e);
        }
    }

    public String decryptByXXTea(@NonNull byte[] data) throws UnsupportedEncodingException {
        return XXTEA.decryptToString(data, config.getSecret());
    }

    public String decryptByRSA(@NonNull byte[] data) {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        try {
            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                    cache = this.rsaCipher.doFinal(data, offset, MAX_DECRYPT_BLOCK);
                } else {
                    cache = this.rsaCipher.doFinal(data, offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_DECRYPT_BLOCK;
            }
            return out.toString(config.getEncoding());
        }catch(Exception e){
            throw new RuntimeException(e);
        } finally {
            IOUtils.closeQuietly(out);
        }
    }

    /**
     * 组合url
     * @param path api路径
     * @return
     */
    private String combPath(String path) {
        return config.getApiUrl() + this.urlPrefix + path;
    }

    private String sign(Map<String, String> requestData) throws NoSuchAlgorithmException, InvalidKeyException {
        List<Map.Entry<String, String>> requestDataList =
            new ArrayList<Map.Entry<String, String>>(requestData.entrySet());
        requestDataList.sort((entry1, entry2) ->
                                             entry1.getKey().compareToIgnoreCase(entry2.getKey()));
        StringBuilder encryptValue = new StringBuilder();
        for (Map.Entry<String, String> entry : requestDataList) {
            if (!Strings.isEmpty(entry.getValue())) {
                encryptValue.append(entry.getValue());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("sign string is {}", encryptValue);
        }
        String signature = getSignature(encryptValue.toString(), config.getSecret(), config.getSignatureAlgorithm()).toUpperCase();
        if (log.isDebugEnabled()) {
            log.debug("signature is {}", signature);
        }
        return signature;
    }

    private String getSignature(String data, String key, String type)
            throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] keyBytes = key.getBytes();
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, type);
        Mac mac = Mac.getInstance(type);
        mac.init(signingKey);
        byte[] rawHmac = mac.doFinal(data.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : rawHmac) {
            sb.append(byteToHexString(b));
        }
        return sb.toString();
    }

    private static String byteToHexString(byte ib) {
        char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                        'a', 'b', 'c', 'd', 'e', 'f' };
        char[] ob = new char[2];
        ob[0] = Digit[(ib >>> 4) & 0X0f];
        ob[1] = Digit[ib & 0X0F];
        String s = new String( ob );
        return s;
    }

    private HttpEntity combBody(Map<String, String> p) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, DecoderException {
        p.entrySet().removeIf((e) -> Objects.isNull(e.getValue()));
        Map<String, String> param = new HashMap<>(6);
        param.put("appId", config.getAppid());
        param.put("clientType", String.valueOf(config.getClientType()));
        param.put("params", encryptBody(p));
        param.put("timestamp", String.valueOf(Instant.now().toEpochMilli()));
        param.put("version", config.getVersion());
        param.put("signature", sign(param));
        return new UrlEncodedFormEntity(param.entrySet().stream()
                .map(e -> new BasicNameValuePair(e.getKey() ,e.getValue()))
                .collect(Collectors.toList()), config.getEncoding()
        );
    }

    private String encryptBody(Map<String, String> paraData) throws DecoderException, UnsupportedEncodingException {
        if (log.isDebugEnabled()) {
            log.debug("para map  is {}", paraData);
        }
        StringBuilder paramBuilder = new StringBuilder();
        for (String key : paraData.keySet()) {
            String value = paraData.get(key);
            paramBuilder.append(key).append("=").append(value).append("&");
        }
        if (paraData.size() > 0) {
            paramBuilder.deleteCharAt(paramBuilder.length() - 1);
        }
        String sortParamStr = paramBuilder.toString();
        if (log.isDebugEnabled()) {
            log.debug("sorted body is {}", sortParamStr);
        }
        String ecryptParam = Hex.encodeHexString(XXTEA.encrypt(sortParamStr, config.getSecret())).toUpperCase();
        if (log.isDebugEnabled()) {
            log.debug("encrypt body is {}", ecryptParam);
        }
        return ecryptParam;
    }

    private String postRequest(String path, Map<String, String> p) {
        HttpResponse response = null;
        try {
            String url = combPath(path);
            final HttpEntity body = combBody(p);
            HttpPost post = new HttpPost(url);
            post.setConfig(this.requestConfig);
            post.setHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");
            post.setHeader("apiVersion", config.getApiVersion());
            post.setEntity(body);

            if (log.isDebugEnabled()) {
                log.debug("post request path=[{}], headers=[{}] body=[{}]",
                        post.getURI().toString(), post.getAllHeaders(), readInputStream(body.getContent(), config.getEncoding()));
            }

            response = client.execute(post);
            String respContent = readInputStream(response.getEntity().getContent(),
                    Objects.isNull(response.getEntity().getContentEncoding()) ? config.getEncoding() : response.getEntity().getContentEncoding().getValue());
            if (log.isDebugEnabled()) {
                log.debug("path=[{}], params=[{}], response status=[{}] content=[{}]", path, p,
                        response.getStatusLine().getStatusCode(), respContent);
            }
            return respContent;
        } catch (Exception e) {
            log.info("path=[{}], params=[{}] error.", path, p, e);
            throw new RuntimeException(e);
        } finally {
            try {
                if (Objects.nonNull(response)) {
                    EntityUtils.consume(response.getEntity());
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private String readInputStream(InputStream i, String encoding) throws IOException {
        return IOUtils.toString(i, Objects.isNull(encoding) ? config.getEncoding() : encoding);
    }

    private String parseString(Object o) {
        if (Objects.isNull(o)) {
            return null;
        } else {
            return o.toString();
        }
    }

}
