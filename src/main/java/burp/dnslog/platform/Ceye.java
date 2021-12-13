package burp.dnslog.platform;

import burp.BurpExtender;
import burp.dnslog.IDnslog;
import burp.utils.HttpUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import okhttp3.OkHttpClient;
import okhttp3.Response;

import java.util.concurrent.TimeUnit;


public class Ceye implements IDnslog {
    OkHttpClient client = new OkHttpClient().newBuilder().
            connectTimeout(30, TimeUnit.SECONDS).
            callTimeout(30, TimeUnit.SECONDS).build();
    String platformUrl = "http://api.ceye.io/";
    String rootDomain = "6i81ez.ceye.io";
    String token = "60d94b19a4ee341e556a2021ffe2cec0";

    @Override
    public String getName() {
        return "Ceye.io";
    }

    @Override
    public String getNewDomain() {
        return Utils.GetRandomString(6) + "." + rootDomain;
    }

    @Override
    public boolean CheckResult(String domain) {
        try {
            Response resp = client.newCall(HttpUtils.GetDefaultRequest(platformUrl + "v1/records?token=" + token + "&type=dns&filter=" + domain.substring(0, domain.indexOf("."))).build()).execute();
            JSONObject jObj = JSONObject.parseObject(resp.body().string());
            if (jObj.containsKey("data")) {
                return (((JSONArray) jObj.get("data")).size() > 0);
            }
        } catch (Exception ex) {
            System.out.println(ex);
            return false;
        }
        return false;
    }

    @Override
    public boolean flushCache() {
        return true;
    }

    @Override
    public boolean getState() {
        return true;
    }
}
