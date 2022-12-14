package burp.Application.RemoteCmdExtension.ExtensionMethod;

import java.net.URL;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.io.PrintWriter;

import burp.*;

import burp.Bootstrap.GlobalVariableReader;
import burp.CustomScanIssue;
import burp.DnsLogModule.DnsLog;
import burp.Bootstrap.YamlReader;
import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Application.ExtensionInterface.AAppExtension;
import burp.CustomErrorException.TaskTimeoutException;

public class RemoteCmdScan extends AAppExtension {
    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private BurpAnalyzedRequest analyzedRequest;

    private DnsLog dnsLog;

    private YamlReader yamlReader;

    private List<String> payloads;

    private Date startDate;
    private int maxExecutionTime;

    private String sendDnsLogUrl;

    private ArrayList<String> keyArrayList = new ArrayList<>();
    private ArrayList<String> dnsLogUrlArrayList = new ArrayList<>();
    private ArrayList<IHttpRequestResponse> httpRequestResponseArrayList = new ArrayList<>();

    public RemoteCmdScan(GlobalVariableReader globalVariableReader,
                         IBurpExtenderCallbacks callbacks, BurpAnalyzedRequest analyzedRequest,
                         DnsLog dnsLog, YamlReader yamlReader, List<String> payloads,
                         Date startDate, Integer maxExecutionTime) {
        this.globalVariableReader = globalVariableReader;

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.analyzedRequest = analyzedRequest;

        this.dnsLog = dnsLog;

        this.yamlReader = yamlReader;

        this.payloads = payloads;

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("RemoteCmdScan");
        this.registerExtension();

        this.runExtension();
    }

    private void runExtension() {
        for (String payload : this.payloads) {
            // ???????????????true???????????????????????????,??????????????????,??????????????????
            if (this.globalVariableReader.getBooleanData("isExtensionUnload")) {
                return;
            }

            // ??????????????????dnslog???????????????FastJson
            if (this.isIssue()) {
                return;
            }

            // ??????dnslog??????????????? this.isIssue() ???false
            // ?????????????????? ?????????????????? dnslog??????????????????
            // ??????????????????????????????????????????, ???????????????
            // ????????????????????????
            if (this.dnsLog.run().getBodyContent() != null) {
                if (this.dnsLog.run().getBodyContent().length() >= 1) {
                    break;
                }
            }

            // ??????????????????????????????
            Integer startTime = CustomHelpers.getSecondTimestamp(this.startDate);
            Integer currentTime = CustomHelpers.getSecondTimestamp(new Date());
            Integer runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("scan task timed out");
            }

            // ??????????????????
            this.remoteCmdDetection(payload);
        }

        // ????????????dnslog?????????????????????????????????, ????????????????????????, ??????????????????
        // ??????????????????, ???dnslog??????????????????
        try {
            Thread.sleep(8000);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        // ????????????????????????
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // ????????????????????????
        for (int i = 0; i < this.keyArrayList.size(); i++) {
            // dnslog ??????????????????
            if (!dnsLogBodyContent.contains(this.keyArrayList.get(i))) {
                if ((i + 1) != this.keyArrayList.size()) {
                    continue;
                } else {
                    return;
                }
            }

            // ??????????????????
            this.setIssuesDetail(this.httpRequestResponseArrayList.get(i), this.dnsLogUrlArrayList.get(i));
            return;
        }
    }

    private void remoteCmdDetection(String payload) {
        String key = CustomHelpers.randomStr(15);
        String dnsLogUrl = key + "." + this.dnsLog.run().getTemporaryDomainName();

        // ????????????
        IHttpRequestResponse newHttpRequestResponse = analyzedRequest.makeHttpRequest(payload.replace("dnslog-url", dnsLogUrl), null);

        // ??????????????????
        this.keyArrayList.add(key);
        this.dnsLogUrlArrayList.add(dnsLogUrl);
        this.httpRequestResponseArrayList.add(newHttpRequestResponse);

        // dnslog ?????????????????????
        String dnsLogBodyContent = this.dnsLog.run().getBodyContent();
        if (dnsLogBodyContent == null || dnsLogBodyContent.length() <= 0) {
            return;
        }

        // dnslog ??????????????????
        if (!dnsLogBodyContent.contains(key)) {
            return;
        }

        // ??????????????????
        this.setIssuesDetail(newHttpRequestResponse, dnsLogUrl);
    }

    /**
     * ??????????????????
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, String dnsLogUrl) {
        this.setIssueState(true);
        this.setHttpRequestResponse(httpRequestResponse);

        this.sendDnsLogUrl = dnsLogUrl;
    }

    @Override
    public IScanIssue export() {
        if (!this.isIssue()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============RemoteCmdExtension============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("sendDnsLogUrl: %s <br/>", this.sendDnsLogUrl);
        String str4 = String.format("=====================================<br/>");

        // dnslog ????????????
        String str5 = this.dnsLog.run().export();

        // dnslog body????????????
        String str6 = String.format("<br/>=============DnsLogBodyContent============<br/>");
        String str7 = this.dnsLog.run().getBodyContent();
        String str8 = String.format("<br/>=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7 + str8;

        String issueName = this.yamlReader.getString("application.remoteCmdExtension.config.issueName");

        return new CustomScanIssue(
                newHttpRequestUrl,
                issueName,
                0,
                "High",
                "Certain",
                null,
                null,
                detail,
                null,
                new IHttpRequestResponse[]{newHttpRequestResponse},
                newHttpRequestResponse.getHttpService()
        );
    }

    @Override
    public void consoleExport() {
        if (!this.isIssue()) {
            return;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();
        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);

        stdout.println("");
        stdout.println("===========RemoteCmdExtension??????============");
        stdout.println("?????????~ (????????*)???~");
        stdout.println("???????????????????????????????????????????????????dns?????? ???~");
        stdout.println(String.format("?????????????????????: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("?????????dnsLogUrl: %s", this.sendDnsLogUrl));
        stdout.println("???????????????-Burp Scanner??????-Issue activity??????");
        stdout.println("===================================");
        stdout.println("");

        stdout.println("");
        stdout.println("===========DnsLog????????????============");
        stdout.println(this.dnsLog.run().getBodyContent());
        stdout.println("===================================");
        stdout.println("");

        // dnslog ?????????????????????
        this.dnsLog.run().consoleExport();
    }
}
