package burp.Application.DelayExtension.ExtensionMethod;

import burp.*;
import burp.Application.ExtensionInterface.AAppExtension;
import burp.Bootstrap.BurpAnalyzedRequest;
import burp.Bootstrap.CustomHelpers;
import burp.Bootstrap.GlobalVariableReader;
import burp.Bootstrap.YamlReader;
import burp.CustomErrorException.TaskTimeoutException;

import java.io.PrintWriter;
import java.net.URL;
import java.util.Date;
import java.util.List;

public class DelayScan extends AAppExtension {
    private GlobalVariableReader globalVariableReader;

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private BurpAnalyzedRequest analyzedRequest;
    private IHttpRequestResponse requestResponse;

    private YamlReader yamlReader;

    private List<String> payloads;

    private Date startDate;
    private int maxExecutionTime;

    //待探测端口
    private List<String> scanPort;
    //检测标准
    private int multiple;

    //开放端口
    private Integer openPort;
    //正常响应时间
    private long nomalTime;
    //成功延时端口
    private Integer delayPort;
    //延时响应时间
    private long delayTime;

    public DelayScan(GlobalVariableReader globalVariableReader,
                     IBurpExtenderCallbacks callbacks, BurpAnalyzedRequest analyzedRequest,
                     YamlReader yamlReader, List<String> payloads,
                     Date startDate, Integer maxExecutionTime){
        this.globalVariableReader = globalVariableReader;

        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.analyzedRequest = analyzedRequest;
        this.requestResponse = this.analyzedRequest.requestResponse();

        this.yamlReader = yamlReader;

        this.payloads = payloads;

        this.startDate = startDate;
        this.maxExecutionTime = maxExecutionTime;

        this.setExtensionName("DelayScan");
        this.registerExtension();

        this.runExtension();
    }

    private void runExtension() {
        for (String payload : this.payloads) {
            // 这个参数为true说明插件已经被卸载,退出所有任务,避免继续扫描
            if (this.globalVariableReader.getBooleanData("isExtensionUnload")) {
                return;
            }

            if (this.isIssue()) {
                return;
            }

            // 判断程序是否运行超时
            Integer startTime = CustomHelpers.getSecondTimestamp(this.startDate);
            Integer currentTime = CustomHelpers.getSecondTimestamp(new Date());
            Integer runTime = currentTime - startTime;
            if (runTime >= this.maxExecutionTime) {
                throw new TaskTimeoutException("scan task timed out");
            }

            // 实际业务处理
            this.delayDetection(payload);
        }
    }

    private void delayDetection(String payload) {
        this.scanPort = this.yamlReader.getStringList("application.DelayExtension.config.port");
        this.multiple = this.yamlReader.getInteger("application.DelayExtension.config.multiple");

        //发送请求到确定开放端口
        this.nomalTime = getNormalTime(requestResponse);

        //发送请求到待检测可能未开放端口
        for (String port : this.scanPort) {
            delayTime = analyzedRequest.makeHttpRequest_Delay(payload.replace("port", port), null);
            if (delayTime > this.nomalTime * this.multiple){
                //二次校验，防止网络异常问题
                this.nomalTime = getNormalTime(requestResponse);
                if (delayTime < this.nomalTime * this.multiple){
                    continue;
                }
                this.delayPort = Integer.valueOf(port);
                break;
            }
        }

        // 设置问题详情
        this.setIssuesDetail(this.analyzedRequest.getNewRequestResponse(), requestResponse.getHttpService().getPort(), this.nomalTime, delayPort, delayTime);

    }

    /**
     * 设置问题详情
     */
    private void setIssuesDetail(IHttpRequestResponse httpRequestResponse, Integer val1, long val2, Integer val3, long val4) {
        this.setIssueState(true);
        this.setHttpRequestResponse(httpRequestResponse);
        this.setOpenPort(val1);
        this.setNomalTime(val2);
        this.setClosePort(val3);
        this.setDelayTime(val4);
    }

    /**
     * 获取原始请求响应时间
     * @param requestResponse
     * @return
     */
    private long getNormalTime(IHttpRequestResponse requestResponse) {

        long l = System.currentTimeMillis();
        this.callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        long normalTime = System.currentTimeMillis() - l;

        return normalTime;
    }

    private void setOpenPort(Integer openPort) {
        this.openPort = openPort;
    }

    private void setClosePort(Integer delayPort) {
        this.delayPort = delayPort;
    }

    public Integer getOpenPort() {
        return openPort;
    }

    public Integer getDelayPort() {
        return delayPort;
    }

    public void setNomalTime(long nomalTime) {
        this.nomalTime = nomalTime;
    }

    public void setDelayTime(long delayTime) {
        this.delayTime = delayTime;
    }

    public long getNomalTime() {
        return nomalTime;
    }

    public long getDelayTime() {
        return delayTime;
    }

    @Override
    public IScanIssue export() {
        if (!this.isIssue()) {
            return null;
        }

        IHttpRequestResponse newHttpRequestResponse = this.getHttpRequestResponse();
        URL newHttpRequestUrl = this.helpers.analyzeRequest(newHttpRequestResponse).getUrl();

        String str1 = String.format("<br/>=============delayExtension============<br/>");
        String str2 = String.format("ExtensionMethod: %s <br/>", this.getExtensionName());
        String str3 = String.format("openPort: %s <br/>", this.getOpenPort());
        String str4 = String.format("nomalTime: %s ms<br/>", this.getNomalTime());
        String str5 = String.format("delayPort: %s <br/>", this.getDelayPort());
        String str6 = String.format("delayTime: %s ms <br/>", this.getDelayTime());
        String str7 = String.format("=====================================<br/>");

        String detail = str1 + str2 + str3 + str4 + str5 + str6 + str7;

        String issueName = this.yamlReader.getString("application.DelayExtension.config.issueName");

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
        stdout.println("===========delayExtension详情============");
        stdout.println("你好呀~ (≧ω≦*)喵~");
        stdout.println("这边检测到有一个站点有命令执行 喵~");
        stdout.println(String.format("负责检测的插件: %s", this.getExtensionName()));
        stdout.println(String.format("url: %s", newHttpRequestUrl));
        stdout.println(String.format("开放端口: %s", this.getOpenPort()));
        stdout.println(String.format("正常响应时间: %s ms", this.getNomalTime()));
        stdout.println(String.format("存在延迟的端口: %s", this.getDelayPort()));
        stdout.println(String.format("延迟时间: %s ms", this.getDelayTime()));
        stdout.println("详情请查看-Burp Scanner模块-Issue activity界面");
        stdout.println("===================================");
        stdout.println("");
    }
}
