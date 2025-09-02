# ws_proxy

## 说明
ws_proxy 是一个简单的 websocket 代理服务器，开发此项目的原因是因为在windows上搭建v2ray太麻烦以及薅免费容器

## 安装
```
git clone git@github.com:Anderyly/ws_proxy.git 
cd ws_proxy
go mod tidy
go build
```

## 配置
1. 配置文件为 set.ini，配置项说明如下：
    ```ini
    [main]
    ; 生成的vless名称
    name = hk 
    ; cf解析的域名
    domain = xxx.qzz.io
    
    [server]
    uuid = c6f77633-cf3a-4150-bf1e-d4de3a4b32c7
    port = 22222
    ; ws路径
    ws_path = /ws
    
    [ssl]
    ; cf自签证书
    cert_address = ./pem/cert.pem
    key_address = ./pem/key.pem
    ```
   支持Env变量
   ```text
   UUID
   DOMAIN
   NAME
   PORT
   WS_PATH
   CERT_ADDRESS
   KEY_ADDRESS 
   ```
   
2. cf解析域名
    cf解析域名到服务器IP并且在Origin Rules中重写端口

3. 获取地址
   访问 https://域名/get 获取vless地址导入客户端
