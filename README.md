
# hxgsecurity

## 引用方式

```
allprojects {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}	

dependencies {
    implementation 'com.github.huangxiaoguo1:hxgsecurity:1.0.0'
}
```

#### MD5加密

###### 计算字符串MD5值
```
    MD5Utils.md5(String string);
```

###### 计算文件的 MD5 值
```
    MD5Utils.md5(File file);
```
###### 采用nio的方式,计算文件的 MD5 值
```
    MD5Utils.md5Nio(File file);
```
###### 对字符串多次MD5加密
```
    MD5Utils.md5(String string, int times);
```
###### MD5加盐
```
    MD5Utils.md5(String string, String slat);
```


#### Base64加密解密

###### 字符串进行Base64编码加密

```
    Base64Utils.encodeString(String str);
```

###### 字符串进行Base64解码解密

```
    Base64Utils.decodeString(String encodedString);
```

###### 对文件进行Base64编码加密

```
    Base64Utils.encodeFile(String path);
```

###### 对文件进行Base64解码解密

```
    Base64Utils.decodeFile(String encodedPath);
```
#### AES加密解密（这里是常用的CBC模式）

###### Java层设置key和秘钥默认偏移量

```
    AESUtils.setJavaKey(String skey);
    AESUtils.setJavaIvParameter(String ivParameter);
    
    设置key必须为16位，可更改为自己的key，例如：

    AESUtils.setJavaIvParameter("huangxiaoguo1234");
    AESUtils.setJavaKey("5682huangxiaoguo");
```
###### C层设置key和秘钥默认偏移量

    方式为进行NDK开发打包成.so文件，放进你当前类对应的module的libs中，
    并进行build.gradle配置
```
    android {
        ...
        sourceSets {
            main {
                jniLibs.srcDirs = ['libs']
            }
        }
    }
```
    jni对应的包名为cn.tsou.lib_security.aes
    jni对应的获取key的方法名为getKey()
    jni对应的获取IvParameter的方法名为getIvParameter()
    
    如下JNI简例：
    
```
#include <jni.h>

//JNIEXPORT jstring JNICALL
jstring Java_cn_tsou_lib_1security_aes_AEScbc_getKey(JNIEnv
                                                       *env, jobject instance) {

    return (*env)->NewStringUTF(env, "huangxiaoguo1234");
}
jstring Java_cn_tsou_lib_1security_aes_AEScbc_getIvParameter(JNIEnv
                                                       *env, jobject instance) {

    return (*env)->NewStringUTF(env, "1234huangxiaoguo");
}
```
    检查你设置的key和IvParameter是否生效的Log日志筛选tag条件为：huangxiaoguo


###### AES加密

```
    AESUtils.getInstance().encrypt(String plaintext);
```
###### AES解密

```
    AESUtils.getInstance().decrypt(String ciphertext_base64);
```

#### RSA加密解密

        创建一个公共和私人密钥,并将其存储使用Android密钥存储库中,因此,只有
        这个应用程序将能够访问键。

###### 使用之前请先初始化RSAinit

    最好放在启动页初始化需要一些时间

```
  private RSAPublicKey publicKey = RSAinit.initRSA(this, null, null, 0, null);
```
       initRSA参数介绍
       
       initRSA(Context context,String pcksPadding,String split,int keySize,String alias);
       
       context:上下文
       
       pcksPadding: 加密填充方式  传null，默认："RSA/ECB/PKCS1Padding"
       
       split: 当要加密的内容超过bufferSize，则采用partSplit进行分块加密，
              传null，默认："#HUANGXIAOGUO#"
       
       keySize: 秘钥默认长度，传0，默认：2048
       
       alias: 自己给你的别名，方便在keystore中查找秘钥，传null，默认："xiaoGuoKey"

###### 获取客户端公钥的base64编码的String,登录时将公钥传递给后台

```
   String localPublicKey = EncodeUtils.base64Encode2String(publicKey.getEncoded());
```

###### 用公钥对字符串进行加密(一般使用公钥进行加密)

```
   AndroidKeyStoreRSAUtils.encryptByPublicKey(byte[] data, byte[] publicKey);
   
   简例：
   byte[] encryptBytes = AndroidKeyStoreRSAUtils.encryptByPublicKey(encryptionRSAString.getBytes(),
                               publicKey.getEncoded());
    String encryStr = Base64Encoder.encode(encryptBytes);
```

###### 私钥加密

```
   AndroidKeyStoreRSAUtils.encryptByPrivateKey(byte[] data, byte[] privateKey);
```

###### 公钥解密

```
   AndroidKeyStoreRSAUtils.decryptByPublicKey(byte[] data, byte[] publicKey);
```

###### 使用私钥进行解密(一般使用私钥进行解密)

```
   AndroidKeyStoreRSAUtils.decryptByPrivateKey(byte[] encrypted);
   
   简例：
   
    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(Base64Decoder.decodeToBytes(decodeRSAString));
    
    mTvRsaDecode.setText(new String(decryptBytes));
```

###### 用公钥对字符串进行分段加密

```
   AndroidKeyStoreRSAUtils.encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey);
```

###### 私钥分段加密

```
   AndroidKeyStoreRSAUtils.encryptByPrivateKeyForSpilt(byte[] data, byte[] privateKey);
```

###### 公钥分段解密

```
   AndroidKeyStoreRSAUtils.decryptByPublicKeyForSpilt(byte[] encrypted, byte[] publicKey);
```

###### 使用私钥分段解密

```
   AndroidKeyStoreRSAUtils.decryptByPrivateKeyForSpilt(byte[] encrypted);
```

###### 通过字符串生成私钥，转换服务器传递过来的私钥

```
   AndroidKeyStoreRSAUtils.getPrivateKey(String privateKeyData);
```

###### 通过字符串生成公钥，转换服务器传递过来的公钥

```
   AndroidKeyStoreRSAUtils.getPublicKey(String publicKeyData);
```

###### 判断是否创建过秘钥

```
   AndroidKeyStoreRSAUtils.isHaveKeyStore();
```

###### 获得本地AndroidKeyStore中的公钥
    

```
   AndroidKeyStoreRSAUtils.getLocalPublicKey();
```

#### RSA签名验证
       
        使用之前请先初始化RSAinit
        
 ###### 签名 
 ```
 AndroidKeyStoreRSAUtils.signData(String inputStr);
 ```
 ###### 校验签名的字符串 

```
   boolean b = AndroidKeyStoreRSAUtils. verifyData(String input, String signatureStr);
   
                       
        if (b) {
              mTvRsaVerify.setText("签名一致");
           } else {
              mTvRsaVerify.setText("签名不一致");
           }
```
#### SP加密存储(使用的是RSA)

    使用之前请先初始化RSAinit
    
###### SP存入

```
    SPSecuredUtils.put(Context context, String key, Object object, RSAPublicKey publicKey);
    
    简例：
    SPSecuredUtils.put(this, "huangxiaoguo", encryptionSpString, publicKey);
    SPSecuredUtils.put(this, "huangxiaoguo1", 1, publicKey);
    SPSecuredUtils.put(this, "huangxiaoguo2", 0.01, publicKey);
    SPSecuredUtils.put(this, "huangxiaoguo3", true, publicKey);
```

###### SP读取

```
    SPSecuredUtils.get(Context context, String key, Object defaultObject);
    
   String huangxiaoguo = (String) SPSecuredUtils.get(this, "huangxiaoguo", "");
   int huangxiaoguo1 = (int) SPSecuredUtils.get(this, "huangxiaoguo1", 0);
   double huangxiaoguo2 = (double) SPSecuredUtils.get(this, "huangxiaoguo2", 0.0);
   boolean huangxiaoguo3 = (boolean) SPSecuredUtils.get(this, "huangxiaoguo3", false);
```

###### 将对象储存到sharepreference

```
   SPSecuredUtils.saveDeviceData(Context context, String key, T device, RSAPublicKey publicKey);
```

###### 将对象从shareprerence中取出来

```
   SPSecuredUtils.getDeviceData(Context context, String key)
```

###### 移除某个key值已经对应的值

```
   SPSecuredUtils.remove(Context context, String key);
```

###### 清除所有数据

```
   SPSecuredUtils.clear(Context context);
```

###### 查询某个key是否已经存在

```
   SPSecuredUtils.contains(Context context, String key);
```

###### 返回所有的键值对

```
   SPSecuredUtils.getAll(Context context);
```

