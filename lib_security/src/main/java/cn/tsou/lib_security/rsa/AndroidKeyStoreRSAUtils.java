package cn.tsou.lib_security.rsa;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;

import cn.tsou.lib_security.aes.Base64Decoder;

public class AndroidKeyStoreRSAUtils {

    public static String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";//加密填充方式
    public static int DEFAULT_KEY_SIZE = 2048;//秘钥默认长度
    // 当要加密的内容超过bufferSize，则采用partSplit进行分块加密
    public static byte[] DEFAULT_SPLIT = "#HUANGXIAOGUO#".getBytes();
    public static int DEFAULT_BUFFERSIZE = (DEFAULT_KEY_SIZE / 8) - 11;// 当前秘钥支持加密的最大字节数
    /**
     * 自己给你的别名，方便在keystore中查找秘钥
     */
    public static String SAMPLE_ALIAS = "xiaoGuoKey";

    /**
     * 自己给你的别名  就是SAMPLE_ALIAS
     */
    private static String mAlias = null;

    public static void setEcbPcksPadding(String pcksPadding) {
        ECB_PKCS1_PADDING = pcksPadding;
    }

    public static void setSplit(String split) {
        DEFAULT_SPLIT = split.getBytes();
    }

    public static void setKeySize(int keySize) {
        DEFAULT_KEY_SIZE = keySize;
    }
    public static void setOwnAlias(String alias){
        SAMPLE_ALIAS=alias;
    }
    private static void setAlias(String alias) {
        mAlias = alias;
    }

    /**
     * 创建一个公共和私人密钥,并将其存储使用Android密钥存储库中,因此,只有
     * 这个应用程序将能够访问键。
     *
     * @param context
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    @SuppressLint("NewApi")
    public static KeyPair generateRSAKeyPair(Context context) throws
            InvalidAlgorithmParameterException,
            NoSuchProviderException, NoSuchAlgorithmException {
        setAlias(SAMPLE_ALIAS);
        //创建一个开始和结束时间,有效范围内的密钥对才会生成。
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);//往后加一年
        AlgorithmParameterSpec spec;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            //使用别名来检索的key 。这是一个key 的key !
            spec = new KeyPairGeneratorSpec.Builder(context)
                    //使用别名来检索的关键。这是一个关键的关键!
                    .setAlias(mAlias)
                    // 用于生成自签名证书的主题 X500Principal 接受 RFC 1779/2253的专有名词
                    .setSubject(new X500Principal("CN=" + mAlias))
                    //用于自签名证书的序列号生成的一对。
                    .setSerialNumber(BigInteger.valueOf(1337))
                    // 签名在有效日期范围内
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .build();
        } else {
            //Android 6.0(或者以上)使用KeyGenparameterSpec.Builder 方式来创建,
            // 允许你自定义允许的的关键属性和限制
            spec = new KeyGenParameterSpec.Builder(mAlias, KeyProperties.PURPOSE_SIGN
                    | KeyProperties.PURPOSE_ENCRYPT
                    | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(DEFAULT_KEY_SIZE)
                    .setUserAuthenticationRequired(false)
                    .setCertificateSubject(new X500Principal("CN=" + mAlias))
                    //, KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA224, KeyProperties.DIGEST_SHA384,
                    // KeyProperties.DIGEST_SHA512, KeyProperties.DIGEST_MD5)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                    .setCertificateNotBefore(start.getTime())
                    .setCertificateNotAfter(end.getTime())
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build();
        }
        KeyPairGenerator kpGenerator = KeyPairGenerator
                .getInstance(SecurityConstants.TYPE_RSA,
                        SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        kpGenerator.initialize(spec);
        KeyPair kp = kpGenerator.generateKeyPair();
        return kp;
    }

    /**
     * 用公钥对字符串进行加密
     *
     * @param data 原文
     */
    public static byte[] encryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        // 得到公钥  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(SecurityConstants.TYPE_RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 加密数据  
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.ENCRYPT_MODE, keyPublic);
        return cp.doFinal(data);
    }


    /**
     * 私钥加密
     *
     * @param data       待加密数据
     * @param privateKey 密钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPrivateKey(byte[] data, byte[] privateKey) throws Exception {
        // 得到私钥  
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(SecurityConstants.TYPE_RSA);
        PrivateKey keyPrivate = kf.generatePrivate(keySpec);
        // 数据加密  
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, keyPrivate);
        return cipher.doFinal(data);
    }

    /**
     * 公钥解密
     *
     * @param data      待解密数据
     * @param publicKey 密钥
     * @return byte[] 解密数据
     */
    public static byte[] decryptByPublicKey(byte[] data, byte[] publicKey) throws Exception {
        // 得到公钥  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(SecurityConstants.TYPE_RSA);
        PublicKey keyPublic = kf.generatePublic(keySpec);
        // 数据解密  
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, keyPublic);
        return cipher.doFinal(data);
    }

    /**
     * 使用私钥进行解密
     */
    public static byte[] decryptByPrivateKey(byte[] encrypted) throws Exception {

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        if (mAlias == null) {
            setAlias(SAMPLE_ALIAS);
        }
        //从Android加载密钥对密钥存储库中
        KeyStore.Entry entry = ks.getEntry(mAlias, null);
        if (entry == null) {
            return null;
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            return null;
        }
        PrivateKey keyPrivate = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        // 解密数据
        Cipher cp = Cipher.getInstance(ECB_PKCS1_PADDING);
        cp.init(Cipher.DECRYPT_MODE, keyPrivate);
        byte[] arr = cp.doFinal(encrypted);
        return arr;
    }

    /**
     * 用公钥对字符串进行分段加密
     */
    public static byte[] encryptByPublicKeyForSpilt(byte[] data, byte[] publicKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPublicKey(data, publicKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPublicKey(buf, publicKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 私钥分段加密
     *
     * @param data       要加密的原始数据
     * @param privateKey 秘钥
     */
    public static byte[] encryptByPrivateKeyForSpilt(byte[] data, byte[] privateKey) throws Exception {
        int dataLen = data.length;
        if (dataLen <= DEFAULT_BUFFERSIZE) {
            return encryptByPrivateKey(data, privateKey);
        }
        List<Byte> allBytes = new ArrayList<Byte>(2048);
        int bufIndex = 0;
        int subDataLoop = 0;
        byte[] buf = new byte[DEFAULT_BUFFERSIZE];
        for (int i = 0; i < dataLen; i++) {
            buf[bufIndex] = data[i];
            if (++bufIndex == DEFAULT_BUFFERSIZE || i == dataLen - 1) {
                subDataLoop++;
                if (subDataLoop != 1) {
                    for (byte b : DEFAULT_SPLIT) {
                        allBytes.add(b);
                    }
                }
                byte[] encryptBytes = encryptByPrivateKey(buf, privateKey);
                for (byte b : encryptBytes) {
                    allBytes.add(b);
                }
                bufIndex = 0;
                if (i == dataLen - 1) {
                    buf = null;
                } else {
                    buf = new byte[Math.min(DEFAULT_BUFFERSIZE, dataLen - i - 1)];
                }
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 公钥分段解密
     *
     * @param encrypted 待解密数据
     * @param publicKey 密钥
     */
    public static byte[] decryptByPublicKeyForSpilt(byte[] encrypted, byte[] publicKey) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPublicKey(encrypted, publicKey);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了  
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头  
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围  
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段  
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了  
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPublicKey(part, publicKey);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 使用私钥分段解密
     */
    public static byte[] decryptByPrivateKeyForSpilt(byte[] encrypted) throws Exception {
        int splitLen = DEFAULT_SPLIT.length;
        if (splitLen <= 0) {
            return decryptByPrivateKey(encrypted);
        }
        int dataLen = encrypted.length;
        List<Byte> allBytes = new ArrayList<Byte>(1024);
        int latestStartIndex = 0;
        for (int i = 0; i < dataLen; i++) {
            byte bt = encrypted[i];
            boolean isMatchSplit = false;
            if (i == dataLen - 1) {
                // 到data的最后了  
                byte[] part = new byte[dataLen - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            } else if (bt == DEFAULT_SPLIT[0]) {
                // 这个是以split[0]开头  
                if (splitLen > 1) {
                    if (i + splitLen < dataLen) {
                        // 没有超出data的范围  
                        for (int j = 1; j < splitLen; j++) {
                            if (DEFAULT_SPLIT[j] != encrypted[i + j]) {
                                break;
                            }
                            if (j == splitLen - 1) {
                                // 验证到split的最后一位，都没有break，则表明已经确认是split段  
                                isMatchSplit = true;
                            }
                        }
                    }
                } else {
                    // split只有一位，则已经匹配了  
                    isMatchSplit = true;
                }
            }
            if (isMatchSplit) {
                byte[] part = new byte[i - latestStartIndex];
                System.arraycopy(encrypted, latestStartIndex, part, 0, part.length);
                byte[] decryptPart = decryptByPrivateKey(part);
                for (byte b : decryptPart) {
                    allBytes.add(b);
                }
                latestStartIndex = i + splitLen;
                i = latestStartIndex - 1;
            }
        }
        byte[] bytes = new byte[allBytes.size()];
        {
            int i = 0;
            for (Byte b : allBytes) {
                bytes[i++] = b.byteValue();
            }
        }
        return bytes;
    }

    /**
     * 通过字符串生成私钥，转换服务器传递过来的私钥
     */
    public static PrivateKey getPrivateKey(String privateKeyData) {
        PrivateKey privateKey = null;
        try {
            byte[] decodeKey = Base64Decoder.decodeToBytes(privateKeyData);
            PKCS8EncodedKeySpec x509 = new PKCS8EncodedKeySpec(decodeKey);//创建x509证书封装类  
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");//指定RSA  
            privateKey = keyFactory.generatePrivate(x509);//生成私钥  
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }

    /**
     * 通过字符串生成公钥，转换服务器传递过来的公钥
     */
    public static PublicKey getPublicKey(String publicKeyData) {
        PublicKey publicKey = null;
        try {
            byte[] decodeKey = Base64Decoder.decodeToBytes(publicKeyData);
            X509EncodedKeySpec x509 = new X509EncodedKeySpec(decodeKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(x509);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }


    /**
     * 判断是否创建过秘钥
     *
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableEntryException
     */
    public static boolean isHaveKeyStore() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (mAlias == null) {
                setAlias(SAMPLE_ALIAS);
            }
            //从Android加载密钥对密钥存储库中
            KeyStore.Entry entry = ks.getEntry(mAlias, null);
            if (entry == null) {
                return false;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return false;
        } catch (CertificateException e) {
            e.printStackTrace();
            return false;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * 获得本地AndroidKeyStore中的公钥
     *
     * @return
     */
    public static PublicKey getLocalPublicKey() {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (mAlias == null) {
                setAlias(SAMPLE_ALIAS);
            }
            //从Android加载密钥对密钥存储库中
            KeyStore.Entry entry = ks.getEntry(mAlias, null);
            if (entry == null) {
                return null;
            }

            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                return null;
            }
            PublicKey publicKey = ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey();
            return publicKey;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return null;
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
            return null;
        }
    }
    //-----------------------------------数据签名使用---------------------------------------------

    /**
     * 签名
     *
     * @param inputStr
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableEntryException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String signData(String inputStr) throws KeyStoreException, CertificateException,
            NoSuchAlgorithmException, IOException, UnrecoverableEntryException,
            InvalidKeyException, SignatureException {
        byte[] data = inputStr.getBytes();
        //AndroidKeyStore
        KeyStore ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        // 如果你没有InputStream加载,你仍然需要
        //称之为“负载”,或者它会崩溃
        ks.load(null);
        if (mAlias == null) {
            setAlias(SAMPLE_ALIAS);
        }
        //从Android加载密钥对密钥存储库中
        KeyStore.Entry entry = ks.getEntry(mAlias, null);
         /* *
         *进行判断处理钥匙是不是存储的当前别名下 不存在要遍历别名列表Keystore.aliases()
         */
        if (entry == null) {
            Log.w("huangxiaoguo", "No key found under alias: " + mAlias);
            Log.w("huangxiaoguo", "Exiting signData()...");
            return null;
        }
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("huangxiaoguo", "Not an instance of a PrivateKeyEntry");
            Log.w("huangxiaoguo", "Exiting signData()...");
            return null;
        }
        // 开始签名
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);
        //初始化使用指定的私钥签名
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        // 签名并存储结果作为Base64编码的字符串。
        s.update(data);
        byte[] signature = s.sign();
        String result = Base64.encodeToString(signature, Base64.DEFAULT);
        return result;
    }

    /**
     * 校验签名的字符串
     *
     * @param input
     * @param signatureStr
     * @return
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws UnrecoverableEntryException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verifyData(String input, String signatureStr) throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException {

        //要验证的数据
        byte[] data = input.getBytes();
        //签名
        byte[] signature;


        //判断签名是否存在
        if (signatureStr == null) {
            Log.w("huangxiaoguo", "Invalid signature.");
            Log.w("huangxiaoguo", "Exiting verifyData()...");
            return false;
        }

        try {

            //Base64解码字符串
            signature = Base64.decode(signatureStr, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            return false;
        }
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);

        // Load the key pair from the Android Key Store
        if (mAlias == null) {
            setAlias(SAMPLE_ALIAS);
        }
        //从Android加载密钥对密钥存储库中
        KeyStore.Entry entry = ks.getEntry(mAlias, null);
        if (entry == null) {
            Log.w("huangxiaoguo", "No key found under alias: " + mAlias);
            Log.w("huangxiaoguo", "Exiting verifyData()...");
            return false;
        }
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("huangxiaoguo", "Not an instance of a PrivateKeyEntry");
            return false;
        }
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);
        // 开始校验签名
        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        boolean valid = s.verify(signature);
        return valid;//true 签名一致
    }
}
