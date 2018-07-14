package cn.tsou.lib_security.aes;

import android.text.TextUtils;
import android.util.Log;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {
    private final String CIPHERMODEPADDING = "AES/CBC/PKCS5Padding";// AES/CBC/PKCS7Padding

    private SecretKeySpec skforAES = null;
    //private static String ivParameter = "1234huangxiaoguo";// 密钥默认偏移，可更改
    private static String mIvParameter;// 密钥默认偏移，可更改

    private IvParameterSpec IV;
    //    String sKey = "huangxiaoguo1234";// key必须为16位，可更改为自己的key
    private static String mSKey;
    private static AESUtils instance = null;

    public static AESUtils getInstance() {
        if (instance == null) {
            synchronized (AESUtils.class) {
                if (instance == null) {
                    if (TextUtils.isEmpty(mSKey))
                        mSKey = AEScbc.getKey();
                    if (TextUtils.isEmpty(mIvParameter))
                        mIvParameter = AEScbc.getIvParameter();
                    instance = new AESUtils();
                }
            }
        }
        return instance;
    }

    /**
     * 设置key必须为16位，可更改为自己的key
     *
     * @param skey
     */
    public static void setJavaKey(String skey) {
        mSKey = skey;
    }

    /**
     * 设置秘钥默认偏移量
     *
     * @param ivParameter
     */
    public static void setJavaIvParameter(String ivParameter) {
        mIvParameter = ivParameter;
    }

    public AESUtils() {
        byte[] skAsByteArray;
        try {
            skAsByteArray = mSKey.getBytes("ASCII");
            skforAES = new SecretKeySpec(skAsByteArray, "AES");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        IV = new IvParameterSpec(mIvParameter.getBytes());
        Log.e("huangxiaoguo","mSKey==>"+mSKey);
        Log.e("huangxiaoguo","mIvParameter==>"+mIvParameter);
    }

    /**
     * 加密
     *
     * @param plaintext
     * @return
     */
    public String encrypt(String plaintext) {
        try {
            byte[] plainbyte = plaintext.getBytes("UTF8");
            byte[] ciphertext = encrypt(CIPHERMODEPADDING, skforAES, IV, plainbyte);
            String base64_ciphertext = Base64Encoder.encode(ciphertext);
            return base64_ciphertext;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param ciphertext_base64
     * @return
     */
    public String decrypt(String ciphertext_base64) {
        byte[] s = Base64Decoder.decodeToBytes(ciphertext_base64);
        String decrypted = new String(decrypt(CIPHERMODEPADDING, skforAES, IV,
                s));
        return decrypted;
    }

    private byte[] encrypt(String cmp, SecretKey sk, IvParameterSpec IV,
                           byte[] msg) {
        try {
            Cipher c = Cipher.getInstance(cmp);
            c.init(Cipher.ENCRYPT_MODE, sk, IV);
            return c.doFinal(msg);
        } catch (Exception nsae) {
        }
        return null;
    }

    private byte[] decrypt(String cmp, SecretKey sk, IvParameterSpec IV,
                           byte[] ciphertext) {
        try {
            Cipher c = Cipher.getInstance(cmp);
            c.init(Cipher.DECRYPT_MODE, sk, IV);
            return c.doFinal(ciphertext);
        } catch (Exception nsae) {
        }
        return null;
    }
}