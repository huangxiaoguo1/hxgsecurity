package cn.tsou.lib_security.rsa;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.text.TextUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by Administrator on 2018/6/5 0005.
 */

public class RSAinit {

    private static RSAPublicKey publicKey;

    /**
     *
     * @param context
     * @param pcksPadding 加密填充方式
     * @param split  当要加密的内容超过bufferSize，则采用partSplit进行分块加密
     * @param keySize  秘钥默认长度
     * @param alias 自己给你的别名，方便在keystore中查找秘钥
     * @return
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    public static RSAPublicKey initRSA(Context context,String pcksPadding,String split,int keySize,String alias) {
        if (AndroidKeyStoreRSAUtils.isHaveKeyStore()) {//是否有秘钥
            publicKey = (RSAPublicKey) AndroidKeyStoreRSAUtils.getLocalPublicKey();
        } else {
            try {//在项目中放在application或启动页中
                if (!TextUtils.isEmpty(pcksPadding)){
                    AndroidKeyStoreRSAUtils.setEcbPcksPadding(pcksPadding);
                }
                if (!TextUtils.isEmpty(split)){
                    AndroidKeyStoreRSAUtils.setSplit(split);
                }
                if (keySize>0){
                    AndroidKeyStoreRSAUtils.setKeySize(keySize);
                }
                if (!TextUtils.isEmpty(alias)){
                    AndroidKeyStoreRSAUtils.setOwnAlias(alias);
                }
                KeyPair keyPair = AndroidKeyStoreRSAUtils.generateRSAKeyPair(context.getApplicationContext());
                // 公钥
                publicKey = (RSAPublicKey) keyPair.getPublic();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return publicKey;
    }


}
