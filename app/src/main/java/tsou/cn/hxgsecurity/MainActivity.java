package tsou.cn.hxgsecurity;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import cn.tsou.lib_security.aes.AESUtils;
import cn.tsou.lib_security.aes.Base64Decoder;
import cn.tsou.lib_security.aes.Base64Encoder;
import cn.tsou.lib_security.base64.Base64Utils;
import cn.tsou.lib_security.md5.MD5Utils;
import cn.tsou.lib_security.rsa.AndroidKeyStoreRSAUtils;
import cn.tsou.lib_security.rsa.RSAinit;
import cn.tsou.lib_security.sp.SPSecuredUtils;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    /**
     * 黄晓果
     */
    private EditText mEtMd5;
    /**
     * MD5加密
     */
    private Button mOnMD5Click;
    /**
     * MD5加密内容
     */
    private TextView mTvMd5;
    /**
     * 黄晓果
     */
    private EditText mEtBase64;
    /**
     * Base64加密
     */
    private Button mOnBase64EncryptClick;
    /**
     * Bsar64加密内容
     */
    private TextView mTvBase64Encrypt;
    /**
     * Base64解密
     */
    private Button mOnBase64DecodeClick;
    /**
     * Bsar64解密内容
     */
    private TextView mTvBase64Decode;
    /**
     * 黄晓果
     */
    private EditText mEtAes;
    /**
     * AES加密
     */
    private Button mOnAesEncryptClick;
    /**
     * AES加密内容
     */
    private TextView mTvAesEncrypt;
    /**
     * AES解密
     */
    private Button mOnAesDecodeClick;
    /**
     * AES解密内容
     */
    private TextView mTvAesDecode;
    /**
     * 黄晓果
     */
    private EditText mEtRsa;
    /**
     * RSA公钥加密
     */
    private Button mOnRsaEncryptClick;
    /**
     * RSA公钥加密内容
     */
    private TextView mTvRsaEncrypt;
    /**
     * RSA私钥解密
     */
    private Button mOnRsaDecodeClick;
    /**
     * RSA私钥解密内容
     */
    private TextView mTvRsaDecode;
    /**
     * 黄晓果
     */
    private EditText mEtRsaSign;
    /**
     * RSA签名
     */
    private Button mOnRsaSignClick;
    /**
     * RSA签名内容
     */
    private TextView mTvRsaSign;
    /**
     * RSA校验签名
     */
    private Button mOnRsaVerifyClick;
    /**
     * RSA校验签名内容
     */
    private TextView mTvRsaVerify;
    /**
     * 黄晓果
     */
    private EditText mEtRsaSp;
    /**
     * SP存入
     */
    private Button mOnRsaSPSaveClick;
    /**
     * SP读取
     */
    private Button mOnRsaSPGetClick;
    /**
     * RSA_SP内容
     */
    private TextView mTvRsaSp;
    private RSAPublicKey publicKey;
    private String mSignatureStr;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        publicKey = RSAinit.initRSA(this, null, null, 0, null);
        initView();
    }

    private void initView() {
        mEtMd5 = (EditText) findViewById(R.id.et_md5);
        mOnMD5Click = (Button) findViewById(R.id.onMD5Click);
        mOnMD5Click.setOnClickListener(this);
        mTvMd5 = (TextView) findViewById(R.id.tv_md5);
        mEtBase64 = (EditText) findViewById(R.id.et_base64);
        mOnBase64EncryptClick = (Button) findViewById(R.id.onBase64EncryptClick);
        mOnBase64EncryptClick.setOnClickListener(this);
        mTvBase64Encrypt = (TextView) findViewById(R.id.tv_base64_encrypt);
        mOnBase64DecodeClick = (Button) findViewById(R.id.onBase64DecodeClick);
        mOnBase64DecodeClick.setOnClickListener(this);
        mTvBase64Decode = (TextView) findViewById(R.id.tv_base64_decode);
        mEtAes = (EditText) findViewById(R.id.et_aes);
        mOnAesEncryptClick = (Button) findViewById(R.id.onAesEncryptClick);
        mOnAesEncryptClick.setOnClickListener(this);
        mTvAesEncrypt = (TextView) findViewById(R.id.tv_aes_encrypt);
        mOnAesDecodeClick = (Button) findViewById(R.id.onAesDecodeClick);
        mOnAesDecodeClick.setOnClickListener(this);
        mTvAesDecode = (TextView) findViewById(R.id.tv_aes_decode);
        mEtRsa = (EditText) findViewById(R.id.et_rsa);
        mOnRsaEncryptClick = (Button) findViewById(R.id.onRsaEncryptClick);
        mOnRsaEncryptClick.setOnClickListener(this);
        mTvRsaEncrypt = (TextView) findViewById(R.id.tv_rsa_encrypt);
        mOnRsaDecodeClick = (Button) findViewById(R.id.onRsaDecodeClick);
        mOnRsaDecodeClick.setOnClickListener(this);
        mTvRsaDecode = (TextView) findViewById(R.id.tv_rsa_decode);
        mEtRsaSign = (EditText) findViewById(R.id.et_rsa_sign);
        mOnRsaSignClick = (Button) findViewById(R.id.onRsaSignClick);
        mOnRsaSignClick.setOnClickListener(this);
        mTvRsaSign = (TextView) findViewById(R.id.tv_rsa_sign);
        mOnRsaVerifyClick = (Button) findViewById(R.id.onRsaVerifyClick);
        mOnRsaVerifyClick.setOnClickListener(this);
        mTvRsaVerify = (TextView) findViewById(R.id.tv_rsa_verify);
        mEtRsaSp = (EditText) findViewById(R.id.et_rsa_sp);
        mOnRsaSPSaveClick = (Button) findViewById(R.id.onRsaSPSaveClick);
        mOnRsaSPSaveClick.setOnClickListener(this);
        mOnRsaSPGetClick = (Button) findViewById(R.id.onRsaSPGetClick);
        mOnRsaSPGetClick.setOnClickListener(this);
        mTvRsaSp = (TextView) findViewById(R.id.tv_rsa_sp);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            default:
                break;
            /**
             * MD5
             */
            case R.id.onMD5Click://MD5加密
                String md5String = mEtMd5.getText().toString().trim();
                if (TextUtils.isEmpty(md5String)) {
                    Toast.makeText(this, "请输入加密内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                String encodeMD5 = MD5Utils.md5(md5String);
                mTvMd5.setText(encodeMD5);
                break;
            /**
             * Base64
             */
            case R.id.onBase64EncryptClick://Base64加密
                String encryptionBase64String = mEtBase64.getText().toString().trim();
                if (TextUtils.isEmpty(encryptionBase64String)) {
                    Toast.makeText(this, "请输入加密内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                String encodeBase64 = Base64Utils.encodeString(encryptionBase64String);
                mTvBase64Encrypt.setText(encodeBase64);
                break;
            case R.id.onBase64DecodeClick://Base64解密
                String decodeBase64String = mTvBase64Encrypt.getText().toString().trim();
                if (TextUtils.isEmpty(decodeBase64String)) {
                    Toast.makeText(this, "请先加密", Toast.LENGTH_SHORT).show();
                    return;
                }
                String decodeBase64 = Base64Utils.decodeString(decodeBase64String);
                mTvBase64Decode.setText(decodeBase64);
                break;
            /**
             * AES
             */
            case R.id.onAesEncryptClick://AES加密
//                AESUtils.setJavaIvParameter("huangxiaoguo1234");
//                AESUtils.setJavaKey("5682huangxiaoguo");
                String encryptionAesString = mEtAes.getText().toString().trim();
                if (TextUtils.isEmpty(encryptionAesString)) {
                    Toast.makeText(this, "请输入加密内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                String encryptAes = AESUtils.getInstance().encrypt(encryptionAesString);
                mTvAesEncrypt.setText(encryptAes);

                break;
            case R.id.onAesDecodeClick://AES解密
                String decodeAesString = mTvAesEncrypt.getText().toString().trim();
                if (TextUtils.isEmpty(decodeAesString)) {
                    Toast.makeText(this, "请先加密", Toast.LENGTH_SHORT).show();
                    return;
                }
                String decryptAes = AESUtils.getInstance().decrypt(decodeAesString);
                mTvAesDecode.setText(decryptAes);
                break;
            /**
             * RSA加密解密
             *
             * 使用之前请先初始化RSAinit
             */
            case R.id.onRsaEncryptClick://RSA公钥加密
                //获取客户端公钥的base64编码的String,登录时将公钥传递给后台
                //String localPublicKey = EncodeUtils.base64Encode2String(publicKey.getEncoded());

                String encryptionRSAString = mEtRsa.getText().toString().trim();

                if (TextUtils.isEmpty(encryptionRSAString)) {
                    Toast.makeText(this, "请输入加密内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                try {
                    byte[] encryptBytes = AndroidKeyStoreRSAUtils.encryptByPublicKey(encryptionRSAString.getBytes(),
                            publicKey.getEncoded());
                    String encryStr = Base64Encoder.encode(encryptBytes);
                    mTvRsaEncrypt.setText(encryStr);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case R.id.onRsaDecodeClick://RSA私钥解密
                String decodeRSAString = mTvRsaEncrypt.getText().toString().trim();
                if (TextUtils.isEmpty(decodeRSAString)) {
                    Toast.makeText(this, "请先加密", Toast.LENGTH_SHORT).show();
                    return;
                }
                try {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(decodeRSAString));
                    mTvRsaDecode.setText(new String(decryptBytes));
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            /**
             * RSA签名
             * 使用之前请先初始化RSAinit
             */
            case R.id.onRsaSignClick:
                String encryptionString = mEtRsaSign.getText().toString().trim();
                try {
                    mSignatureStr = AndroidKeyStoreRSAUtils.signData(encryptionString);
                    mTvRsaSign.setText(mSignatureStr);
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "密钥存储库没有初始化,可能没有生成秘钥对", Toast.LENGTH_SHORT).show();
                } catch (CertificateException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "加载证书时发生错误", Toast.LENGTH_SHORT).show();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "不支持RSA", Toast.LENGTH_SHORT).show();
                } catch (IOException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "IO Exception", Toast.LENGTH_SHORT).show();
                } catch (UnrecoverableEntryException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "密钥对没有恢复", Toast.LENGTH_SHORT).show();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "无效的key", Toast.LENGTH_SHORT).show();
                } catch (SignatureException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "无效的签名", Toast.LENGTH_SHORT).show();
                }
                break;
            /**
             * RSA校验签名
             * 使用之前请先初始化RSAinit
             */
            case R.id.onRsaVerifyClick:
                String encryptionverifyString = mEtRsaSign.getText().toString().trim();
                if (TextUtils.isEmpty(encryptionverifyString)) {
                    Toast.makeText(this, "请输入验证内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                if (TextUtils.isEmpty(mSignatureStr)) {
                    Toast.makeText(this, "请先签名", Toast.LENGTH_SHORT).show();
                    return;
                }
                try {
                    boolean b = AndroidKeyStoreRSAUtils.verifyData(encryptionverifyString, mSignatureStr);
                    if (b) {
                        mTvRsaVerify.setText("签名一致");
                    } else {
                        mTvRsaVerify.setText("签名不一致");
                    }
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "密钥存储库没有初始化,可能没有生成秘钥对", Toast.LENGTH_SHORT).show();
                } catch (CertificateException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "加载证书时发生错误", Toast.LENGTH_SHORT).show();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "不支持RSA", Toast.LENGTH_SHORT).show();
                } catch (IOException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "IO Exception", Toast.LENGTH_SHORT).show();
                } catch (UnrecoverableEntryException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "密钥对没有恢复", Toast.LENGTH_SHORT).show();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "无效的key", Toast.LENGTH_SHORT).show();
                } catch (SignatureException e) {
                    e.printStackTrace();
                    Toast.makeText(this, "无效的签名", Toast.LENGTH_SHORT).show();
                }
                break;
            /**
             * SP存入
             * 使用之前请先初始化RSAinit
             */
            case R.id.onRsaSPSaveClick:
                String encryptionSpString = mEtRsaSp.getText().toString().trim();
                if (TextUtils.isEmpty(encryptionSpString)) {
                    Toast.makeText(this, "请输入加密内容", Toast.LENGTH_SHORT).show();
                    return;
                }
                SPSecuredUtils.put(this, "huangxiaoguo", encryptionSpString, publicKey);
                SPSecuredUtils.put(this, "huangxiaoguo1", 1, publicKey);
                SPSecuredUtils.put(this, "huangxiaoguo2", 0.01, publicKey);
                SPSecuredUtils.put(this, "huangxiaoguo3", true, publicKey);
                break;
            /**
             * SP读取
             * 使用之前请先初始化RSAinit
             */
            case R.id.onRsaSPGetClick:
                String huangxiaoguo = (String) SPSecuredUtils.get(this, "huangxiaoguo", "");
                int huangxiaoguo1 = (int) SPSecuredUtils.get(this, "huangxiaoguo1", 0);
                double huangxiaoguo2 = (double) SPSecuredUtils.get(this, "huangxiaoguo2", 0.0);
                boolean huangxiaoguo3 = (boolean) SPSecuredUtils.get(this, "huangxiaoguo3", false);
                mTvRsaSp.setText(huangxiaoguo + "---" + huangxiaoguo1 + "---" + huangxiaoguo2 + "---" + huangxiaoguo3);
                break;
        }
    }
}
