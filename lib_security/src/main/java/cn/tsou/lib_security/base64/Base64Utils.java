package cn.tsou.lib_security.base64;

import android.util.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

public class Base64Utils {
    /**
     * 字符串进行Base64编码加密
     *
     * @param str
     * @return
     */
    public static String encodeString(String str) {
        return Base64.encodeToString(str.getBytes(), Base64.DEFAULT);
    }

    /**
     * 字符串进行Base64解码解密
     *
     * @param encodedString
     * @return
     */

    public static String decodeString(String encodedString) {
        return new String(Base64.decode(encodedString, Base64.DEFAULT));
    }

    /**
     * 对文件进行Base64编码加密
     *
     * @param path
     * @return
     */
    public static String encodeFile(String path) {
        File file = new File(path);
        FileInputStream inputFile = null;
        try {
            inputFile = new FileInputStream(file);
            byte[] buffer = new byte[(int) file.length()];
            inputFile.read(buffer);
            inputFile.close();
            return Base64.encodeToString(buffer, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    /**
     * 对文件进行Base64解码解密
     *
     * @param encodedPath
     * @return
     */

    public static void decodeFile(String encodedPath) {
        File desFile = new File(encodedPath);
        FileOutputStream fos = null;
        try {
            byte[] decodeBytes = Base64.decode(encodedPath.getBytes(), Base64.DEFAULT);
            fos = new FileOutputStream(desFile);
            fos.write(decodeBytes);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
