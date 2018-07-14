package cn.tsou.lib_security.sp;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import cn.tsou.lib_security.aes.Base64Decoder;
import cn.tsou.lib_security.aes.Base64Encoder;
import cn.tsou.lib_security.rsa.AndroidKeyStoreRSAUtils;

/**
 * Created by huangxiaoguo on 2017/2/9.
 */

public class SPSecuredUtils {
    /**
     * 保存在手机里面的文件名
     */
    public static final String FILE_NAME = "sp_secured";
    private static SharedPreferences mSharedPreferences;

    /**
     * 保存数据的方法，我们需要拿到保存数据的具体类型，然后根据类型调用不同的保存方法
     *
     * @param context
     * @param key
     * @param object
     * @param publicKey
     */
    public static void put(Context context, String key, Object object, RSAPublicKey publicKey) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
//        byte[] encryptBytes = AndroidKeyStoreRSAUtils.encryptByPublicKeyForSpilt(encryptionString.getBytes(),
//                publicKey.getEncoded());
        try {
            if (object instanceof String) {
                byte[] encryptBytes = AndroidKeyStoreRSAUtils.encryptByPublicKey(((String) object).getBytes(),
                        publicKey.getEncoded());
                editor.putString(key, Base64Encoder.encode(encryptBytes));
            } else if (object instanceof Integer) {
                put(context, key, Integer.toString((Integer) object), publicKey);
            } else if (object instanceof Boolean) {
                put(context, key, Boolean.toString((Boolean) object), publicKey);
            } else if (object instanceof Float) {
                put(context, key, Float.toString((Float) object), publicKey);
            } else if (object instanceof Long) {
                put(context, key, Long.toString((Long) object), publicKey);
            } else {
                put(context, key, object.toString(), publicKey);
            }

            SharedPreferencesCompat.apply(editor);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 得到保存数据的方法，我们根据默认值得到保存的数据的具体类型，然后调用相对于的方法获取值
     *
     * @param context
     * @param key
     * @param defaultObject
     * @return
     */
    public static Object get(Context context, String key, Object defaultObject) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
//        byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKeyForSpilt(
//                Base64Decoder.decodeToBytes(decodeString));
        try {
            if (defaultObject instanceof String) {
                String string = sp.getString(key, (String) defaultObject);
                if (!string.equals((String) defaultObject)) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return new String(decryptBytes);
                }
                return (String) defaultObject;
            } else if (defaultObject instanceof Integer) {
                String string = sp.getString(key, Integer.toString((Integer) defaultObject));
                if (!string.equals(Integer.toString((Integer) defaultObject))) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return Integer.valueOf(new String(decryptBytes));
                }
                return (Integer) defaultObject;
            } else if (defaultObject instanceof Boolean) {
                String string = sp.getString(key, Boolean.toString((Boolean) defaultObject));
                if (!string.equals(Boolean.toString((Boolean) defaultObject))) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return Boolean.valueOf(new String(decryptBytes));
                }
                return (Boolean) defaultObject;
            } else if (defaultObject instanceof Float) {
                String string = sp.getString(key, Float.toString((Float) defaultObject));
                if (!string.equals(Float.toString((Float) defaultObject))) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return Float.valueOf(new String(decryptBytes));
                }
                return (Float) defaultObject;
            } else if (defaultObject instanceof Long) {
                String string = sp.getString(key, Long.toString((Long) defaultObject));
                if (!string.equals(Long.toString((Long) defaultObject))) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return Long.valueOf(new String(decryptBytes));
                }
                return (Long) defaultObject;
            }else if (defaultObject instanceof Double){
                String string = sp.getString(key, Double.toString((Double) defaultObject));
                if (!string.equals(Double.toString((Double) defaultObject))) {
                    byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                            Base64Decoder.decodeToBytes(string));
                    return Double.valueOf(new String(decryptBytes));
                }
                return (Double) defaultObject;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    /**
     * 将对象储存到sharepreference
     *
     * @param key
     * @param device
     * @param <T>
     */
    public static <T> boolean saveDeviceData(Context context, String key, T device, RSAPublicKey publicKey) {
        if (mSharedPreferences == null) {
            mSharedPreferences = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {   //Device为自定义类
            // 创建对象输出流，并封装字节流
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            // 将对象写入字节流
            oos.writeObject(device);
            // 将字节流编码成base64的字符串
            String oAuth_Base64 = new String(Base64.encode
                    (baos.toByteArray(), Base64.DEFAULT));
            byte[] encryptBytes = AndroidKeyStoreRSAUtils.encryptByPublicKey(oAuth_Base64.getBytes(),
                    publicKey.getEncoded());
            mSharedPreferences.edit().putString(key, Base64Encoder.encode(encryptBytes)).apply();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * 将对象从shareprerence中取出来
     *
     * @param key
     * @param <T>
     * @return
     */
    public static <T> T getDeviceData(Context context, String key) {
        if (mSharedPreferences == null) {
            mSharedPreferences = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE);
        }
        try {
            T device = null;
            String productBase64 = mSharedPreferences.getString(key, null);
            if (productBase64 == null) {
                return null;
            }
            byte[] decryptBytes = AndroidKeyStoreRSAUtils.decryptByPrivateKey(
                    Base64Decoder.decodeToBytes(productBase64));
            // 读取字节
            byte[] base64 = Base64.decode(new String(decryptBytes).getBytes(), Base64.DEFAULT);
            // 封装到字节流
            ByteArrayInputStream bais = new ByteArrayInputStream(base64);
            // 再次封装
            ObjectInputStream bis = new ObjectInputStream(bais);
            // 读取对象
            device = (T) bis.readObject();
            return device;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 移除某个key值已经对应的值
     *
     * @param context
     * @param key
     */
    public static void remove(Context context, String key) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.remove(key);
        SharedPreferencesCompat.apply(editor);
    }

    /**
     * 清除所有数据
     *
     * @param context
     */
    public static void clear(Context context) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sp.edit();
        editor.clear();
        SharedPreferencesCompat.apply(editor);
    }

    /**
     * 查询某个key是否已经存在
     *
     * @param context
     * @param key
     * @return
     */
    public static boolean contains(Context context, String key) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
        return sp.contains(key);
    }

    /**
     * 返回所有的键值对
     *
     * @param context
     * @return
     */
    public static Map<String, ?> getAll(Context context) {
        SharedPreferences sp = context.getSharedPreferences(FILE_NAME,
                Context.MODE_PRIVATE);
        return sp.getAll();
    }

    /**
     * 创建一个解决SharedPreferencesCompat.apply方法的一个兼容类
     *
     * @author zhy
     */
    private static class SharedPreferencesCompat {
        private static final Method sApplyMethod = findApplyMethod();

        /**
         * 反射查找apply的方法
         *
         * @return
         */
        @SuppressWarnings({"unchecked", "rawtypes"})
        private static Method findApplyMethod() {
            try {
                Class clz = SharedPreferences.Editor.class;
                return clz.getMethod("apply");
            } catch (NoSuchMethodException e) {
            }

            return null;
        }

        /**
         * 如果找到则使用apply执行，否则使用commit
         *
         * @param editor
         */
        public static void apply(SharedPreferences.Editor editor) {
            try {
                if (sApplyMethod != null) {
                    sApplyMethod.invoke(editor);
                    return;
                }
            } catch (IllegalArgumentException e) {
            } catch (IllegalAccessException e) {
            } catch (InvocationTargetException e) {
            }
            editor.commit();
        }
    }

}