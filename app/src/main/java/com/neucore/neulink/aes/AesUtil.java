package com.neucore.neulink.aes;

public class AesUtil {
    static {
        System.loadLibrary("AesUtil");
    }

    static public native String encrypt$decrypt(String plainData);

    /**
     * 加密
     * @param plainData 明文
     * @return
     */
    static public native String encrypt(String plainData);

    /**
     * 解密
     * @param encData 密文
     * @return
     */
    static public native String decrypt(String encData);

    static public native String encBase64(String data);

    static public native String decBase64(String data);

    static public native String trans(String data);
}
