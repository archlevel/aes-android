package com.neucore.neulink.aes;

public class AesUtil {
    static {
        System.loadLibrary("AesUtil");
    }
    static public native String stringFromJNI();

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
}
