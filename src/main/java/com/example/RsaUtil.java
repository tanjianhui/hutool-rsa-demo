package com.example;

import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.RSA;
import cn.hutool.crypto.asymmetric.Sign;

import java.util.Base64;

public final class RsaUtil {
    private final static String SIGNATURE_ALGORITHM = "MD5withRSA";

    /**
     * <p>
     * 生成密钥对(公钥和私钥)
     * </p>
     *
     * @return KeyPair
     */
    public static RsaKeyPair genKeyPair() {
        RSA rsa = new RSA();
        return new RsaKeyPair(rsa.getPrivateKeyBase64(), rsa.getPublicKeyBase64());
    }

    /**
     * <p>Base64编码</p>
     *
     * @param binaryData 二进制数据
     * @return Base64编码字符串
     */
    public static String encodeBase64(byte[] binaryData) {
        return Base64.getEncoder().encodeToString(binaryData);
    }

    /**
     * <p>Base64解码</p>
     *
     * @param encoded Base64编码字符串
     * @return 二进制数据
     */
    public static byte[] decodeBase64(String encoded) {
        return Base64.getDecoder().decode(encoded);
    }

    /**
     * 使用私钥对数据进行加密
     */
    public static byte[] encryptByPrivateKey(byte[] binaryData, String privateKey) {
        return new RSA(privateKey, null).encrypt(binaryData, KeyType.PrivateKey);
    }

    /**
     * 使用公钥对数据进行加密
     */
    public static byte[] encryptByPublicKey(byte[] binaryData, String publicKey) {
        return new RSA(null, publicKey).encrypt(binaryData, KeyType.PublicKey);
    }

    /**
     * 使用私钥对数据进行解密
     */
    public static byte[] decryptByPrivateKey(byte[] binaryData, String privateKey) {
        return new RSA(privateKey, null).decrypt(binaryData, KeyType.PrivateKey);
    }

    /**
     * 使用公钥对数据进行解密
     */
    public static byte[] decryptByPublicKey(byte[] binaryData, String publicKey) {
        return new RSA(null, publicKey).decrypt(binaryData, KeyType.PublicKey);
    }

    /**
     * 使用私钥对数据进行签名
     */
    public static String signByPrivateKey(byte[] binaryData, String privateKey) {
        return encodeBase64(new Sign(SIGNATURE_ALGORITHM, privateKey, null).sign(binaryData));
    }

    /**
     * 使用公钥对数据签名进行验证
     */
    public static boolean verifyByPublicKey(byte[] binaryData, String publicKey, String sign) {
        return new Sign(SIGNATURE_ALGORITHM, null, publicKey).verify(binaryData, decodeBase64(sign));
    }

    public static void main(String[] args) {
        RsaKeyPair keyPair = RsaUtil.genKeyPair();
        String privateKey = keyPair.getPrivateKey();
        String publicKey = keyPair.getPublicKey();

        String content = "未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据未加密数据";

        System.out.println("1、私钥加密与公钥解密");
        byte[] encodeContent = encryptByPrivateKey(content.getBytes(), privateKey);
        System.out.println("私钥加密后的数据：" + encodeBase64(encodeContent));
        byte[] decodeContent = decryptByPublicKey(encodeContent, publicKey);
        System.out.println("公钥解密后的数据：" + new String(decodeContent));

        System.out.println("2、公钥加密与私钥解密");
        byte[] encodeContent2 = encryptByPublicKey(content.getBytes(), publicKey);
        System.out.println("公钥加密后的数据：" + encodeBase64(encodeContent2));
        byte[] decodeContent2 = decryptByPrivateKey(encodeContent2, privateKey);
        System.out.println("私钥解密后的数据：" + new String(decodeContent2));

        System.out.println("3、私钥签名与公钥验签");
        String signString = signByPrivateKey(content.getBytes(), privateKey);
        System.out.println("私钥加签后的数据：" + signString);
        boolean result = verifyByPublicKey(content.getBytes(), publicKey, signString);
        System.out.println("公钥验签结果：" + result);
    }

    /**
     * <p>公私钥对存储对象</p>
     */
    public final static class RsaKeyPair {
        private final String privateKey;
        private final String publicKey;

        public RsaKeyPair(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }
    }
}
