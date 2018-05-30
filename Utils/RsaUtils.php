<?php

/**
 * 
 * Create by
 * @author  Xuân Sơn <sonnx@applancer.net>
 * @version 1.0
 */


include_once ROOT_PATH . DS . 'Crypt/RSA.php';
/**
 * 
 */
class RsaUtils
{
    
    function __construct(){
        # code...
    }

    function msg(){
        return 'sonnx';
    }

    /**
     * encryptData - Mã hóa dữ liệu với thuật toán RSA kèm publickey
     * @param  string $data      Dữ liệu cần mã hóa
     * @param  string $publicKey Là key dùng để mã hóa dữ liệu truyền đi - Là key đã được cung cấp
     * @return string            Dữ liệu đã được mã hóa
     */
    function encryptData($data, $publicKey) {
        $rsa = new Crypt_RSA();
        $rsa->loadKey($publicKey); // public key
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        $output = $rsa->encrypt($data);
        return base64_encode($output);
    }

    /**
     * decryptData  - Dịch ngược dữ liệu đã được mã hóa với thuật toán RSA kèm publickey
     * @param  string $data      Dữ liệu cần dịch ngược
     * @param  string $publicKey Là key đã được cung cấp
     * @return json              Dữ liệu đã được dịch ngược
     */
    function decryptData($data, $publicKey) {
        $rsa = new Crypt_RSA();
        $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
        $ciphertext = base64_decode($data);
        $rsa->loadKey($publicKey); // public key
        $output = $rsa->decrypt($ciphertext);
        return $output;
    }

    /**
     * [checkSumData - Đối soát dữ liệu]
     * @param  [json] $params['data']        - 
     * @param  [string] $params['checksum']  - 
     * @param  [string] $key_checksum        - 
     * @return [true|fasle]
     */
    function checkSumData($params, $key_checksum = ''){
        
        $return = false;
        if (!empty($params) && 
            is_array($params) && 
            md5(sha1($params['data']) . $key_checksum) == $params['checksum']) {
            
            $return = true;
        }
        return $return;
    }

    /**
     * [genRSAKey - Create file key ssh]
     * @return [aray] [publicKey && privKey]
     */
    function genRSAKey(){

        $rsa = new Crypt_RSA();
        return $rsa->createKey();
    }

}
