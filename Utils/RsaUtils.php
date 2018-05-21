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
     * @return [file] [publicKey && privKey]
     */
    function genRSAKey(){

        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => 4096,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
            
        // Create the private and public key
        $res = openssl_pkey_new($config);

        // Extract the private key from $res to $privKey
        openssl_pkey_export($res, $privKey);

        // Extract the public key from $res to $pubKey
        $pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey["key"];

        $path_key = ROOT_PATH . DS . 'Utils/key';

        if (!file_exists($path_key)) {
            mkdir($path_key, 0777, true);
        }
        $PathFilenamePubKey = $path_key . DS . 'rsaPubKey.pub';
        $PathFilenamePrivKey= $path_key . DS . 'rsaPrivKey';

        if (file_put_contents($PathFilenamePubKey, $pubKey) !== false && file_put_contents($PathFilenamePrivKey, $privKey) !== false) {
            echo "File created (" . basename($PathFilenamePubKey) . ")";
            echo "File created (" . basename($PathFilenamePrivKey) . ")";
        } else {
            echo "Cannot create file (" . basename($PathFilenamePubKey) . ")";
            echo "Cannot create file (" . basename($PathFilenamePrivKey) . ")";
        }
    }

}