<?php

namespace mazter\Crypt;

/**
 * Pure-PHP implementation of AES.
 * Uses mcrypt, if available/possible, and an internal implementation, otherwise.
 * PHP version 5
 * NOTE: Since AES.php is (for compatibility and mazter-historical reasons) virtually
 * just a wrapper to Rijndael.php you may consider using Rijndael.php instead of
 * to save one include_once().
 * if setkey, setmethod, setiv, encrypt, decrypt
 *  * Here's a short example of how to use this library:
 * <code>
 * <?php
 *    include 'vendor/autoload.php';
 *
 *    $aes = new \mazter\Crypt\AES();
 *
 *    $aes->setKey('abcdefghijklmnop');
 *    $aes->setmethod('AES-256-CBC');
 *    $aes->setiv('abcdefghijklmnop'); //just 16 byte
 *    echo $aes->decrypt($aes->encrypt($plaintext));
 * ?>
 * </code>
 */

class AES
{

    private $_key;
    private $_keysize;
    private $_iv;
    private $_method;

    public function __construct()
    {
        $this->_key = openssl_random_pseudo_bytes(32);
        $this->_keysize = strlen($this->_key) * 8;
        $this->_method = 'AES-256-CBC';
        $this->_iv = openssl_random_pseudo_bytes(16);
    }

    public function setkey(string $key)
    {
        $this->_key = $key;
        $this->_keysize = strlen($key) * 8;
    }

    public function setmethod(string $method)
    {
        $this->_method = $method;
    }

    public function setiv(string $iv)
    {
        if (strlen($iv) < 16) {
            throw 'Key using not accept 16 bit';
        }

        $this->_iv = $iv;
    }

    public function encrypt(string $data)
    {
        return base64_encode(openssl_encrypt($data, $this->_method, $this->_key, OPENSSL_RAW_DATA, $this->_iv));
    }

    public function decrypt(string $data)
    {
        return openssl_decrypt(base64_decode($data), $this->_method, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
    }

    public function encryptString(string $data)
    {
        return base64_encode(openssl_encrypt($data, $this->_method, $this->_key, OPENSSL_RAW_DATA, $this->_iv));
    }

    public function encryptObject(object $data)
    {
        return base64_encode(openssl_encrypt(json_encode($data), $this->_method, $this->_key, OPENSSL_RAW_DATA, $this->_iv));
    }

    public function encryptArray(array $data)
    {
        return base64_encode(openssl_encrypt(json_encode($data), $this->_method, $this->_key, OPENSSL_RAW_DATA, $this->_iv));
    }
}
