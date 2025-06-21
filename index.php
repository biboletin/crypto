<?php
/**
 * Example script demonstrating the usage of the Session class.
 * 
 * This script shows how to create, configure, use, and destroy a session.
 */


// Include Composer autoloader
use Biboletin\Crypto\Crypto;
use Biboletin\Enum\CipherAlgorithm;
use Biboletin\Exceptions\Custom\Crypto\EncryptException;
use Random\RandomException;

include __DIR__ . '/vendor/autoload.php';

try {
    $crypto = new Crypto('password', CipherAlgorithm::AES_256_GCM, 16, true);
    $encryptedText = $crypto->encrypt('Hello, World!');
    $decryptedText = $crypto->decrypt($encryptedText);

    $crypto2 = new Crypto('password2', CipherAlgorithm::AES_256_GCM, 16, false);
    $encryptedText2 = $crypto2->encrypt('Hello, World!');
    $decryptedText2 = $crypto2->decrypt($encryptedText2);

    dd(
        $encryptedText, 
        $decryptedText,
        $encryptedText2,
        $decryptedText2
    );
} catch (EncryptException | RandomException $e) {
    dd($e->getMessage());
}
