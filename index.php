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
    $crypto = new Crypto('password', 'salt', CipherAlgorithm::AES_256_GCM, 16);
    $encryptedText = $crypto->encrypt('Hello, World!');
    $decryptedText = $crypto->decrypt($encryptedText);

    dd($encryptedText, $decryptedText);
} catch (EncryptException | RandomException $e) {
    dd($e->getMessage());
}
