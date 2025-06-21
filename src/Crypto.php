<?php

namespace Biboletin\Crypto;

use Biboletin\Enum\CryptoVersion;
use Biboletin\Exceptions\Custom\Crypto\EncryptException;
use Biboletin\Enum\CipherAlgorithm;
use InvalidArgumentException;
use Random\RandomException;

/**
 * Class Crypto
 *
 * Provides methods for encrypting and decrypting data using a specified cipher algorithm.
 * Supports AES-256-GCM encryption with a random initialization vector (IV) and authentication tag.
 */
class Crypto
{
    /**
     * The encryption key derived from the provided key and salt.
     *
     * @var string
     */
    private string $key;

    /**
     * The cipher algorithm used for encryption and decryption.
     *
     * @var CipherAlgorithm
     */
    private CipherAlgorithm $cipherAlgorithm;

    /**
     * The length of the initialization vector (IV) in bytes.
     *
     * @var int
     */
    private int $ivLength;

    /**
     * The initialization vector (IV) used for encryption.
     *
     * @var string
     */
    private string $iv;

    /**
     * The salt used for key derivation.
     *
     * @var string
     */
    private const SALT = '_biboletin';

    /**
     * The length of the authentication tag for GCM mode.
     * This is set to 16 bytes, which is standard for AES-256-GCM.
     *
     * @var int
     */
    private const TAG_LENGTH = 16;

    /**
     * Crypto constructor.
     *
     * Initializes the Crypto instance with a key, optional salt, cipher algorithm, and IV length.
     *
     * @param string          $key             The encryption key.
     * @param string|null     $salt            Optional salt for key derivation. Defaults to a predefined salt.
     * @param CipherAlgorithm $cipherAlgorithm The cipher algorithm to use for encryption and decryption.
     * @param int             $ivLength        The length of the initialization vector (IV) in bytes. Defaults to 16.
     *
     * @throws InvalidArgumentException|RandomException If the provided cipher algorithm is not supported.
     */
    public function __construct(
        string $key,
        ?string $salt = null,
        CipherAlgorithm $cipherAlgorithm = CipherAlgorithm::AES_256_GCM,
        int $ivLength = 16
    ) {
        $salt = $salt ?? self::SALT;
        $this->key = $key;
        $this->cipherAlgorithm = $cipherAlgorithm;
        $this->ivLength = $ivLength;
        $this->iv = random_bytes($this->ivLength);

        if (!in_array($this->cipherAlgorithm->value, openssl_get_cipher_methods(true))) {
            throw new InvalidArgumentException(
                'Invalid cipher algorithm provided: ' . $this->cipherAlgorithm->value
            );
        }

        $this->key = hash_pbkdf2('sha256', $this->key, $salt, $this->ivLength, true);
        $this->ivLength = openssl_cipher_iv_length($this->cipherAlgorithm->value);
    }

    /**
     * Encrypts the provided text using the specified cipher algorithm and returns the encrypted data.
     *
     * @param string $text The text to encrypt.
     *
     * @return string The encrypted text, base64-encoded with version information.
     * @throws EncryptException|RandomException If encryption fails.
     */
    public function encrypt(string $text): string
    {
        $iv = random_bytes($this->ivLength);
        $tag = '';

        $encryptedText = openssl_encrypt(
            $text,
            $this->cipherAlgorithm->value,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($encryptedText === false) {
            throw new EncryptException('Encryption failed: ' . openssl_error_string());
        }

        $payload = base64_encode($iv . $tag . $encryptedText);

        return CryptoVersion::V1->value . ':' . $payload;
    }

    /**
     * Decrypts the provided encrypted text and returns the original plaintext.
     *
     * @param string $text The encrypted text to decrypt.
     *
     * @return string|null The decrypted text, or null if decryption fails or the format is invalid.
     */
    public function decrypt(string $text): ?string
    {
        [$version, $payload] = explode(':', $text, 2) + [null, null];

        if ($version !== CryptoVersion::V1->value || $payload === null) {
            return null;
        }

        $data = base64_decode($payload, true);

        if ($data === false || strlen($data) < $this->ivLength + self::TAG_LENGTH) {
            return null;
        }

        $iv = substr($data, 0, $this->ivLength);
        $tag = substr($data, $this->ivLength, self::TAG_LENGTH);
        $encryptedText = substr($data, $this->ivLength + self::TAG_LENGTH);
        $decryptedText = openssl_decrypt(
            $encryptedText,
            $this->cipherAlgorithm->value,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $decryptedText !== false ? $decryptedText : null;
    }
}
