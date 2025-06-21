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
     * The salt used for key derivation.
     *
     * @var int
     */
    private const int SALT_LENGTH = 16;

    /**
     * The length of the HMAC key used for integrity verification.
     * This is set to 32 bytes, which is standard for SHA-256 HMAC.
     *
     * @var int
     */
    private const int HMAC_LENGTH = 32;

    /**
     * The length of the authentication tag for GCM mode.
     * This is set to 16 bytes, which is standard for AES-256-GCM.
     *
     * @var int
     */
    private const int TAG_LENGTH = 16;

    private bool $useHmac;

    /**
     * Crypto constructor.
     *
     * Initializes the Crypto instance with a key, optional salt, cipher algorithm, and IV length.
     *
     * @param string          $key             The encryption key.
     * @param CipherAlgorithm $cipherAlgorithm The cipher algorithm to use for encryption and decryption.
     * @param int             $ivLength        The length of the initialization vector (IV) in bytes. Defaults to 16.
     */
    public function __construct(
        string $key,
        CipherAlgorithm $cipherAlgorithm = CipherAlgorithm::AES_256_GCM,
        int $ivLength = 16,
        bool $useHmac = true
    ) {
        $this->key = $key;
        $this->cipherAlgorithm = $cipherAlgorithm;
        $this->ivLength = $ivLength;

        if (!in_array($this->cipherAlgorithm->value, openssl_get_cipher_methods(true))) {
            throw new InvalidArgumentException(
                'Invalid cipher algorithm provided: ' . $this->cipherAlgorithm->value
            );
        }

        $this->ivLength = openssl_cipher_iv_length($this->cipherAlgorithm->value);
        $this->useHmac = $useHmac;
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
        // Salt for PBKDF2
        $salt = random_bytes(self::SALT_LENGTH);
        // IV for encryption
        $iv = random_bytes($this->ivLength);
        $tag = '';

        $key = hash_pbkdf2('sha256', $this->key, $salt, 100_000, 32, true);
        $encryptedText = openssl_encrypt(
            $text,
            $this->cipherAlgorithm->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LENGTH
        );

        if ($encryptedText === false) {
            throw new EncryptException('Encryption failed: ' . openssl_error_string());
        }

        // Format: salt|iv|tag|ciphertext
        $payload = $salt . $iv . $tag . $encryptedText;

        if ($this->useHmac) {
            // Ensure the HMAC is calculated over the entire formatted string
            $hmacKey = hash_pbkdf2(
                'sha256',
                $this->key,
                $salt . 'hmac',
                100_000,
                self::HMAC_LENGTH,
                true
            );

            // HMAC added for integrity
            $hmac = hash_hmac('sha256', $payload, $hmacKey, true);
            $payload .= $hmac;
        }

        return CryptoVersion::V1->value . ':' . base64_encode($payload);
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
        if ($data === false) {
            return null;
        }

        $minLength = self::SALT_LENGTH + $this->ivLength + self::TAG_LENGTH;
        if ($this->useHmac) {
            $minLength += self::HMAC_LENGTH;
        }

        if (strlen($data) < $minLength) {
            return null;
        }

        // Extract salt, IV, tag
        $offset = 0;
        $salt = substr($data, $offset, self::SALT_LENGTH);
        $offset += self::SALT_LENGTH;

        $iv = substr($data, $offset, $this->ivLength);
        $offset += $this->ivLength;

        $tag = substr($data, $offset, self::TAG_LENGTH);
        $offset += self::TAG_LENGTH;

        $key = hash_pbkdf2('sha256', $this->key, $salt, 100_000, 32, true);

        if ($this->useHmac) {
            $hmac = substr($data, -self::HMAC_LENGTH);
            $encryptedText = substr($data, $offset, -self::HMAC_LENGTH);

            $hmacKey = hash_pbkdf2('sha256', $this->key, $salt . 'hmac', 100_000, self::HMAC_LENGTH, true);
            $dataToCheck = substr($data, 0, -self::HMAC_LENGTH);
            $calculatedHmac = hash_hmac('sha256', $dataToCheck, $hmacKey, true);

            if (!hash_equals($hmac, $calculatedHmac)) {
                return null; // HMAC check failed
            }
        } else {
            $encryptedText = substr($data, $offset);
        }

        $decryptedText = openssl_decrypt(
            $encryptedText,
            $this->cipherAlgorithm->value,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        return $decryptedText !== false ? $decryptedText : null;
    }
}
