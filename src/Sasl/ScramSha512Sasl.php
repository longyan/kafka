<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace longlang\phpkafka\Sasl;

use longlang\phpkafka\Config\CommonConfig;
use longlang\phpkafka\Exception\KafkaErrorException;
use longlang\phpkafka\Protocol\ErrorCode;

class ScramSha512Sasl implements SaslInterface
{
    /**
     * @var CommonConfig
     */
    protected $config;

    protected string $nonce = '';

    protected string $saltedPassword = '';

    protected string $authMessage = '';

    public function __construct(CommonConfig $config)
    {
        $this->config = $config;
        $this->nonce = base64_encode(random_bytes(16));
    }

    /**
     * 授权模式.
     */
    public function getName(): string
    {
        return 'SCRAM-SHA-512';
    }

    /**
     * SCRAM-SHA-512 first handshake.
     */
    public function getAuthBytes(): string
    {
        $config = $this->config->getSasl();
        if (empty($config['username']) || empty($config['password'])) {
            throw new KafkaErrorException('sasl not found auth info');
        }

        return sprintf('n,,%s', $this->getFirstMessageBare());
    }

    /**
     * Get all SASL configurations.
     */
    public function getSaslConfigs(): array
    {
        return $this->config->getSasl();
    }

    /**
     * Get SASL simple configuration.
     */
    public function getSaslConfig(string $key): mixed
    {
        return $this->getSaslConfigs()[$key] ?? null;
    }

    /**
     * Second handshake of SCRAM-SHA-512.
     */
    public function getFinalMessage(string $response): string
    {
        // Split the response after the first handshake
        [$r, $s, $i] = explode(',', $response);

        // Extract the random number, salt, and number of iterations
        $serverNonce = $this->ltrimMessage($r);
        $salt = base64_decode($this->ltrimMessage($s));
        $iterations = (int) $this->ltrimMessage($i);

        // Calculate the parameters for the second handshake
        $this->saltedPassword = $saltedPassword = $this->calculateSaltedPassword($this->getPassword(), $salt, $iterations);

        $clientKey = $this->calculateClientKey($saltedPassword);
        $storedKey = $this->calculateStoredKey($clientKey);

        $clientFirstMessageBare = $this->getFirstMessageBare();
        $serverFirstMessage = $response;
        $clientFinalMessageWithoutProof = $this->getMessageWithoutProof($serverNonce);

        $this->authMessage = $authMessage = sprintf('%s,%s,%s', $clientFirstMessageBare, $serverFirstMessage, $clientFinalMessageWithoutProof);
        $clientSignature = $this->hmac($authMessage, $storedKey);

        return sprintf('%s,p=%s', $clientFinalMessageWithoutProof, base64_encode($clientKey ^ $clientSignature));
    }

    /**
     * SHA-512 encryption.
     */
    public function hmac(string $data, string $key): string
    {
        return hash_hmac('sha512', $data, $key, true);
    }

    /**
     * Remove the first two characters of the server response message.
     */
    public function ltrimMessage(string $param): string
    {
        return substr($param, 2);
    }

    /**
     * Whether to enable final signature verification.
     */
    public function enableFinalSignatureVerification(): bool
    {
        return (bool) $this->getSaslConfig('verify_final_signature');
    }

    /**
     * Verify final signature.
     */
    public function verifyFinalMessage(string $message): void
    {
        $receivedSignature = $this->ltrimMessage($message);
        $receivedSignature = base64_decode($receivedSignature);

        $serverKey = $this->hmac('Server Key', $this->saltedPassword);
        $expectedSignature = $this->hmac($this->authMessage, $serverKey);

        if (! hash_equals($receivedSignature, $expectedSignature)) {
            ErrorCode::check(ErrorCode::SASL_AUTHENTICATION_FAILED);
        }
    }

    /**
     * Get first handshake information of SCRAM-SHA-512.
     */
    private function getFirstMessageBare(): string
    {
        return sprintf('n=%s,r=%s', $this->getSaslConfig('username'), $this->nonce);
    }

    /**
     * Get SASL password.
     */
    private function getPassword(): string
    {
        return $this->getSaslConfigs()['password'] ?? '';
    }

    /**
     * Compute salted password using PBKDF2 function and the salt and iteration count provided by the server.
     */
    private function calculateSaltedPassword(string $password, string $salt, int $iterations): string
    {
        return hash_pbkdf2('sha512', $password, $salt, $iterations, 0, true);
    }

    /**
     * Compute client key using salted password and HMAC function to calculate client key.
     */
    private function calculateClientKey(string $saltedPassword): string
    {
        // In SCRAM-SHA-512, a salted password is required to encrypt the calculation secret
        // and the key is fixed to "Client Key"
        return $this->hmac('Client Key', $saltedPassword);
    }

    /**
     * Compute stored key using client key and SHA-256 function to calculate stored key.
     */
    private function calculateStoredKey(string $clientKey): string
    {
        return hash('sha512', $clientKey, true);
    }

    /**
     * Get message without proof.
     */
    private function getMessageWithoutProof(string $nonce): string
    {
        return sprintf('c=biws,r=%s', $nonce);
    }
}
