<?php

declare(strict_types=1);

namespace longlang\phpkafka\Sasl;

use longlang\phpkafka\Client\ClientInterface;
use longlang\phpkafka\Config\CommonConfig;
use longlang\phpkafka\Exception\KafkaErrorException;
use longlang\phpkafka\Protocol\ErrorCode;
use longlang\phpkafka\Protocol\SaslAuthenticate\SaslAuthenticateRequest;
use longlang\phpkafka\Protocol\SaslAuthenticate\SaslAuthenticateResponse;
use longlang\phpkafka\Protocol\SaslHandshake\SaslHandshakeRequest;
use longlang\phpkafka\Protocol\SaslHandshake\SaslHandshakeResponse;

class PlainSasl implements SaslInterface
{
    /**
     * @var CommonConfig
     */
    protected $config;

    /**
     * @var ClientInterface
     */
    protected $client;

    public function __construct(ClientInterface $client, CommonConfig $config)
    {
        $this->client = $client;
        $this->config = $config;
    }

    public function auth(): void {
        $handshakeRequest = new SaslHandshakeRequest();
        $handshakeRequest->setMechanism($this->getName());
        $correlationId = $this->client->send($handshakeRequest);
        /** @var SaslHandshakeResponse $handshakeResponse */
        $handshakeResponse = $this->client->recv($correlationId);
        ErrorCode::check($handshakeResponse->getErrorCode());

        $authenticateRequest = new SaslAuthenticateRequest();
        $authenticateRequest->setAuthBytes($this->getAuthBytes());
        $correlationId = $this->client->send($authenticateRequest);
        /** @var SaslAuthenticateResponse $authenticateResponse */
        $authenticateResponse = $this->client->recv($correlationId);
        ErrorCode::check($authenticateResponse->getErrorCode());
    }

    /**
     * 授权模式.
     */
    protected function getName(): string
    {
        return 'PLAIN';
    }

    /**
     * 获得加密串.
     */
    protected function getAuthBytes(): string
    {
        $config = $this->config->getSasl();
        if (empty($config['username']) || empty($config['password'])) {
            // 不存在就报错
            throw new KafkaErrorException('sasl not found auth info');
        }

        return sprintf("\x00%s\x00%s", $config['username'], $config['password']);
    }
}
