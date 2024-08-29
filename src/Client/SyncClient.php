<?php

declare(strict_types=1);

namespace longlang\phpkafka\Client;

use InvalidArgumentException;
use longlang\phpkafka\Config\CommonConfig;
use longlang\phpkafka\Exception\UnsupportedApiKeyException;
use longlang\phpkafka\Exception\UnsupportedApiVersionException;
use longlang\phpkafka\Protocol\AbstractRequest;
use longlang\phpkafka\Protocol\AbstractResponse;
use longlang\phpkafka\Protocol\ApiKeys;
use longlang\phpkafka\Protocol\ApiVersions\ApiVersionsRequest;
use longlang\phpkafka\Protocol\ApiVersions\ApiVersionsResponse;
use longlang\phpkafka\Protocol\ApiVersions\ApiVersionsResponseKey;
use longlang\phpkafka\Protocol\ErrorCode;
use longlang\phpkafka\Protocol\KafkaRequest;
use longlang\phpkafka\Protocol\RequestHeader\RequestHeader;
use longlang\phpkafka\Protocol\ResponseHeader\ResponseHeader;
use longlang\phpkafka\Protocol\SaslAuthenticate\SaslAuthenticateRequest;
use longlang\phpkafka\Protocol\SaslAuthenticate\SaslAuthenticateResponse;
use longlang\phpkafka\Protocol\SaslHandshake\SaslHandshakeRequest;
use longlang\phpkafka\Protocol\SaslHandshake\SaslHandshakeResponse;
use longlang\phpkafka\Protocol\Type\Int32;
use longlang\phpkafka\Sasl\PlainSasl;
use longlang\phpkafka\Sasl\SaslInterface;
use longlang\phpkafka\Sasl\ScramSha512Sasl;
use longlang\phpkafka\Socket\SocketInterface;
use longlang\phpkafka\Socket\StreamSocket;

class SyncClient implements ClientInterface
{
    /**
     * @var SocketInterface
     */
    protected $socket;

    /**
     * @var ApiVersionsResponseKey[]
     */
    protected $apiKeys;

    /**
     * @var array
     */
    protected $waitResponseMaps;

    /**
     * @var int
     */
    protected $correlationIdIncrValue = 0;

    public function __construct(string $host, int $port, ?CommonConfig $config = null, string $socketClass = StreamSocket::class)
    {
        $this->socket = new $socketClass($host, $port, $config);
    }

    public function getHost(): string
    {
        return $this->socket->getHost();
    }

    public function getPort(): int
    {
        return $this->socket->getPort();
    }

    public function getConfig(): CommonConfig
    {
        return $this->socket->getConfig();
    }

    public function getSocket(): SocketInterface
    {
        return $this->socket;
    }

    /**
     * @param ApiVersionsResponseKey[] $apiKeys
     */
    public function setApiKeys(array $apiKeys): ClientInterface
    {
        $result = [];
        foreach ($apiKeys as $item) {
            $result[$item->getApiKey()] = $item;
        }
        $this->apiKeys = $result;

        return $this;
    }

    /**
     * @return ApiVersionsResponseKey[]|null
     */
    public function getApiKeys(): ?array
    {
        return $this->apiKeys;
    }

    public function connect(): void
    {
        $this->socket->connect();
        $this->waitResponseMaps = [];
        $this->updateApiVersions();
        $this->sendAuthInfo();
    }

    public function close(): bool
    {
        return $this->socket->close();
    }

    public function getRequestApiVersion(AbstractRequest $request): int
    {
        $apiKey = $request->getRequestApiKey();
        $apiKeyConfig = $this->apiKeys[$apiKey] ?? null;
        if (!$apiKeyConfig) {
            if (ApiKeys::PROTOCOL_API_VERSIONS === $apiKey) {
                return 1;
            }
            throw new UnsupportedApiKeyException(sprintf('Unsupported apikey %s', $apiKey));
        }
        $requestMaxSupportedVersion = $request->getMaxSupportedVersion();
        if ($apiKeyConfig->getMinVersion() > $request->getMaxSupportedVersion()) {
            throw new UnsupportedApiVersionException(sprintf('The version of Api %s must be >= v%s and <= v%s, the latest version currently supported is v%s', $request->getApiKeyText(), $apiKeyConfig->getMinVersion(), $apiKeyConfig->getMaxVersion(), $request->getMaxSupportedVersion()));
        }
        $apiKeyMaxVersion = $apiKeyConfig->getMaxVersion();
        if ($requestMaxSupportedVersion <= $apiKeyMaxVersion) {
            return $requestMaxSupportedVersion;
        } else {
            return $apiKeyMaxVersion;
        }
    }

    /**
     * Send message to kafka server.
     *
     * If successful, return the correlationId
     */
    public function send(AbstractRequest $request, ?RequestHeader $header = null, bool $hasResponse = true): int
    {
        $apiKey = $request->getRequestApiKey();
        if (null === $header) {
            $header = new RequestHeader();
            $header->setRequestApiKey($apiKey);
            $header->setRequestApiVersion($this->getRequestApiVersion($request));
            $header->setClientId($this->getConfig()->getClientId());
            $header->setCorrelationId(++$this->correlationIdIncrValue);
        }
        $kafkaRequest = new KafkaRequest($request, $header);
        $this->socket->send($kafkaRequest->pack());
        $correlationId = $header->getCorrelationId();

        if ($hasResponse) {
            $this->waitResponseMaps[$correlationId] = [
                'apiKey'           => $apiKey,
                'apiVersion'       => $header->getRequestApiVersion(),
                'flexibleVersions' => $request->getFlexibleVersions(),
            ];
        }

        return $correlationId;
    }

    public function recv(?int $correlationId, ?ResponseHeader &$header = null): AbstractResponse
    {
        if (!isset($this->waitResponseMaps[$correlationId])) {
            throw new InvalidArgumentException(sprintf('Invalid correlationId %s', $correlationId));
        }
        $mapData = $this->waitResponseMaps[$correlationId];
        $data = $this->socket->recv(4);
        $length = Int32::unpack($data);
        $data = $this->socket->recv($length);
        $header = new ResponseHeader();
        $header->unpack($data, $size, ResponseHeader::parseVersion($mapData['apiVersion'], $mapData['flexibleVersions']));
        $data = substr($data, $size);

        $result = ApiKeys::createResponse($mapData['apiKey'], $data, $mapData['apiVersion']);
        unset($this->waitResponseMaps[$correlationId]);

        return $result;
    }

    public function sendRecv(AbstractRequest $request, ?RequestHeader $requestHeader = null, ?ResponseHeader &$responseHeader = null): AbstractResponse
    {
        $correlationId = $this->send($request, $requestHeader);

        return $this->recv($correlationId, $responseHeader);
    }

    protected function updateApiVersions(): void
    {
        $request = new ApiVersionsRequest();
        $correlationId = $this->send($request);
        /** @var ApiVersionsResponse $response */
        $response = $this->recv($correlationId);
        ErrorCode::check($response->getErrorCode());
        $this->setApiKeys($response->getApiKeys());
    }

    protected function sendAuthInfo(): void
    {
        $config = $this->getConfig()->getSasl();
        if (!isset($config['type']) || empty($config['type'])) {
            return;
        }
        $class = new $config['type']($this->getConfig());
        if (!$class instanceof SaslInterface) {
            return;
        }

        if ($class instanceof PlainSasl) {
            /* \longlang\phpkafka\Sasl\PlainSasl $class */
            $this->sendPlainAuthInfo($class);
        } elseif ($class instanceof ScramSha512Sasl) {
            /* \longlang\phpkafka\Sasl\ScramSha512Sasl $class */
            $this->sendScramSha512AuthInfo($class);
        } else {
            return;
        }
    }

    private function sendPlainAuthInfo(SaslInterface $class): void
    {
        /** @var \longlang\phpkafka\Sasl\PlainSasl $class */
        $handshakeRequest = new SaslHandshakeRequest();
        $handshakeRequest->setMechanism($class->getName());
        $correlationId = $this->send($handshakeRequest);
        /** @var SaslHandshakeResponse $handshakeResponse */
        $handshakeResponse = $this->recv($correlationId);
        ErrorCode::check($handshakeResponse->getErrorCode());

        $authenticateRequest = new SaslAuthenticateRequest();
        $authenticateRequest->setAuthBytes($class->getAuthBytes());
        $correlationId = $this->send($authenticateRequest);
        /** @var SaslAuthenticateResponse $authenticateResponse */
        $authenticateResponse = $this->recv($correlationId);
        ErrorCode::check($authenticateResponse->getErrorCode());
    }

    private function sendScramSha512AuthInfo(SaslInterface $class): void
    {
        /** @var \longlang\phpkafka\Sasl\ScramSha512Sasl $class */
        // Send first verification message
        $handshakeRequest = new SaslHandshakeRequest();
        $handshakeRequest->setMechanism($class->getName());
        $correlationId = $this->send($handshakeRequest);
        /** @var SaslHandshakeResponse $handshakeResponse */
        $handshakeResponse = $this->recv($correlationId);
        ErrorCode::check($handshakeResponse->getErrorCode());

        // First handshake
        $authenticateRequest = new SaslAuthenticateRequest();
        $authenticateRequest->setAuthBytes($class->getAuthBytes());
        $correlationId = $this->send($authenticateRequest);
        /** @var SaslAuthenticateResponse $authenticateResponse */
        $authenticateResponse = $this->recv($correlationId);
        ErrorCode::check($authenticateResponse->getErrorCode());

        // Second handshake
        $authenticateRequest = new SaslAuthenticateRequest();
        $authenticateRequest->setAuthBytes($class->getFinalMessage($authenticateResponse->getAuthBytes()));
        $correlationId = $this->send($authenticateRequest);
        /** @var SaslAuthenticateResponse $authenticateResponse */
        $authenticateResponse = $this->recv($correlationId);
        ErrorCode::check($authenticateResponse->getErrorCode());

        // Verify the second server response
        if ($class->enableFinalSignatureVerification()) {
            $class->verifyFinalMessage($authenticateResponse->getAuthBytes());
        }
    }
}
