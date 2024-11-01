<?php

declare(strict_types=1);

namespace longlang\phpkafka\Config;

use InvalidArgumentException;

class CommonConfig extends AbstractConfig
{
    /**
     * @var float
     */
    protected $connectTimeout = -1;

    /**
     * @var float
     */
    protected $sendTimeout = -1;

    /**
     * @var float
     */
    protected $recvTimeout = -1;

    /**
     * The client ID string.
     *
     * @var string
     */
    protected $clientId;

    /**
     * @var int
     */
    protected $maxWriteAttempts = 3;

    /**
     * @var string[]
     */
    protected $bootstrapServers = [];

    /**
     * Auto update brokers.
     *
     * @var bool
     */
    protected $updateBrokers = true;

    /**
     * Exception callback in SwooleClient.
     *
     * @var callable|null
     */
    protected $exceptionCallback = null;

    /**
     * @var array
     */
    protected $sasl = [];

    /**
     * @var SslConfig|null
     */
    protected $ssl = null;

    /**
     * @var int
     */
    protected $maxTopicFetchRetry = -1;

    public function getConnectTimeout(): float
    {
        return $this->connectTimeout;
    }

    public function setConnectTimeout(float $connectTimeout): self
    {
        $this->connectTimeout = $connectTimeout;

        return $this;
    }

    public function setSendTimeout(float $value): self
    {
        $this->sendTimeout = $value;

        return $this;
    }

    public function getSendTimeout(): float
    {
        return $this->sendTimeout;
    }

    public function getRecvTimeout(): float
    {
        return $this->recvTimeout;
    }

    public function setRecvTimeout(float $recvTimeout): self
    {
        $this->recvTimeout = $recvTimeout;

        return $this;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function setClientId(?string $clientId): self
    {
        $this->clientId = $clientId;

        return $this;
    }

    public function getMaxWriteAttempts(): int
    {
        return $this->maxWriteAttempts;
    }

    public function setMaxWriteAttempts(int $maxWriteAttempts): self
    {
        $this->maxWriteAttempts = $maxWriteAttempts;

        return $this;
    }

    public function getBootstrapServer(): array
    {
        return $this->bootstrapServers;
    }

    /**
     * @param string|string[] $bootstrapServer
     */
    public function setBootstrapServer($bootstrapServer): self
    {
        return $this->setBootstrapServers($bootstrapServer);
    }

    public function getBootstrapServers(): array
    {
        return $this->bootstrapServers;
    }

    /**
     * @param string|string[] $bootstrapServers
     */
    public function setBootstrapServers($bootstrapServers): self
    {
        if (\is_string($bootstrapServers)) {
            $this->bootstrapServers = explode(',', $bootstrapServers);
        } elseif (\is_array($bootstrapServers)) {
            $this->bootstrapServers = $bootstrapServers;
        } else {
            throw new InvalidArgumentException(sprintf('The bootstrapServers must be string or array, and the current type is %s', \gettype($bootstrapServers)));
        }

        return $this;
    }

    public function getUpdateBrokers(): bool
    {
        return $this->updateBrokers;
    }

    public function setUpdateBrokers(bool $updateBrokers): self
    {
        $this->updateBrokers = $updateBrokers;

        return $this;
    }

    public function getExceptionCallback(): ?callable
    {
        return $this->exceptionCallback;
    }

    public function setExceptionCallback(?callable $exceptionCallback): self
    {
        $this->exceptionCallback = $exceptionCallback;

        return $this;
    }

    public function getSasl(): array
    {
        return $this->sasl;
    }

    public function setSasl(array $sasl): self
    {
        $this->sasl = $sasl;

        return $this;
    }

    public function getSsl(): SslConfig
    {
        if (null == $this->ssl) {
            return new SslConfig([]);
        }

        return $this->ssl;
    }

    /**
     * @param SslConfig|array $ssl
     */
    public function setSsl($ssl): self
    {
        if (\is_array($ssl)) {
            $this->ssl = new SslConfig($ssl);
        } elseif ($ssl instanceof SslConfig) {
            $this->ssl = $ssl;
        } else {
            throw new InvalidArgumentException(sprintf('The ssl must be array or SslConfig, and the current type is %s', \gettype($ssl)));
        }

        return $this;
    }

    public function getMaxTopicFetchRetry(): int
    {
        return $this->maxTopicFetchRetry;
    }

    public function setMaxTopicFetchRetry(int $maxTopicFetchRetry): self
    {
        $this->maxTopicFetchRetry = $maxTopicFetchRetry;

        return $this;
    }
}
