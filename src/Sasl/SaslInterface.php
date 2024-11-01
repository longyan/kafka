<?php

declare(strict_types=1);

namespace longlang\phpkafka\Sasl;

use longlang\phpkafka\Client\ClientInterface;
use longlang\phpkafka\Config\CommonConfig;

interface SaslInterface
{
    public function __construct(ClientInterface $client, CommonConfig $config);

    public function auth(): void;
}
