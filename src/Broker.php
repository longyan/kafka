<?php

declare(strict_types=1);

namespace longlang\phpkafka;

use InvalidArgumentException;
use longlang\phpkafka\Client\ClientInterface;
use longlang\phpkafka\Consumer\ConsumerConfig;
use longlang\phpkafka\Exception\NoAliveBrokerException;
use longlang\phpkafka\Producer\ProducerConfig;
use longlang\phpkafka\Protocol\ErrorCode;
use longlang\phpkafka\Protocol\Metadata\MetadataRequest;
use longlang\phpkafka\Protocol\Metadata\MetadataRequestTopic;
use longlang\phpkafka\Protocol\Metadata\MetadataResponse;
use longlang\phpkafka\Protocol\Metadata\MetadataResponseTopic;
use longlang\phpkafka\Util\KafkaUtil;

class Broker
{
    /**
     * @var ProducerConfig|ConsumerConfig
     */
    protected $config;

    /**
     * @var string[]
     */
    protected $brokers;

    /**
     * @var ClientInterface[]
     */
    protected $clients = [];

    /**
     * @var MetadataResponseTopic[]
     */
    protected $topicsMeta;

    /**
     * @var string[]
     */
    protected $metaUpdatedTopics = [];

    /**
     * @param ProducerConfig|ConsumerConfig $config
     */
    public function __construct($config)
    {
        $this->config = $config;
    }

    public function close(): void
    {
        foreach ($this->clients as $client) {
            $client->close();
        }
        $this->clients = [];
    }

    public function updateBrokers(): void
    {
        $config = $this->config;

        $url = null;
        if ($config instanceof ConsumerConfig) {
            $brokers = $config->getBroker();

            if (\is_array($brokers)) {
                $url = parse_url($brokers[array_rand($brokers)]);
            } elseif (\is_string($brokers)) {
                $url = parse_url(explode(',', $brokers)[0]);
            }
        }
        if (!$url) {
            $bootstrapServers = $config->getBootstrapServers();
            $url = parse_url($bootstrapServers[array_rand($bootstrapServers)]);
        }

        if (!$url) {
            throw new InvalidArgumentException('Invalid bootstrapServer');
        }

        $clientClass = KafkaUtil::getClientClass($config->getClient());
        /** @var ClientInterface $client */
        $client = new $clientClass($url['host'], $url['port'] ?? 9092, $config, KafkaUtil::getSocketClass($config->getSocket()));
        $client->connect();
        $response = $this->updateMetadata([], $client);
        $client->close();

        $brokers = [];
        foreach ($response->getBrokers() as $broker) {
            $brokers[$broker->getNodeId()] = $broker->getHost() . ':' . $broker->getPort();
        }

        if (empty($brokers)) {
            throw new NoAliveBrokerException('No brokers are available');
        }

        $this->setBrokers($brokers);
    }

    public function updateMetadata(array $topics = [], ?ClientInterface $client = null, int $retry = 0): MetadataResponse
    {
        if (null === $client) {
            $client = $this->getClient();
        }
        $config = $this->config;
        $request = new MetadataRequest();
        $topicsArray = [];
        foreach ($topics as $topic) {
            $topicsArray[] = (new MetadataRequestTopic())->setName($topic);
        }
        $request->setTopics($topicsArray ?: null);
        $request->setAllowAutoTopicCreation($config->getAutoCreateTopic());
        /** @var MetadataResponse $response */
        $response = $client->sendRecv($request);
        $topicsMeta = [];
        $retryTopics = [];
        foreach ($response->getTopics() as $topicItem) {
            $errorCode = $topicItem->getErrorCode();
            if (ErrorCode::success($errorCode)) {
                $topicsMeta[] = $topicItem;
            } else {
                switch ($topicItem->getErrorCode()) {
                    case ErrorCode::UNKNOWN_TOPIC_OR_PARTITION:
                    case ErrorCode::LEADER_NOT_AVAILABLE:
                        $retryTopics[] = $topicItem->getName();
                        break;
                    default:
                        ErrorCode::check($errorCode);
                }
            }
        }
        if ($this->topicsMeta) {
            $this->topicsMeta = array_values(array_merge($this->topicsMeta, $topicsMeta));
        } else {
            $this->topicsMeta = $topicsMeta;
        }
        if ($this->metaUpdatedTopics) {
            $this->metaUpdatedTopics = array_values(array_merge($this->metaUpdatedTopics, $topics));
        } else {
            $this->metaUpdatedTopics = $topics;
        }

        if ($retryTopics && ($this->config->getMaxTopicFetchRetry() < 0 || $this->config->getMaxTopicFetchRetry() <= $retry)) {
            return $this->updateMetadata($retryTopics, $client, $retry + 1);
        }

        return $response;
    }

    public function getClient(?int $brokerId = null): ClientInterface
    {
        return $this->getClientByBrokerId($brokerId ?? array_rand($this->brokers, 1));
    }

    public function getClientByBrokerId(int $brokerId): ClientInterface
    {
        if (!isset($this->brokers[$brokerId])) {
            throw new InvalidArgumentException(sprintf('Not found brokerId %s', $brokerId));
        }

        $url = parse_url($this->brokers[$brokerId]);
        if (!$url) {
            throw new InvalidArgumentException(sprintf('Invalid bootstrapServer %s', $this->brokers[$brokerId]));
        }

        if (isset($this->clients[$brokerId])) {
            $client = $this->clients[$brokerId];
            if (!$client->getSocket()->isConnected()) {
                $client = $this->setClientConnection($brokerId);
            }
        } else {
            $client = $this->setClientConnection($brokerId);
        }

        return $client;
    }

    /**
     * @return string|string[]
     */
    public function getBrokers()
    {
        return $this->brokers;
    }

    /**
     * @param string|string[] $brokers
     */
    public function setBrokers($brokers): self
    {
        if (\is_string($brokers)) {
            $this->brokers = explode(',', $brokers);
        } elseif (\is_array($brokers)) {
            $this->brokers = $brokers;
        } else {
            throw new InvalidArgumentException(sprintf('The type of brokers must be string or array, and the current type is %s', \gettype($brokers)));
        }

        return $this;
    }

    /**
     * @return ProducerConfig|ConsumerConfig
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * @param string|string[]|null $topics
     *
     * @return MetadataResponseTopic[]
     */
    public function getTopicsMeta($topics = null): array
    {
        if ($topics) {
            $notFoundTopics = [];
            foreach ((array) $topics as $topic) {
                if (!\in_array($topic, $this->metaUpdatedTopics)) {
                    $notFoundTopics[] = $topic;
                }
            }
            if ($notFoundTopics) {
                $this->updateMetadata($notFoundTopics);
            }
        }

        return $this->topicsMeta;
    }

    public function getBrokerIdByTopic(string $topic, int $partition): ?int
    {
        if (!\in_array($topic, $this->metaUpdatedTopics)) {
            $this->updateMetadata([$topic]);
        }
        foreach ($this->topicsMeta as $topicMeta) {
            if ($topicMeta->getName() === $topic) {
                foreach ($topicMeta->getPartitions() as $topicPartition) {
                    if ($topicPartition->getPartitionIndex() === $partition) {
                        return $topicPartition->getLeaderId();
                    }
                }
            }
        }

        return null;
    }

    /**
     * Set the Kafka Client Connection.
     */
    private function setClientConnection(?int $brokerId): ClientInterface
    {
        $url = parse_url($this->brokers[$brokerId]);
        $clientClass = KafkaUtil::getClientClass($this->config->getClient());
        /** @var ClientInterface $client */
        $client = new $clientClass($url['host'], $url['port'] ?? 9092, $this->config, KafkaUtil::getSocketClass($this->config->getSocket()));
        $client->connect();
        $this->clients[$brokerId] = $client;

        return $client;
    }
}
