本仓库是在 [longlang/kafka](https://github.com/swoole/phpkafka) 的基础上增加了 `SCRAM-SHA-512` 加密方式的连接。

使用时 `sasl` 配置为
```php
...
'sasl' => [
    'type' => \longlang\phpkafka\Sasl\ScramSha512Sasl::class,
    'username' => env('KAFKA_SASL_USERNAME', ''),
    'password' => env('KAFKA_SASL_PASSWORD', ''),
    // 是否验证第二次握手的服务器响应消息的签名
    'verify_final_signature' => (bool) env('KAFKA_SASL_VERIFY_FINAL_SIGNATURE', false),
],
...
```


# Changed Log
## [v1.2.3] - 2023-08-24
### Added
 - 增加基于 `SCRAM-SHA-512` 加密方式的连接；