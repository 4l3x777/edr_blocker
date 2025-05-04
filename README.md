# WFP Endpoint Protection Agent Traffic Blocker

- блокировка трафика EDR/XDR агента с сервером центра безопасности
- использован модифицированный WFP драйвер (Windivert) последней версии

## Windivert driver

- windivert-driver - проект содержит WFP драйвер, который необоходимо собрать для проекта

## Edr blocker

- проект, взаимодействующий с windivert driver и выполняющий блокировку трафика

### Agent name

- в socket_connection.h по необходимости добавьте имя процесса EDR агента

```C++
namespace socket_connection {

    #define INET6_ADDRSTRLEN    45

    namespace {
        sf::safe_ptr<std::vector<std::string>> edr_process_name(
            std::vector<std::string>({
                //av
                "ccsvchst",
                "smc",
                "mfetp",
                ...
```

### Monitoring thread count

- в edr_blocker.h

```C++
    class EdrSocketPacketSniffer {
        ...
        int monitor_threads_count{ 5 };
        ...
```

### API

- EdrSocketPacketSniffer - реализован как singleton класс

```C++
    auto socket_sniffer = EdrSocketPacketSniffer::getInstance(); 
```

- startSniffing - запуск перехвата и блокировки пакетов

- stopSniffing - остановка блокировки пакетов

### Example

![alt text](/img/edr_blocker.gif)

```C++
int __cdecl main(int argc, char **argv)
{
    auto socket_sniffer = EdrSocketPacketSniffer::getInstance();  
    // start sniffing
    if (socket_sniffer.startSniffing()) {
        // monitoring one hour
        Sleep(3600000);
        // stop sniffing
        socket_sniffer.stopSniffing();
    }
    return 0;
}
```

