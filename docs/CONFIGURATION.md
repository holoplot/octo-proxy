# Configuration

## Servers
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| servers  | [Server[]](#server)      | A list of proxy exposed by octo | yes      |
| dnsWatch | [`dnsWatchConfig`](#dnswatchconfig) | Settings shared by all targets that have `dnsWatch` set | no       |


## Server
| Field        | Type             | Description   | Required |
| ------------ | ---------------- | ------------- | -------- |
| name         | `<string>`       | Name of proxy | no       |
| listener     | [`Hostconfig`](#hostconfig) | Set of listener related configuration, all of incoming request to octo-proxy will be handled by this listener.            | yes      |
| targets      | [`Hostconfig[]`](#hostconfig) | Set of target related configurations. These targets are backends which octo-proxy will forward all incoming traffic accepted by the listener.            | yes      |
| mdnsTarget   | [`mdnsTargetConfig`](#mdnstargetconfig) | A mDNS service target configuration. If specified, services announced under this name will be resolved and then be used as additional targets on each request.            | no      |
| mirror       | [`Hostconfig`](#hostconfig)  | Set of mirror related configuration, if this configuration is set, all incoming request will also forwarded to this mirror, unlike target, in mirror we implement fire & forget, every request will only forwarded, and the response will be ignored.            | no       |

## Hostconfig
| Field     | Type          | Description                     | Required |
| --------- | ------------- | ------------------------------- | -------- |
| host      | `<string>`    | On `listener`, this is host where listener will be listen, and on `target` and `mirror` this is host of backend where request will be forwarded | yes      |
| port      | `<string>`    | On `listener`, this is port where listener will be bind, and on `target` and `mirror` this is port of backend where request will be forwarded | yes      |
| connection   | [`connectionConfig`](#connectionConfig)    | set timeout (in second) or deadline for every connection, default 300 seconds. A value of 0 will disable deadlines on connections | no      |
| tls       | [`tlsConfig`](#tlsconfig)   | set tls configuration if host use tls | no      |
| dnsWatch  | `bool`        | Only on `targets`, and only when `host` is a hostname. Close connections to this target when their address is no longer in the hostname's DNS answer, so that clients reconnect to an address that is. See [DNS watch](#dns-watch) | no      |

When `host` of a `target` or `mirror` is a hostname, octo-proxy resolves it itself and dials the addresses in random order, starting the next address after `dialStagger` if the previous one hasn't connected yet. Connections therefore spread over all addresses whatever order the resolver returns them in, and an unreachable address delays a connection by only `dialStagger`.

## mdnsTargetConfig
| Field       | Type          | Description                     | Required |
| ----------- | ------------- | ------------------------------- | -------- |
| serviceName | `<string>`    | The mDNS service name to resolve. Must start with an underscore. | yes      |
| ipv4        | `bool`        | Enable the lookup of IPv4 addresses for this service | no    |
| ipv6        | `bool`        | Enable the lookup of IPv6 addresses for this service | no    |
| connection  | [`connectionConfig`](#connectionConfig)    | set timeout (in second) or deadline for every connection, default 300 seconds. A value of 0 will disable deadlines on connections | no      |
| tls         | [`tlsConfig`](#tlsconfig) | set tls configuration if host use tls    | no      |

At least one of `ipv4` or `ipv6` needs to be set to `true`.

## connectionConfig
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| timeout  | `<string>`    | Set timeout or deadline for every connection, you can set in milliseconds with `ms` or seconds `s`. default 300 seconds. A value of 0 will disable deadlines on connections                 | no       |
| connectTimeout | `<string>` | Timeout for each connection attempt, as a duration such as `5s`. Default 5 seconds | no       |
| dialStagger | `<string>` | For hostname targets: how long to wait for one address before also trying the next, as a duration such as `250ms`. Default 250 milliseconds. A value of 0 tries all addresses at once | no       |

## tlsConfig
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| mode     | [`tlsMode`](#tlsmode)       | Set mode of tls                 | yes      |
| caCert   | `<string>`    | Location where CA Certificates is stored, use this option if root certificated is not stored in trust store, this option can be used in `simple`. In `mutual` mode this option is `REQUIRED`                 | yes      |
| cert     | `<string>`    | Location where Certificates is stored, use this option if want to enable tls in `listener`, in `mirror` and `target` this certificate will be used to prove identity                  | yes      |
| key      | `<string>`    | Location where private key is stored, use this option if want to enable tls in `listener`, in `mirror` and `target` this certificate will be used to prove identity                  | yes      |

## tlsMode
| Field     | Type          | Description                     |
| --------- | ------------- | ------------------------------- 
| `simple`  | `<string>`    | Use this option to use simple TLS, and will only verify the server identity. Required option `mode: simple` and `caCert` if root certificate not stored in trust store |
| `mutual`  | `<string>`    | Use this option to use mutual TLS (mTLS). With this mode, server and client will verify each other. Required option `mode: mutual`, `caCert`, `cert`, and `key`. |

> Currently, in mutual mode octo-proxy will only verify the ip address of it's client and try to match it with ip sans in certificate. In the future we will adding more alternative names verification.

## dnsWatchConfig
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| interval | `<string>`    | How often to look up each watched hostname, as a duration such as `5s`. Default 5 seconds | no       |

## DNS watch
For every hostname that a target with `dnsWatch: true` names, octo-proxy runs one watcher, shared by all servers. Every `interval` it asks the local resolver for the hostname's IPv4 addresses. When a successful, non-empty answer no longer contains the address of a connection to that target, octo-proxy closes both sides of that connection right away, and the client's reconnect is dialled to an address from the current answer.

- Polling the local resolver is cheap: a caching resolver such as systemd-resolved answers from its cache until the record's TTL expires, so a change is seen at most one `interval` after the TTL runs out.
- Failed lookups, NXDOMAIN and empty answers close nothing.
- Connections from `mdnsTarget`, IP-literal targets and IPv6 connections are never closed by the watcher.

```yaml
dnsWatch:
  interval: 5s

servers:
  - name: example
    listener:
      host: 127.0.0.1
      port: 4222
    targets:
      - host: backend.example.com
        port: 4222
        dnsWatch: true
        connection:
          timeout: 0
```

Metrics, labelled with the hostname: `octo_dnswatch_answer_change`, `octo_dnswatch_conn_moved`, `octo_dnswatch_resolve_error`.

## Metrics
| Field    | Type          | Description                     |                                                 | Required |
| -------- | ------------- | ------------------------------- | ----------------------------------------------- | -------- |
| metrics  | [HostConfig]  | Configures the host and port for the metrics server, currently doesn't support tls settings | no       |
