# Configuration

## Servers
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| servers  | Server[]      | A list of proxy exposed by octo | yes      |


## Server

| Field    | Type          | Description   | Required |
| -------- | ------------- | ------------- | -------- |
| name     | `<string>`    | Name of proxy | no       |
| listener | `Hostconfig`  | Set of listener related configuration, all of incoming request to octo-proxy will be handled by this listener.            | yes      |
| target   | `Hostconfig`  | Set of target related configuration, this target is backend which octo-proxy will forward all incoming request accepted by listener.            | yes      |
| mirror   | `Hostconfig`  | Set of mirror related configuration, if this configuration is set, all incoming request will also forwarded to this mirror, unlike target, in mirror we implement fire & forget, every request will only forwarded, and the response will be ignored.            | no       |

## Hostconfig
| Field     | Type          | Description                     | Required |
| --------- | ------------- | ------------------------------- | -------- |
| host      | `<string>`    | On `listener`, this is host where listener will be listen, and on `target` and `mirror` this is host of backend where request will be forwarded | yes      |
| port      | `<string>`    | On `listener`, this is port where listener will be bind, and on `target` and `mirror` this is port of backend where request will be forwarded | yes      |
| timeout   | `<string>`    | set timeout (in second) or deadline for every connection, default 300 seconds | no      |
| tlsConfig | `tlsConfig`   | set tls configuration if host use tls | no      |


## tlsConfig
| Field    | Type          | Description                     | Required |
| -------- | ------------- | ------------------------------- | -------- |
| mode     | tlsMode       | Set mode of tls                 | yes      |
| caCert   | `<string>`    | Location where CA Certificates is stored, use this option if root certificated is not stored in trust store, this option can be used in `simple`. In `mutual` mode this option is `REQUIRED`                 | yes      |
| cert     | `<string>`    | Location where Certificates is stored, use this option if want to enable tls in `listener`, in `mirror` and `target` this certificate will be used to prove identity                  | yes      |
| key      | `<string>`    | Location where private key is stored, use this option if want to enable tls in `listener`, in `mirror` and `target` this certificate will be used to prove identity                  | yes      |


## tlsMode
| Field     | Type          | Description                     |
| --------- | ------------- | ------------------------------- 
| `simple`  | `<string>`    | Use this option to use simple TLS, and will only verify the server identity. Required option `mode: simple` and `caCert` if root certificate not stored in trust store |
| `mutual`  | `<string>`    | Use this option to use mutual TLS (mTLS). With this mode, server and client will verify each other. Required option `mode: mutual`, `caCert`, `cert`, and `key`. |