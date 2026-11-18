# NanoDNS

NanoDNS es un servidor DNS modular y de consumo mínimo escrito en Rust. No es un clon de Pi-hole: su arquitectura separa el protocolo, la resolución, la caché, el filtrado y las integraciones opcionales detrás de interfaces propias.

Estado actual: **Fase 3 completada** (workspace, configuración, errores, modelos, interfaces, ciclo de vida, servidor DNS UDP/TCP y resolver forwarder). La caché llegará en la Fase 4.

## Requisitos

- Rust estable (MSRV 1.90).
- Cargo.

## Estructura

```
crates/
  nano-dns-core/     configuración, errores, modelos, interfaces, runtime
  nano-dns/          ejecutable y ciclo de vida
  nano-dns-protocol/ UDP/TCP, validación de mensajes y control de acceso
  nano-dns-resolver/ forwarder (Fase 3); recursivo en la Fase 6
  nano-dns-cache/    Fase 4
  nano-dns-blocker/  Fase 5
  nano-dns-storage/  Fase 7
  nano-dns-stats/    Fase 8
  nano-dns-api/      Fase 9
  nano-dns-web/      Fase 10
config/nano-dns.json
data/lists/
data/database/
tests/
```

Los crates de fases futuras se crearán cuando tengan una implementación real, para evitar módulos vacíos.

## Uso (Fase 3)

```powershell
cargo run -p nano-dns -- --config config/nano-dns.json --check-config
```

Sin `--check-config`, el proceso valida la configuración, inicializa logging, abre los listeners UDP/TCP configurados, reenvía las consultas a los upstreams definidos y espera una señal de apagado.

Las consultas válidas se reenvian sin modificar a `resolver.upstreams`, primero por UDP y por TCP si la respuesta llega truncada o el upstream está marcado con `tcp: true`. Si ningún upstream responde, el cliente recibe `SERVFAIL`. Las consultas malformadas, sobredimensionadas o con más de una pregunta reciben `FORMERR`; las operaciones no soportadas reciben `NOTIMP`.

El modo recursivo (`recursive`) y DNSSEC todavía no están implementados: la configuración se rechaza con un error claro. La caché y el bloqueo tampoco participan aún en el pipeline.

> En Linux, enlazar el puerto 53 puede requerir privilegios. Usa puertos altos en pruebas o ejecuta el proceso con la capacitación correspondiente.

## Cargo features

Por defecto: `forward`, `blocker`.

Opcionales: `recursive`, `sqlite`, `statistics`, `api`, `web`, `doh`, `dot`, `dnssec`.

```powershell
cargo check -p nano-dns
cargo check -p nano-dns --no-default-features
```

La configuración se valida contra las features compiladas: si el JSON solicita SQLite, recursive, API, etc. y la feature no está activa, el arranque falla con un error claro antes de abrir sockets.

## Decisiones técnicas de la Fase 1

- `nano-dns-core` no depende de Hickory DNS: las librerías externas de protocolo quedan encapsuladas en crates posteriores.
- El JSON usa `deny_unknown_fields` y validación semántica completa: nunca se aplica una configuración parcialmente válida.
- Los clientes se identifican únicamente por la dirección `peer` del socket, nunca por cabeceras DNS.
- La API y la web escuchan por defecto solo en loopback.
- Las dependencias se fijan con versiones mínimas verificadas en crates.io (thiserror 2.0, serde 1.0, tokio 1.54, clap 4.6, ipnet 2.12).
- Las dependencias opcionales aún no se han añadido; por eso la build mínima no incluye SQLite, Axum ni Askama.

## Decisiones técnicas de la Fase 2

- Hickory DNS 0.26.3 implementa la codificación DNS; NanoDNS no escribe su propio parser serializador.
- `hickory-server` se compila con `default-features = false`: no se arrastran `resolver`, TLS, SQLite ni verificadores de certificados.
- Hickory queda encapsulado en `nano-dns-protocol`; `nano-dns-core` sigue sin depender de él.
- El control de acceso usa `Server::with_access` con `listeners.allowed_networks`. Si la lista está vacía, se permite solo loopback IPv4 e IPv6.
- La identidad del cliente se toma del `peer` del socket y se correlaciona con `clients[].networks`.
- `listeners.max_packet_bytes` y `listeners.max_concurrent_queries` se aplican en el handler antes de cualquier trabajo de resolución.
- Las respuestas de error conservan las preguntas y EDNS del request cuando está presente.
- El apagado es graceful: se cancela la recepción de nuevas consultas y se espera a que terminen las tareas de los listeners.

## Decisiones técnicas de la Fase 3

- `nano-dns-resolver` implementa el trait `Resolver` de `nano-dns-core` con `DnsQuery`, un tipo neutro que conserva los bytes originales del request.
- La query se reenvía sin recodificar: se preservan flags y opciones EDNS del cliente.
- El upstream se valida antes de aceptarlo: id, tipo de mensaje, opcode y pregunta deben coincidir con la consulta original.
- UDP usa un socket conectado por consulta para evitar respuestas de terceros; el payload se toma del EDNS del cliente o de 1232 bytes por defecto.
- Una respuesta UDP truncada se reintenta por TCP contra el mismo upstream.
- Los reintentos recorren todos los upstreams configurados; `resolver.retries` controla las rondas adicionales.
- El handler del protocolo sustituye el id de la respuesta por el del cliente y reutiliza las preguntas originales al construir la respuesta.
- `nano-dns-core` sigue sin depender de Hickory ni del resolver.

## Verificación

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

## Licencia

MIT. Ver [LICENSE](LICENSE).
