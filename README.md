# NanoDNS

NanoDNS es un servidor DNS modular y de consumo mínimo escrito en Rust. No es un clon de Pi-hole: su arquitectura separa el protocolo, la resolución, la caché, el filtrado y las integraciones opcionales detrás de interfaces propias.

Estado actual: **Fase 10 completada** (workspace, configuración, errores, modelos, interfaces, ciclo de vida, servidor DNS UDP/TCP, resolver forwarder, resolver recursivo iterativo, caché DNS en memoria, bloqueo por listas, persistencia SQLite opcional, estadísticas en memoria, API REST opcional, capa HTTP compartida y panel web opcional). DoH y DoT llegarán en fases posteriores.

## Requisitos

- Rust estable (MSRV 1.90).
- Cargo.

## Estructura

```
crates/
  nano-dns-core/     configuración, errores, modelos, interfaces, runtime
  nano-dns/          ejecutable y ciclo de vida
  nano-dns-protocol/ UDP/TCP, validación de mensajes y control de acceso
  nano-dns-resolver/ forwarder y resolver iterativo (feature `recursive`)
  nano-dns-cache/    caché DNS en memoria y decorador de resolver
  nano-dns-blocker/  listas de dominios y reglas de filtrado
  nano-dns-storage/  persistencia SQLite opcional (feature `sqlite`)
  nano-dns-stats/    estadísticas en memoria (feature `statistics`)
  nano-dns-http/     servidor HTTP/1.1 mínimo compartido
  nano-dns-api/      API REST opcional (feature `api`)
  nano-dns-web/      panel web opcional (feature `web`)
config/nano-dns.json
data/lists/
data/database/
tests/
```

Los crates de fases futuras se crearán cuando tengan una implementación real, para evitar módulos vacíos.

## Uso (Fase 10)

```powershell
cargo run -p nano-dns -- --config config/nano-dns.json --check-config
```

Sin `--check-config`, el proceso valida la configuración, inicializa logging, carga las listas de bloqueo locales, abre los listeners UDP/TCP configurados y, si procede, los listeners de la API REST y del panel web; aplica las reglas de filtrado, resuelve las consultas permitidas en modo forward o recursivo, sirve las respuestas cacheadas cuando procede, escribe el historial opcional, actualiza las estadísticas en memoria y espera una señal de apagado que detiene todos los servidores a la vez.

Las consultas válidas se reenvian sin modificar a `resolver.upstreams`, primero por UDP y por TCP si la respuesta llega truncada o el upstream está marcado con `tcp: true`. Si ningún upstream responde, el cliente recibe `SERVFAIL`. Las consultas malformadas, sobredimensionadas o con más de una pregunta reciben `FORMERR`; las operaciones no soportadas reciben `NOTIMP`.

Cuando `dns_cache.enabled` es `true`, las respuestas se guardan en una caché LRU en memoria. Las consultas repetidas se sirven desde la caché sin contactar al upstream, y los TTL devueltos se reducen con el tiempo transcurrido. Las respuestas negativas usan `negative_ttl_secs`; los TTL positivos se limitan con `max_ttl_secs`. Si la caché está desactivada, el pipeline pasa las consultas directamente al forwarder.

Cuando `blocker.enabled` es `true`, las consultas se evalúan contra `denylist`, `allowlist`, listas locales y reglas por cliente antes de la resolución. El allowlist global y el de cliente tienen prioridad sobre el denylist. La respuesta se elige con `blocker.block_response`: `NXDOMAIN`, `NODATA` o `SINKHOLE` (usando `sinkhole_v4`/`sinkhole_v6`). Las listas remotas no se descargan; una fuente con esquema URL se rechaza en el arranque.

Con `resolver.mode = "recursive"` y la feature `recursive` activada, NanoDNS resuelve desde `resolver.root_hints` sin depender de un forwarder: sigue delegaciones NS, usa glue cuando está disponible, resuelve nombres de servidores sin glue, sigue cadenas CNAME y devuelve la respuesta autoritativa con el id original del cliente. `resolver.root_port` permite usar puertos altos en pruebas; en producción suele ser `53`. DNSSEC todavía no se valida: la configuración que lo solicita se rechaza con un error claro.

Con `storage.enabled = true` y la feature `sqlite` activada, NanoDNS crea el esquema en `storage.path` y registra consultas completadas. Si `storage.history = true`, cada consulta permitida o bloqueada se guarda con cliente, transporte, dominio, tipo/clase, decisión, código de respuesta y TTL. El handler solo encola un evento: un hilo escritor agrupa los registros en transacciones SQLite y el apagado graceful vacía la cola antes de terminar. Si el historial está desactivado, se crea la base de datos pero no se almacenan eventos por consulta.

Con `stats.enabled = true` y la feature `statistics` activada, NanoDNS mantiene contadores en memoria para las consultas completadas en los últimos `stats.retention_secs`: totales, permitidas, bloqueadas, aciertos de caché, errores, distribución por código de respuesta, tipo y transporte, y los dominios más consultados. El collector usa un ring temporal protegido por un mutex; expirar entradas no requiere un hilo de limpieza. El flag `cache_hit` viaja desde la caché hasta el evento de estadísticas.

Con `api.enabled = true` y la feature `api` activada, NanoDNS expone una API REST mínima en `api.listen:api.port`. El acceso se restringe por red (solo loopback si `api.allowed_networks` está vacío) y, si se configura `api.token`, mediante `Authorization: Bearer <token>`. La identidad del cliente se toma siempre del peer del socket. Los endpoints son `GET /api/v1/status` (estado y uptime), `GET /api/v1/stats` (snapshot de estadísticas; 404 si no están activadas) y `GET /api/v1/config` (configuración saneada, sin secretos). Métodos distintos de GET devuelven `405` con cabecera `Allow`.

Con `web.enabled = true` y la feature `web` activada, NanoDNS sirve un panel HTML de solo lectura en `web.listen:web.port`. Muestra estado, uptime, modo de resolución y, si las estadísticas están activadas, contadores y desgloses por código de respuesta, tipo, transporte y dominios más consultados. El panel es siempre loopback-only: `WebConfig` no expone lista de redes, y el peer del socket debe ser `127.0.0.0/8` o `::1/128`. Las rutas son `/` (panel) y `/health` (texto plano). Todo valor dinámico se escapa antes de renderizar.

> En Linux, enlazar el puerto 53 puede requerir privilegios. Usa puertos altos en pruebas o ejecuta el proceso con la capacitación correspondiente.

## Cargo features

Por defecto: `forward`, `blocker`.

Opcionales: `recursive`, `sqlite`, `statistics`, `api`, `web`, `doh`, `dot`, `dnssec`.

```powershell
cargo check -p nano-dns
cargo check -p nano-dns --no-default-features
```

La configuración se valida contra las features compiladas: si el JSON solicita SQLite, estadísticas, recursive, API, bloqueo, etc. y la feature no está activa, el arranque falla con un error claro antes de abrir sockets. Las features `blocker`, `recursive`, `sqlite`, `statistics`, `api` y `web` también controlan sus dependencias de código: sin ellas, el filtrado, el resolver iterativo, el escritor SQLite, el collector de estadísticas, el servidor HTTP o el panel web no se compilan en el ejecutable.

## Decisiones técnicas de la Fase 1

- `nano-dns-core` no depende de Hickory DNS: las librerías externas de protocolo quedan encapsuladas en crates posteriores.
- El JSON usa `deny_unknown_fields` y validación semántica completa: nunca se aplica una configuración parcialmente válida.
- Los clientes se identifican únicamente por la dirección `peer` del socket, nunca por cabeceras DNS.
- La API y la web escuchan por defecto solo en loopback.
- Las dependencias se fijan con versiones mínimas verificadas en crates.io (thiserror 2.0, serde 1.0, tokio 1.54, clap 4.6, ipnet 2.12).
- Las dependencias opcionales se añaden solo con su feature; la build mínima no incluye SQLite, Axum ni Askama.

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

## Decisiones técnicas de la Fase 4

- `nano-dns-cache` implementa el trait `DnsCache` del core con claves `DnsQuery`; el id de transacción se excluye para que consultas equivalentes compartan entrada.
- La clave incluye nombre, tipo, clase y el flag DNSSEC, de modo que respuestas con y sin registros DNSSEC no se mezclan.
- `CachingResolver<R>` decora cualquier `Resolver`: sirve aciertos y guarda los fallos en caché tras una resolución correcta. Si `dns_cache.enabled` es falso, usa un modo pass-through y mantiene el mismo tipo concreto en el servidor.
- La caché es LRU y respeta `max_entries` y `max_bytes` (límite blando de memoria).
- Los TTL incrustados en el mensaje codificado se limitan al guardar y se reducen al leer, usando un reloj inyectable para pruebas deterministas.
- Las respuestas negativas usan `negative_ttl_secs`; las positivas con TTL cero no se cachean.
- Solo se usa `hickory-proto` para ajustar TTL; `nano-dns-core` sigue sin depender de Hickory ni de la caché.
- No se añadió ninguna feature de Cargo para la caché: no incorpora dependencias nuevas y siempre está disponible.

## Decisiones técnicas de la Fase 5

- `nano-dns-blocker` implementa el trait `Policy` del core sin depender de Hickory.
- El filtrado se ejecuta en el handler antes de la caché y del forwarder; una consulta bloqueada nunca contacta al upstream ni llena la caché de DNS.
- La coincidencia es por sufijo de dominio, insensible a mayúsculas y al punto final, con soporte para `*.dominio`, `.dominio`, `||dominio^` y filas de hosts.
- El allowlist global y el allowlist del cliente prevalecen sobre el denylist global y del cliente.
- El id del cliente se correlaciona desde la IP peer del socket con `clients[].networks`; nunca se confía en cabeceras DNS.
- Las listas se leen de `blocker.lists_dir` al arrancar; no hay descargas remotas ni tareas de refresco en esta fase.
- `policy_cache.enabled` activa una caché LRU de decisiones por dominio y cliente; `policy_cache.max_entries` la acota.
- Las respuestas bloqueadas se construyen con Hickory dentro de `nano-dns-protocol`, preservando pregunta y EDNS del request.
- No se añadieron dependencias nuevas: solo se usan `core`, `thiserror` y `tracing`, ya presentes en el workspace.

## Decisiones técnicas de la Fase 6

- El resolver iterativo vive en `nano-dns-resolver` y está detrás de la feature `recursive`; el core sigue sin depender de Hickory.
- No se añadió `hickory-resolver`: se reutilizan `hickory-proto` y `tokio`, ya presentes, para mantener el tamaño mínimo.
- Las consultas iterativas usan `RD=0` y un id propio; la respuesta final se reescribe con el id y la pregunta originales del cliente.
- Se siguen delegaciones NS con glue de la sección adicional. Sin glue, los nombres de servidor se resuelven por A/AAAA desde las raíces, con límite de profundidad.
- Se siguen cadenas CNAME acumulando todos los registros y se detectan ciclos.
- Los límites `MAX_DEPTH` y `MAX_ITERATIONS` evitan bucles y consultas infinitas.
- UDP reintenta por TCP cuando la respuesta está truncada; los reintentos y el timeout usan la configuración existente.
- `resolver.root_port` permite probar con puertos altos sin privilegios.
- El pipeline usa un enum `UpstreamResolver` para seleccionar forwarder o recursivo sin objetos trait ni GATs complejos; la caché y el handler no cambian.
- DNSSEC sigue sin implementarse y se rechaza explícitamente en la validación.

## Decisiones técnicas de la Fase 7

- `nano-dns-storage` implementa el trait `Storage` del core sin depender de Hickory.
- SQLite se añade solo con la feature `sqlite`, usando `rusqlite` con SQLite empaquetado para no exigir una librería del sistema.
- El writer es un hilo propio con una cola acotada de eventos; `record` no hace E/S de disco y nunca falla la consulta DNS.
- Los eventos se agrupan en transacciones SQLite; `flush` se usa durante el apagado graceful.
- El esquema guarda metadatos de versión, índices por fecha y dominio, y una tabla `query_history` con cliente, transporte, decisión, código de respuesta y TTL.
- `storage.history = false` mantiene la base de datos y el esquema listos sin escribir una fila por consulta.
- La identidad del cliente sigue viniendo del peer del socket; nunca se toma de cabeceras DNS.
- Las stats agregadas se implementaron en la Fase 8; la API para consultar los datos se implementó en la Fase 9.

## Decisiones técnicas de la Fase 8

- `nano-dns-stats` implementa el trait `StatsSink` del core sin depender de Hickory.
- El collector mantiene un `VecDeque` de eventos con marca de tiempo; la retención se aplica recortando por tiempo, sin tareas en segundo plano.
- `StatsSnapshot` es un tipo del core con contadores agregados y mapas ordenados, listo para ser expuesto por la API.
- `Response` y `QueryEvent` llevan un flag `cache_hit` que la caché introduce y el handler propaga a estadísticas y persistencia.
- El handler alimenta storage y stats desde el mismo evento; un fallo de persistencia nunca aborta la consulta ni impide contabilizarla.
- `DnsServer::stats_snapshot()` expone el estado actual para futuras integraciones.
- La configuración exige `stats.retention_secs > 0` cuando las estadísticas están activadas.

## Decisiones técnicas de la Fase 9

- `nano-dns-http` implementa un servidor HTTP/1.1 mínimo sobre Tokio sin axum, hyper ni tower, para no añadir dependencias a la build mínima.
- La API depende de `nano-dns-core`, `nano-dns-http` y Tokio; no conoce Hickory ni el servidor DNS.
- El access control usa el peer del socket y una lista de redes (loopback por defecto); el token Bearer se compara en tiempo constante.
- `stats` se comparte como `Arc<dyn StatsSink>` entre el handler DNS y la API, sin copiar datos.
- `/api/v1/stats` devuelve 404 cuando la feature `statistics` no está compilada o las stats están desactivadas.
- La respuesta de `/api/v1/config` es una vista saneada: nunca expone `api.token` ni rutas de certificados.
- DNS, API y web comparten un canal de apagado `watch`: una sola señal del sistema detiene todos los servidores de forma coordinada.
- Las peticiones se limitan por tamaño y tiempo de lectura; solo se acepta `GET` y una petición por conexión.

## Decisiones técnicas de la Fase 10

- La capa HTTP se extrajo a `nano-dns-http` para que API y web compartan el parser, la escritura de respuestas y el accept loop sin duplicar código ni añadir un framework.
- `HttpServer<S>` recibe un handler sobre estado compartido: cada crate decide enrutamiento, autenticación y contenido.
- `nano-dns-web` es un panel de solo lectura: no hay endpoints de mutación, por lo que basta con restringirlo a loopback en lugar de añadir otro esquema de tokens.
- El HTML se genera en el servidor con escape de todos los valores dinámicos (nombre de instancia, dominios, transportes) para evitar inyección de markup.
- El panel reutiliza el mismo `Arc<dyn StatsSink>` que la API y el handler DNS, sin copias ni hilos adicionales.
- Las respuestas usan `Content-Type` explícito y `X-Content-Type-Options: nosniff`; solo se acepta `GET` y una petición por conexión.

## Verificación

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo check --workspace --all-features
cargo test --workspace --all-features
cargo check -p nano-dns --no-default-features
cargo check -p nano-dns --no-default-features --features forward,blocker,recursive,sqlite,statistics,api,web,doh,dot,dnssec
```

## Licencia

MIT. Ver [LICENSE](LICENSE).
