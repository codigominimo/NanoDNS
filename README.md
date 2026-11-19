# NanoDNS

NanoDNS es un servidor DNS modular y de consumo mínimo escrito en Rust. No es un clon de Pi-hole: su arquitectura separa el protocolo, la resolución, la caché, el filtrado y las integraciones opcionales detrás de interfaces propias. Todas las capacidades se compilan siempre; es el JSON quien decide cuáles se activan.

Estado actual: **Fase 13 completada** (workspace, configuración, errores, modelos, interfaces, ciclo de vida, servidor DNS UDP/TCP, resolver forwarder, resolver recursivo iterativo, caché DNS en memoria, bloqueo por listas controlable en caliente, persistencia SQLite, estadísticas en memoria, API REST, capa HTTP compartida, panel web con control del bloqueador, DNS sobre TLS/HTTPS y validación DNSSEC). Cada una de esas integraciones se activa o desactiva desde `config/nano-dns.json`.

## Requisitos

- Rust estable (MSRV 1.90).
- Cargo.

## Estructura

```
crates/
  nano-dns-core/     configuración, errores, modelos, interfaces, runtime
  nano-dns/          ejecutable y ciclo de vida
  nano-dns-protocol/ UDP/TCP, DoT/DoH, validación de mensajes y control de acceso
  nano-dns-resolver/ forwarder, resolver iterativo y validador DNSSEC
  nano-dns-cache/    caché DNS en memoria y decorador de resolver
  nano-dns-blocker/  listas de dominios y reglas de filtrado
  nano-dns-storage/  persistencia SQLite
  nano-dns-stats/    estadísticas en memoria
  nano-dns-http/     servidor HTTP/1.1 mínimo compartido
  nano-dns-api/      API REST
  nano-dns-web/      panel web con control del bloqueador
config/nano-dns.json
data/lists/
data/database/
tests/
```

Los crates de fases futuras se crearán cuando tengan una implementación real, para evitar módulos vacíos.

## Uso (Fase 13)

```powershell
cargo run -p nano-dns -- --config config/nano-dns.json --check-config
```

Sin `--check-config`, el proceso valida la configuración, inicializa logging, carga las listas de bloqueo locales, abre los listeners UDP/TCP configurados y, si procede, los listeners de la API REST y del panel web; aplica las reglas de filtrado, resuelve las consultas permitidas en modo forward o recursivo, sirve las respuestas cacheadas cuando procede, escribe el historial opcional, actualiza las estadísticas en memoria y espera una señal de apagado que detiene todos los servidores a la vez. El estado del bloqueador (`blocker.enabled`) es solo el estado inicial: el panel web puede activarlo o desactivarlo en caliente, y ese cambio se mantiene únicamente en memoria hasta el reinicio.

Las consultas válidas se reenvian sin modificar a `resolver.upstreams`, primero por UDP y por TCP si la respuesta llega truncada o el upstream está marcado con `tcp: true`. Si ningún upstream responde, el cliente recibe `SERVFAIL`. Las consultas malformadas, sobredimensionadas o con más de una pregunta reciben `FORMERR`; las operaciones no soportadas reciben `NOTIMP`.

Cuando `dns_cache.enabled` es `true`, las respuestas se guardan en una caché LRU en memoria. Las consultas repetidas se sirven desde la caché sin contactar al upstream, y los TTL devueltos se reducen con el tiempo transcurrido. Las respuestas negativas usan `negative_ttl_secs`; los TTL positivos se limitan con `max_ttl_secs`. Si la caché está desactivada, el pipeline pasa las consultas directamente al forwarder.

Cuando `blocker.enabled` es `true`, las consultas se evalúan contra `denylist`, `allowlist`, listas locales y reglas por cliente antes de la resolución. El allowlist global y el de cliente tienen prioridad sobre el denylist. La respuesta se elige con `blocker.block_response`: `NXDOMAIN`, `NODATA` o `SINKHOLE` (usando `sinkhole_v4`/`sinkhole_v6`). Las listas remotas no se descargan; una fuente con esquema URL se rechaza en el arranque. El bloqueador existe aunque `blocker.enabled` sea `false`, de modo que el panel pueda activarlo en caliente. Cada cambio de reglas o de estado invalida la caché de decisiones para que la siguiente consulta use el estado nuevo.

Con `resolver.mode = "recursive"`, NanoDNS resuelve desde `resolver.root_hints` sin depender de un forwarder: sigue delegaciones NS, usa glue cuando está disponible, resuelve nombres de servidores sin glue, sigue cadenas CNAME y devuelve la respuesta autoritativa con el id original del cliente. `resolver.root_port` permite usar puertos altos en pruebas; en producción suele ser `53`. DNSSEC no se valida en modo recursivo: la combinación se rechaza con un error claro.

Con `storage.enabled = true`, NanoDNS crea el esquema en `storage.path` y registra consultas completadas. Si `storage.history = true`, cada consulta permitida o bloqueada se guarda con cliente, transporte, dominio, tipo/clase, decisión, código de respuesta y TTL. El handler solo encola un evento: un hilo escritor agrupa los registros en transacciones SQLite y el apagado graceful vacía la cola antes de terminar. Si el historial está desactivado, se crea la base de datos pero no se almacenan eventos por consulta.

Con `stats.enabled = true`, NanoDNS mantiene contadores en memoria para las consultas completadas en los últimos `stats.retention_secs`: totales, permitidas, bloqueadas, aciertos de caché, errores, distribución por código de respuesta, tipo y transporte, y los dominios más consultados. El collector usa un ring temporal protegido por un mutex; expirar entradas no requiere un hilo de limpieza. El flag `cache_hit` viaja desde la caché hasta el evento de estadísticas.

Con `api.enabled = true`, NanoDNS expone una API REST mínima en `api.listen:api.port`. El acceso se restringe por red (solo loopback si `api.allowed_networks` está vacío) y, si se configura `api.token`, mediante `Authorization: Bearer <token>`. La identidad del cliente se toma siempre del peer del socket. Los endpoints son `GET /api/v1/status` (estado y uptime), `GET /api/v1/stats` (snapshot de estadísticas; 404 si no están activadas) y `GET /api/v1/config` (configuración saneada, sin secretos). Métodos distintos de GET devuelven `405` con cabecera `Allow`.

Con `web.enabled = true`, NanoDNS sirve un panel HTML en `web.listen:web.port`. Muestra estado, uptime, modo de resolución y, si `stats.enabled` está activado, contadores y desgloses por código de respuesta, tipo, transporte y dominios más consultados. El panel muestra siempre el estado del filtro, contadores de bloqueo, reglas en memoria, listas locales cargadas y formularios para activar/desactivar el bloqueo, añadir o quitar dominios (allow/deny), vaciar reglas y recargar listas. El cambio de estado es en memoria; no se escribe en la configuración ni en SQLite. El panel es siempre loopback-only: `WebConfig` no expone lista de redes, y el peer del socket debe ser `127.0.0.0/8` o `::1/128`. Las rutas son `/` (panel), `/health` (texto plano) y, solo para `POST`, `/blocker/toggle`, `/blocker/domains` y `/blocker/reload`. Todo valor dinámico se escapa antes de renderizar y las peticiones de cambio requieren un token por proceso incluido en el formulario; sin él devuelven `403`. Si el panel se monta sin un controlador de bloqueo, los controles no se muestran y esas rutas devuelven `404`.

Con `dot.enabled = true`, NanoDNS sirve DNS sobre TLS en `dot.port` (853 por defecto) para cada listener con `dot: true`. El certificado y la clave PEM se cargan de `dot.cert_path` y `dot.key_path`. Con `doh.enabled = true`, sirve DNS sobre HTTPS (HTTP/2) en `doh.port` (443 por defecto) para cada listener con `doh: true`, usando `doh.path` como ruta de consulta y `doh.cert_path`/`doh.key_path` para TLS. En ambos casos se reutiliza el mismo handler, caché, filtrado, estadísticas y control de acceso por red que en UDP/TCP; la identidad del cliente se toma del peer del socket TLS, nunca de cabeceras. Un listener no puede pedir DoT/DoH si la sección correspondiente está desactivada, y la configuración con `enabled = true` sin certificado, clave o listener que opte por el transporte se rechaza en el arranque.

Con `resolver.dnssec = true`, NanoDNS valida las respuestas del upstream antes de servirlas: verifica DNSKEY/DS/RRSIG y las pruebas NSEC/NSEC3 de respuestas negativas siguiendo la cadena de confianza hasta las anclas raíz incluidas en Hickory, o hasta un archivo propio de anclas en `resolver.dnssec_trust_anchor` (registros DNSKEY en formato de presentación). Solo se admite junto con `resolver.mode = "forward"`. Las respuestas válidas se devuelven con el flag AD (`authentic_data`); las bogus o sin prueba de seguridad se convierten en `SERVFAIL`. La validación usa el mismo UDP/TCP del forwarder y no añade `hickory-resolver`.

> En Linux, enlazar los puertos 53, 853 o 443 puede requerir privilegios. Usa puertos altos en pruebas o ejecuta el proceso con la capacitación correspondiente.

## Activación de capacidades

No hay features de Cargo en NanoDNS: no existen `--features` ni `--no-default-features`. Todo el código se compila siempre y la configuración JSON decide qué se inicializa y qué escucha. Un mismo ejecutable sirve para todas las combinaciones; basta cambiar el JSON y reiniciar.

| Capacidad | Interruptor en JSON |
| --- | --- |
| Resolución directa | `resolver.mode = "forward"` |
| Resolución iterativa | `resolver.mode = "recursive"` (requiere `root_hints`) |
| Validación DNSSEC | `resolver.dnssec = true` (solo en modo forward) |
| Bloqueo de dominios | `blocker.enabled` (estado inicial; se puede cambiar en caliente desde la web) |
| Caché DNS | `dns_cache.enabled` |
| Caché de decisiones | `policy_cache.enabled` |
| Persistencia SQLite | `storage.enabled` |
| Estadísticas | `stats.enabled` |
| API REST | `api.enabled` |
| Panel web | `web.enabled` |
| DNS sobre TLS | `dot.enabled` (requiere certificado, clave y un listener con `dot: true`) |
| DNS sobre HTTPS | `doh.enabled` (requiere certificado, clave y un listener con `doh: true`) |

La validación sigue siendo estricta y se ejecuta antes de abrir cualquier socket: comprueba los valores de cada sección activada, que DoT/DoH tengan certificado, clave y listener, y que DNSSEC no se combine con modo recursivo. Ya no existen errores del tipo “compilado sin la feature X”. Las secciones desactivadas no asignan recursos ni enlazan puertos; por ejemplo, con `storage.enabled = false` no se abre la base de datos, y con `api.enabled = false` no se enlaza el puerto 8080.

Ejemplo: para usar solo el panel web con filtrado, deja `blocker.enabled` y `web.enabled` en `true` y mantén `storage`, `stats`, `api`, `dot` y `doh` en `false`, como en `config/nano-dns.json`. Para añadir estadísticas y SQLite, cambia esos dos interruptores a `true` y reinicia.

## Decisiones técnicas de la Fase 1

- `nano-dns-core` no depende de Hickory DNS: las librerías externas de protocolo quedan encapsuladas en crates posteriores.
- El JSON usa `deny_unknown_fields` y validación semántica completa: nunca se aplica una configuración parcialmente válida.
- Los clientes se identifican únicamente por la dirección `peer` del socket, nunca por cabeceras DNS.
- La API y la web escuchan por defecto solo en loopback.
- Las dependencias se fijan con versiones mínimas verificadas en crates.io (thiserror 2.0, serde 1.0, tokio 1.54, clap 4.6, ipnet 2.12).
- Se descartaron `axum`, `hyper`, `tower` y `askama`: el servidor HTTP propio evita esas dependencias. Todas las integraciones se compilan; su activación es solo configuración.

## Decisiones técnicas de la Fase 2

- Hickory DNS 0.26.3 implementa la codificación DNS; NanoDNS no escribe su propio parser serializador.
- `hickory-server` se compila con `default-features = false` y solo los flags `tls-ring` y `https-ring`: están disponibles para DoT/DoH, pero no se arrastran `resolver` ni SQLite.
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
- La caché no incorpora dependencias nuevas: siempre está compilada y se activa con `dns_cache.enabled`.

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

- El resolver iterativo vive en `nano-dns-resolver` y se selecciona con `resolver.mode = "recursive"`; el core sigue sin depender de Hickory.
- No se añadió `hickory-resolver`: se reutilizan `hickory-proto` y `tokio`, ya presentes, para mantener el tamaño mínimo.
- Las consultas iterativas usan `RD=0` y un id propio; la respuesta final se reescribe con el id y la pregunta originales del cliente.
- Se siguen delegaciones NS con glue de la sección adicional. Sin glue, los nombres de servidor se resuelven por A/AAAA desde las raíces, con límite de profundidad.
- Se siguen cadenas CNAME acumulando todos los registros y se detectan ciclos.
- Los límites `MAX_DEPTH` y `MAX_ITERATIONS` evitan bucles y consultas infinitas.
- UDP reintenta por TCP cuando la respuesta está truncada; los reintentos y el timeout usan la configuración existente.
- `resolver.root_port` permite probar con puertos altos sin privilegios.
- El pipeline usa un enum `UpstreamResolver` para seleccionar forwarder o recursivo sin objetos trait ni GATs complejos; la caché y el handler no cambian.
- DNSSEC no formaba parte de esta fase y se rechazaba explícitamente en la validación; la Fase 12 lo añade como capacidad activable por configuración.

## Decisiones técnicas de la Fase 7

- `nano-dns-storage` implementa el trait `Storage` del core sin depender de Hickory.
- SQLite usa `rusqlite` con SQLite empaquetado para no exigir una librería del sistema; se inicializa solo cuando `storage.enabled = true`.
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
- `/api/v1/stats` devuelve 404 cuando las estadísticas están desactivadas (`stats.enabled = false`).
- La respuesta de `/api/v1/config` es una vista saneada: nunca expone `api.token` ni rutas de certificados.
- DNS, API y web comparten un canal de apagado `watch`: una sola señal del sistema detiene todos los servidores de forma coordinada.
- Las peticiones se limitan por tamaño y tiempo de lectura; la API acepta solo `GET` y cada conexión atiende una petición. El panel web amplió después los métodos permitidos con `POST` acotado al bloqueador.

## Decisiones técnicas de la Fase 10

- La capa HTTP se extrajo a `nano-dns-http` para que API y web compartan el parser, la escritura de respuestas y el accept loop sin duplicar código ni añadir un framework.
- `HttpServer<S>` recibe un handler sobre estado compartido: cada crate decide enrutamiento, autenticación y contenido.
- `nano-dns-web` empezó como panel de solo lectura; en la Fase 13 añade mutación acotada al bloqueador, por lo que conserva la restricción loopback y añade un token por proceso para las peticiones `POST`.
- El HTML se genera en el servidor con escape de todos los valores dinámicos (nombre de instancia, dominios, transportes) para evitar inyección de markup.
- El panel reutiliza el mismo `Arc<dyn StatsSink>` que la API y el handler DNS, sin copias ni hilos adicionales.
- Las respuestas usan `Content-Type` explícito y `X-Content-Type-Options: nosniff`; una conexión atiende una petición, con `GET` para consultas y `POST` para los controles incorporados en Fase 13.

## Decisiones técnicas de la Fase 11

- DoT y DoH usan los listeners nativos de `hickory-server` (`register_tls_listener_with_tls_config` y `register_https_listener`) con ALPN `dot` y `h2` respectivamente.
- Los flags TLS/HTTPS de Hickory y la dependencia rustls están siempre disponibles; el arranque solo registra listeners TLS cuando `dot.enabled` o `doh.enabled` son `true`.
- El material PEM se carga con `rustls`: se rechazan certificados vacíos, claves ilegibles y pares certificado/clave inválidos con errores claros antes de abrir sockets.
- Hickory aplica la misma lista `allowed_networks` a UDP, TCP, DoT y DoH; la IP se toma siempre del peer del socket, nunca de cabeceras DNS ni HTTP.
- DoT y DoH reutilizan `NanoRequestHandler` sin cambios: filtrado, caché, resolver, historial SQLite y estadísticas funcionan igual en los cuatro transportes.
- Un timeout de handshake TLS acota los connection attempts lentos o maliciosos.
- Las pruebas generan certificados autofirmados en tiempo de ejecución con `rcgen` (dev-dependency) y clientes TLS reales, sin guardar claves privadas en el repositorio.
- Las pruebas usan puertos altos efímeros para no colisionar con los listeners fijos de otras suites.

## Decisiones técnicas de la Fase 12

- La validación DNSSEC se implementa en `nano-dns-resolver` y se activa con `resolver.dnssec = true`; `nano-dns-core` sigue sin depender de Hickory.
- Se reutiliza `DnssecDnsHandle` de `hickory-net` con un `DnsHandle` propio que envía los mensajes por el transporte UDP/TCP existente del forwarder.
- DNSSEC añade únicamente `hickory-net/dnssec-ring` y las utilidades de futures necesarias; el validador solo se construye cuando `resolver.dnssec = true`.
- El validador sigue la cadena de confianza completa (DNSKEY, DS, RRSIG, NSEC/NSEC3) y rechaza respuestas bogus o sin prueba de insecurity con `SERVFAIL`.
- El flag AD se activa solo cuando el resumen DNSSEC de las respuestas es `Secure`, de modo que los clientes distingan datos autenticados de datos reenviados sin validar.
- `resolver.dnssec_trust_anchor` permite sustituir las anclas raíz por un archivo DNSKEY local, útil para pruebas y despliegues aislados.
- DNSSEC solo se admite en modo forward; la combinación con recursive se rechaza en la validación de configuración.
- Las pruebas usan un stub DNSSEC firmado en un puerto alto efímero, claves Ed25519 generadas en tiempo de ejecución y anclas temporales: no se guardan claves privadas en el repositorio.

## Decisiones técnicas de la Fase 13

- `nano-dns-core` define `BlockerControl` y tipos de snapshot sin dependencias nuevas; Hickory sigue encapsulado y el core sigue sin conocerlo.
- `DomainBlocker` mantiene el flag de activación, las reglas añadidas en caliente y los contadores de bloqueo con `AtomicBool`, `RwLock` y `Mutex` estándar; no hay hilos de gestión ni asignaciones por consulta añadidas.
- El dominio y la IP del cliente siguen viniendo del peer del socket DNS; el panel solo modifica el estado compartido del filtro, nunca la identidad de las consultas.
- `blocker.enabled` es el estado inicial del bloqueador, no un interruptor de compilación: el bloqueador siempre se construye y el panel puede reactivarlo.
- Toda mutación de reglas, toggle o recarga de listas invalida la caché de decisiones, de modo que el siguiente paquete DNS observe el cambio sin reiniciar.
- Las listas siguen siendo locales: el endpoint de recarga vuelve a leer los archivos configurados y rechaza fuentes con esquema URL, sin descargas remotas.
- `nano-dns-http` admite cuerpos pequeños de formulario con `Content-Length` acotado, decodificación `application/x-www-form-urlencoded` y respuestas `303 See Other` con `Location`.
- El panel mantiene `bind()` como envoltorio compatible y añade `bind_with_blocker()`; el ejecutable conecta el mismo `Arc<dyn BlockerControl>` que usa el handler DNS.
- El toggle es solo en memoria: no se escribe en `config/nano-dns.json` ni en la base de datos opcional, y se pierde al reiniciar.
- Las rutas de mutación conservan la restricción loopback y requieren un token aleatorio por proceso renderizado en el HTML; las peticiones sin token se rechazan con `403`.
- El HTML sigue escapando todos los valores dinámicos, incluidos dominios y nombres de listas gestionados desde la web.
- Las pruebas cubren el cambio de comportamiento DNS en caliente, el body HTTP real, el token CSRF, las rutas sin bloqueador y el rechazo por peer no loopback, usando puertos altos efímeros.

## Verificación

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo run -p nano-dns -- --config config/nano-dns.json --check-config
```

No hay matrices de features que verificar: una sola combinación de compilación cubre todas las capacidades. Los tests de integración de DoT/DoH, DNSSEC, recursivo, SQLite y estadísticas se ejecutan siempre con `cargo test --workspace`.

## Licencia

MIT. Ver [LICENSE](LICENSE).
