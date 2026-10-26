# Phase 04 — Final Acceptance

Fecha: 2026-10-26 (America/Managua)
HEAD auditado: `d6bf8bc79a367d14001278b8eb3afb4a380e8316`
Resultado: **PASS — alcance educativo local**

## 1. Alcance 04.01–04.06.3

Phase 04 entrega una arquitectura de inteligencia de vulnerabilidades que separa
transporte, contratos de proveedor, normalización canónica, interpretación y API.
El alcance aceptado comprende:

- 04.01: integración NVD CVE 2.0, contratos, provenance y cliente HTTP seguro;
- 04.01.1: hardening de streaming, límites decodificados y lifecycle HTTP;
- 04.02: interpretación CVSS/CWE/CPE y aplicabilidad con lógica trivaluada;
- 04.03: catálogo CISA KEV, snapshot inmutable, freshness y lookup prudente;
- 04.04: FIRST EPSS, precisión Decimal, fecha/frescura y cache TTL/LRU;
- 04.05: correlación unificada NVD/KEV/EPSS con fallos parciales;
- 04.06: auditoría integral de seguridad, concurrencia y semántica;
- 04.06.1: ownership y cancelación de tareas coalescidas EPSS;
- 04.06.2: autorización atómica de cache commit EPSS;
- 04.06.3: ownership service-owned y lock scope del refresh KEV.

No forman parte de este alcance scanning activo, exploit execution, patching,
persistencia distribuida, scoring combinado, detección de malware validada ni
MITRE ATT&CK de Phase 05.

## 2. Arquitectura final

Los clientes NVD, CISA KEV y FIRST EPSS usan endpoints HTTPS fijos, TLS
verificado, redirects desactivados, `trust_env=False`, streaming acotado,
deadlines totales, retries finitos, límites de concurrencia y cierre determinista
de respuestas.

FastAPI no publica JSON crudo de proveedor. Los datos pasan por esquemas de
proveedor, validación semántica y modelos canónicos estrictos. La correlación
consulta NVD y EPSS concurrentemente y lee KEV desde el snapshot validado, sin
provocar descargas por lookup.

EPSS mantiene una operación por CVE con ownership de consumidores. KEV mantiene
un refresh service-owned por store. Ambos registran y recolectan explícitamente
sus tasks, aplican cleanup por identidad y mantienen I/O fuera de locks de estado.

## 3. Contratos y semántica científica

NVD conserva identidad CVE, descripciones, CVSS 2.0/3.0/3.1/4.0, CWE,
configuraciones CPE recursivas, referencias, timestamps, estado y provenance.

La aplicabilidad CPE usa TRUE/FALSE/UNKNOWN, AND/OR/NOT, rangos y límites
explícitos. Una coincidencia indica aplicabilidad potencial de criterios
publicados; no confirma que un activo sea vulnerable.

KEV distingue listed, not-listed y not-established según snapshot y freshness.
Una inclusión es evidencia de explotación conocida publicada por CISA, no prueba
de compromiso del entorno evaluado.

EPSS conserva probabilidad, percentile, score date, precision Decimal y
freshness. Es una predicción fechada, no prueba de explotación ni severidad.
Score cero es distinto de ausencia de score.

La correlación conserva evidencia independiente y estados complete, partial y
unavailable. No calcula un score combinado ni transforma fallos de proveedor en
evidencia negativa o inventada.

## 4. Garantías asíncronas verificadas

- un consumidor EPSS cancelado no destruye trabajo compartido por otro;
- el último consumidor retira, cancela y recolecta la operación EPSS;
- una operación EPSS retirada no publica ni sobrescribe a su sucesor;
- shutdown impide late cache commits y drena antes del cierre HTTP;
- un consumidor KEV cancelado no destruye el refresh service-owned;
- refreshes KEV concurrentes comparten un único task y fetch;
- `_refresh_lock` no se mantiene durante red, backoff, parsing o validación;
- un candidato KEV solo se promueve si el task vigente sigue autorizado;
- shutdown KEV retira autorización, cancela y recolecta fuera del lock;
- lookups KEV leen el snapshot activo sin bloquear por refresh ni iniciar I/O.

La cancelación de asyncio es cooperativa. Una coroutine que ignore cancelación
indefinidamente puede retrasar shutdown, aunque los fences impiden que recupere
autorización para publicar estado compartido.

## 5. Hallazgos cerrados

| Hallazgo | Severidad | Resultado independiente |
|---|---|---|
| P04-SEC-001 — EPSS orphaned coalesced tasks | High | FIXED |
| P04-SEC-006 — EPSS stale cache commit | Medium | FIXED |
| P04-SEC-007 — KEV lock durante provider I/O | Medium | FIXED |

### P04-SEC-001

La reproducción final observó cancelación del proveedor al retirarse el último
waiter, `_inflight` vacío, capacidad liberada y cero tasks pendientes. El
coalescing continuó protegiendo consumidores activos.

### P04-SEC-006

Una operación antigua devolvió `0.000010000` después de que su sucesor publicara
`0.999990000`. El valor final permaneció `0.999990000`; la antigua carecía de
autorización. Un sucesor fallido dejó cache vacía y tampoco reautorizó al
predecesor.

### P04-SEC-007

Con el proveedor suspendido por una barrera, el lock pudo adquirirse desde otra
tarea. Dos consumidores compartieron una llamada, lookup leyó el snapshot activo
y el lifecycle terminó con `_refresh_task=None` y cero tasks pendientes.

## 6. Evidencia de validación

La revisión final ejecutó 25 pruebas focalizadas con `PYTHONASYNCIODEBUG=1` y
warnings tratados como errores: 25/25 PASS.

El Quality Gate completo produjo:

| Control | Resultado |
|---|---|
| Tests | 706/706 PASS |
| Cobertura statement/branch | 93.37% |
| Ruff lint | PASS |
| Ruff format | PASS — 116 archivos |
| mypy strict | PASS — 97 archivos |
| `pip check` | PASS |
| Quality Gate | PASS |

Las pruebas son offline y deterministas. La aceptación no depende de llamadas
live a NVD, CISA o FIRST.

## 7. Integridad de proveedores y API

Se revalidaron Health, Static Analysis, ML demo, NVD lookup, interpretación
CVSS/CWE, aplicabilidad CPE, KEV status/lookup, EPSS lookup y Unified GET/POST.
OpenAPI mantiene contratos tipados y errores sanitizados.

Los fallos de red, timeout, rate limit, respuesta inválida y ausencia de datos
permanecen diferenciados. Los límites de tamaño se aplican a bytes decodificados,
incluida expansión gzip, y los streams se cierran tras éxito, error o cancelación.

## 8. Limitaciones residuales

- autenticación y autorización no implementadas;
- rate limiting, caches y snapshots process-local;
- refresh KEV explícito, sin coordinación distribuida;
- sin persistencia obligatoria ni lockfile de dependencias;
- dependencia operativa de proveedores externos;
- digest KEV demuestra integridad de bytes, no firma/autenticidad del contenido;
- metadata de paquete y aplicación todavía `0.1.0`;
- cancelación cooperativa no puede detener forzosamente una coroutine hostil.

Estas limitaciones no invalidan el alcance educativo local, pero sí impiden
presentar el sistema como listo para producción pública.

## 9. Readiness

**Local Educational Release:** READY WITH CONDITIONS.

Las funciones y garantías de Phase 04 están aceptadas. El despliegue debe
mantenerse local/controlado, con configuración explícita y sin afirmar garantías
de producción distribuida.

**Public Production:** NOT READY.

Se requieren, como mínimo, identidad y autorización, controles distribuidos,
operación durable del catálogo, estrategia de dependencias reproducible y
hardening de despliegue.

## 10. Decisión de release v0.4.0

`v0.4.0` queda **RECOMENDADO CON PRERREQUISITOS**, no autorizado para creación
inmediata por esta auditoría:

1. actualizar `apps/api/pyproject.toml:7` de `0.1.0` a `0.4.0`;
2. actualizar el default `APP_VERSION` en `apps/api/app/core/config.py:27` y las
   expectativas relacionadas;
3. commitear este documento y la actualización final del informe;
4. repetir el Quality Gate desde un working tree limpio;
5. crear el tag solo si `main`, `origin/main`, metadata y evidencia coinciden.

La ausencia de lockfile debe permanecer documentada como riesgo de
reproducibilidad aunque no bloquea esta aceptación educativa.

## 11. Decisión final y siguiente fase

Phase 04 queda **ACCEPTADA** para su alcance educativo local. P04-SEC-001,
P04-SEC-006 y P04-SEC-007 están cerrados con reproducción independiente y no se
identificó otro defecto bloqueante sustentado.

Phase 05 no fue iniciada. Su inicio requiere una decisión separada después del
handoff de release de Phase 04.
