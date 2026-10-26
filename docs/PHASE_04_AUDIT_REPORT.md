# Phase 04 / Checkpoint 04.06 — Informe de auditoría integral

Fecha de auditoría: 2026-10-25 (America/Managua)  
Repositorio: `C:\icylens`  
Backend: `C:\icylens\apps\api`  
HEAD auditado: `76007208ea0e3c50cc5d35b9b0ba87793dc038c0`  
Decisión original 04.06: **BLOCKED**  
Resultado de remediación 04.06.1: **PASS — apto para reauditoría de aceptación**
Reauditoría final 2026-10-26: **BLOCKED — P04-SEC-006 abierto**
Resultado de remediación 04.06.2: **PASS — apto para reauditoría independiente**
Reauditoría final independiente 2026-10-26: **BLOCKED — P04-SEC-007 abierto**
Resultado de remediación 04.06.3: **PASS — apto para reauditoría independiente**

## A. Resumen ejecutivo

Phase 04 implementa correctamente la mayor parte de los contratos de NVD, CISA
KEV, FIRST EPSS, interpretación CVSS/CWE/CPE y correlación unificada. La
procedencia se conserva, la identidad CVE se vuelve a validar dentro de los
servicios, los fallos parciales no fabrican evidencia y los clientes HTTP usan
HTTPS fijo, TLS verificado, streaming decodificado acotado, deadlines y cierre de
respuestas. El Quality Gate pasa con 685 pruebas y 93.28% de cobertura combinada
de statements/branches.

La auditoría original no aceptó la fase. Una prueba adversarial que ensambló el correlador
real con el servicio EPSS real demostró que la cancelación o el deadline del
correlador no cancela la tarea interna creada para coalescing. La tarea queda viva
en `_inflight` y el proveedor no recibe la cancelación. Solicitudes canceladas
para CVEs diferentes pueden acumular tareas detrás del semáforo del cliente EPSS.
El test existente de fan-out no detectó el defecto porque sustituía todo el
servicio EPSS por un stub. Checkpoint 04.06.1 corrigió posteriormente la propiedad
de la tarea compartida y añadió la prueba de integración real; la evidencia
original se conserva en este informe y el cierre se registra en la sección Q.

Además, el `main` auditado no está sincronizado con el remoto: el remoto real
`origin/main` apunta a `32bf955c...` y el HEAD local está seis commits por delante.
No debe crearse `v0.4.0` hasta completar 04.06.1, volver a auditar, registrar los
documentos finales y sincronizar el remoto.

## B. Integridad del repositorio y de la release

| Control | Resultado | Evidencia |
|---|---|---|
| Rama | PASS | `main` |
| HEAD | Registrado | `76007208ea0e3c50cc5d35b9b0ba87793dc038c0` |
| Working tree inicial | PASS | Limpio antes de crear este informe |
| Sincronización remota | FAIL | `git status`: ahead 6; `git ls-remote origin refs/heads/main`: `32bf955c...` |
| Tags | PASS informativo | `v0.1.0`, `v0.2.0`, `v0.3.0`; no existe `v0.4.0` |
| `git diff --check` inicial | PASS | Sin errores |
| Checkpoints 04.01–04.05 | Presentes | Cinco aceptaciones y la revisión 04.01.1 |
| Static Analysis / ML | Sin cambios accidentales | El diff `origin/main..HEAD` de 04.05 no toca esos motores |

Los 29 commits de Phase 04 desde `v0.3.0` cubren contratos, implementación,
pruebas y documentación de 04.01 a 04.05. Los seis commits locales no publicados
corresponden a 04.05.

La versión distribuible tampoco tiene una única identidad: `pyproject.toml`, el
valor por defecto de `Settings.APP_VERSION` y `.env.example` permanecen en
`0.1.0`, aunque el tag objetivo es `v0.4.0`. Esto no cambia los datos de
vulnerabilidades, pero debe resolverse o documentarse como política antes de la
release para evitar que `/health` y OpenAPI anuncien una versión distinta.

## C. Arquitectura y trazabilidad de Phase 04

| Checkpoint | Componentes y contrato | Pruebas principales | Documentación | Resultado |
|---|---|---|---|---|
| 04.01 | `integrations/nvd`, normalización, CVSS/CWE/CPE, GET base | `test_nvd_integration.py`, fixtures NVD | `NVD_INTEGRATION.md`, aceptación 04.01 | PASS |
| 04.01.1 | Streaming real, bytes decodificados, deadline, `trust_env=False`, metadata | Streams instrumentados, gzip/deflate, longitud engañosa, cancelación | revisión 04.01.1 | PASS |
| 04.02 | CVSS/CWE/CPE, comparadores y lógica trivalente recursiva | `test_vulnerability_interpretation.py` | `CVSS_CWE_CPE_INTERPRETATION.md`, `CPE_APPLICABILITY_ENGINE.md` | PASS |
| 04.03 | Cliente KEV, snapshot inmutable, promoción atómica, frescura y lookup | `test_kev_integration.py` | `CISA_KEV_INTEGRATION.md`, `KEV_CATALOG_LIFECYCLE.md` | PASS |
| 04.04 | Cliente EPSS, Decimal, frescura, TTL/LRU y coalescing | `test_epss_integration.py` | `FIRST_EPSS_INTEGRATION.md`, `EPSS_SCORE_SEMANTICS.md` | CONDITIONAL |
| 04.05 | Correlación exacta, fan-out, estados, evidencia, GET/POST y límites | `test_unified_vulnerability_intelligence.py` | `UNIFIED_VULNERABILITY_INTELLIGENCE.md`, `EVIDENCE_CORRELATION_POLICY.md` | FAIL por integración de cancelación 04.04↔04.05 |

Flujo GET verificado:

1. FastAPI valida el path y el correlador vuelve a ejecutar `normalize_cve_id`.
2. `CorrelationCapacity.try_acquire` aplica admisión local sin cola.
3. El correlador consulta el snapshot KEV y crea tareas NVD y EPSS concurrentes.
4. NVD valida nuevamente el CVE, consulta un host/path fijo y normaliza un único
   registro cuya identidad debe coincidir.
5. El intérprete conserva todas las métricas CVSS y los registros CWE.
6. KEV resuelve exclusivamente por clave CVE en el snapshot activo.
7. EPSS usa una caché por CVE, valida la identidad devuelta y mantiene score,
   percentil y fecha separados.
8. El correlador vuelve a comprobar identidades y consistencia de presencia.
9. Las afirmaciones apuntan a campos reconstruibles de `sources`,
   `interpretation` o `applicability`.
10. Pydantic/FastAPI serializan el contrato estricto.
11. La ruta devuelve 200 para complete/partial y una taxonomía 429/502/503/504
    cuando ninguna fuente resuelve.

No se encontró una ruta por la cual evidencia de una CVE se atribuya a otra. Las
validaciones no dependen únicamente de la capa HTTP.

## D. Integraciones de proveedores

### NVD

El endpoint está fijado a `https://services.nvd.nist.gov/rest/json/cves/2.0`.
Se rechazan cambios de scheme, host, port, path, query, fragment y credenciales.
El cliente configura verificación TLS, `follow_redirects=False` y
`trust_env=False`; transmite la API key solo al host fijo. Usa `stream=True`,
cuenta bytes producidos por `aiter_bytes` después de la decodificación, no confía
en `Content-Length`, cierra la respuesta en `finally`, limita concurrencia y
presupuesto, y acota retry/backoff/`Retry-After` dentro de un deadline total.
Valida metadata de punto, versión 2.0, timestamps e identidad CVE.

### CISA KEV

La fuente canónica HTTPS está fijada. Se verifican schema, count, máximo de
entradas, duplicados, fechas contradictorias, release futura y profundidad JSON.
La promoción ocurre solo después de construir un snapshot completo inmutable;
un refresh fallido no sustituye el último snapshot válido. Refreshes concurrentes
se coalescen por lock y los lookups no refrescan. Una ausencia solo se declara
`not_listed` con snapshot fresco; con snapshot stale es `not_established`. Las
fechas y acciones de CISA se presentan explícitamente como referencias publicadas,
no obligaciones legales universales.

### FIRST EPSS

El endpoint de punto oficial está fijado y protegido con las mismas garantías
HTTP que NVD. Scores y percentiles usan `Decimal`, conservan precisión, deben
estar en `[0,1]` y rechazan NaN/Infinity. Score cero se distingue de ausencia de
score. Fecha, frescura y versión API son separadas; `model_version` es nullable.
La caché TTL/LRU es acotada y los fallos no se cachean. La identidad CVE se valida
en cliente, normalización y correlación. La salvedad bloqueante es el ciclo de
vida de la tarea coalescida descrito en P04-SEC-001.

## E. Corrección semántica

CVSS 2.0, 3.0, 3.1 y 4.0 se conservan junto con source/type, score opcional,
vector y métricas auxiliares. La severidad publicada no se reemplaza: se deriva
un campo separado solo cuando existe base score, con rangos propios de v2 frente
a v3/v4, y se marca consistencia. La selección de display es determinista o
explícitamente ambigua. CVSS no se convierte en probabilidad ni risk score.

CWE conserva identificador/descripción, idioma, source y type. Reconoce
`NVD-CWE-noinfo`, `NVD-CWE-Other`, valores desconocidos y múltiples registros sin
inventar nombres ni mappings ATT&CK.

El parser CPE 2.3 soporta el subconjunto declarado, escapes y valores lógicos;
rechaza conservadoramente wildcards embebidos o sintaxis no soportada. Los
comparadores numérico y SemVer solo operan cuando el esquema lo permite. AND,
OR y NOT aplican tablas de verdad de tres valores; UNKNOWN no se reduce a boolean.
`vulnerable=false` se trata como plataforma requerida, no como negación. La raíz
de configuraciones múltiples es OR. Profundidad, nodos, condiciones, inventario,
longitud CPE y tiempo cooperativo tienen límites.

Los doce casos adversariales requeridos están cubiertos por las pruebas de
interpretación: versión ausente/dentro/fuera de rango; plataforma ausente con
inventario completo/incompleto; identidad insuficiente; unsupported bajo NOT,
OR y AND; profundidad excesiva; `vulnerable=false`; y configuraciones
alternativas. Ninguno produjo confirmación de vulnerabilidad.

## F. Seguridad HTTP, recursos y concurrencia

| Límite | Implementación observada |
|---|---|
| Upload | `MAX_UPLOAD_BYTES`, lectura incremental |
| POST inventory | `VULNERABILITY_MAX_INVENTORY_BODY_BYTES`, stream y validación estricta |
| Items/CPE | 256 productos, CPE máximo 4096, versiones 256 |
| Árbol | profundidad 16, 512 nodos, 2048 condiciones, deadline cooperativo 0.25 s |
| NVD/KEV/EPSS | bytes decodificados, semáforos, timeouts, deadlines y retries acotados |
| Correlación | admisión 8 por defecto, deadline 60 s, respuesta máxima 2 MiB |
| EPSS cache | TTL 3600 s, LRU 1024 entradas |

Los límites de evaluación Python son cooperativos; no equivalen a un límite duro
de CPU o memoria del proceso. Los rate limits y semáforos son por proceso, no
distribuidos. La respuesta unificada se construye primero y después se mide, por
lo que el máximo serializado es una condición de rechazo, no un límite duro de
memoria durante construcción.

Streaming, gzip/deflate, `Content-Length` falso, cierre temprano, espera de
capacidad, backoff, cancelación y liberación de semáforos tienen pruebas
instrumentadas en los clientes. No se ejecutó estrés contra proveedores reales.
La prueba adicional de integración real correlador↔servicio EPSS falló, como se
detalla en P04-SEC-001.

## G. Fallos parciales

Matriz ejecutada por las suites existentes y revisión directa:

| NVD | KEV | EPSS | Resultado esperado/observado |
|---|---|---|---|
| available | listed/not_listed/not_established | available/not_scored | complete |
| not_found | estado KEV resuelto | estado EPSS resuelto | complete |
| unavailable/invalid/timeout/rate_limited | resuelto | resuelto | partial |
| resuelto | never_loaded/unavailable | resuelto | partial |
| resuelto | resuelto | unavailable/invalid/timeout/rate_limited | partial |
| dos fuentes fallan | una resuelve | cualquiera | partial; conserva evidencia restante |
| todas fallan | never_loaded/unavailable | todas fallan | unavailable; sin evidencia |

`not_found`, `not_listed`, `not_established` y `not_scored` son resultados
tipados, no fallos corruptos. `not_established` no genera evidencia negativa KEV.
Una respuesta inválida nunca genera afirmación positiva o negativa. Los tests
parametrizados cubren fallos simultáneos homogéneos; no enumeran el producto
cartesiano completo, pero las ramas de resolución son independientes y se
verificaron combinaciones de una, dos y tres fuentes fallidas.

## H. API y OpenAPI

Se verificaron estas rutas:

- `GET /api/v1/vulnerabilities/{cve_id}`
- `GET /api/v1/vulnerabilities/{cve_id}/interpretation`
- `POST /api/v1/vulnerabilities/{cve_id}/applicability`
- `GET /api/v1/intelligence/kev/status`
- `GET /api/v1/intelligence/kev/{cve_id}`
- `GET /api/v1/intelligence/epss/{cve_id}`
- `GET /api/v1/intelligence/vulnerabilities/{cve_id}`
- `POST /api/v1/intelligence/vulnerabilities/{cve_id}/assessment`

OpenAPI contiene las ocho rutas con métodos y response models esperados. Las
pruebas FastAPI cubren GET completo, POST con inventario, body inválido/oversize,
paths manipulados, fallos parciales y errores sanitizados. El lifespan crea una
instancia compartida por cliente/servicio y cierra los tres clientes al terminar.
No se observaron secretos en respuestas ni mensajes de proveedor sin sanitizar.

## I. Frontera de autenticación y despliegue

Todas las rutas son públicas y no tienen autenticación ni autorización. Las
rutas de Phase 04 son de lectura respecto de los proveedores y snapshots; el POST
recibe inventario declarado y no lo persiste, pero ese inventario puede ser
sensible en un despliegue real. Existen validación, límites de tamaño, deadlines,
admisión local y rate limiting local. Faltan autenticación, autorización, TLS del
despliegue/ingress, rate limiting distribuido, cuotas por identidad, controles de
privacidad y observabilidad operacional multi-instancia.

Por ello el backend puede evaluarse como educativo/local una vez corregido
P04-SEC-001, pero no está listo para exposición pública en Internet.

## J. Validez científica

Los contratos y documentos distinguen CVE publicada, severidad CVSS, debilidad
CWE, aplicabilidad potencial CPE, inclusión KEV y predicción EPSS. No se encontró
conversión de CVSS a probabilidad, inferencia ATT&CK desde CWE, uso de KEV como
prueba de compromiso, uso de CPE como observación directa, ni score de riesgo
combinado. La demo ML sintética permanece separada y no participa en la
correlación. EPSS histórico/stale conserva fecha y frescura y no se presenta como
current; percentile se explica como ranking, no probabilidad.

## K. Reproducibilidad, dependencias y Quality Gate

Entorno auditado: Python 3.13.17, pip 26.2.2. `pyproject.toml` admite Python
`>=3.12,<3.14`, separa dependencias runtime/dev y fija rangos mayores, pero no
existe lockfile ni requirements con hashes. El entorno concreto incluyó FastAPI
0.162.0, httpx 0.28.1, Pydantic 2.14.1, pytest 9.1.1, Ruff 0.17.2 y mypy 1.20.2.
La ausencia de lock impide reconstrucción exacta a partir del repositorio.

Resultado de `apps/api/scripts/quality_gate.py`:

| Etapa | Resultado |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 116 archivos |
| mypy strict | PASS — 97 archivos fuente |
| pytest | PASS — 685/685 |
| cobertura statements/branches | PASS — 93.28% (4969 stmts, 1132 branches) |
| `pip check` | PASS |
| Quality Gate | PASS |

El baseline esperado coincide exactamente. El PASS del gate no revoca el
hallazgo adversarial fuera de la suite.

## L. Registro de hallazgos

### P04-SEC-001 — Tareas EPSS sobreviven a la cancelación del correlador

- Severity: **Medium (bloqueante)**.
- Clase: defecto confirmado; aislamiento de fallos y agotamiento de recursos.
- Componentes: coalescing EPSS y fan-out unificado.
- Ubicación: `app/services/epss_intelligence.py:71-75,77-93` y
  `app/services/vulnerability_correlation.py:127-139`.
- Descripción: `lookup` crea `_fetch_and_cache` y espera con `asyncio.shield`.
  Al cancelar `_resolve_epss`, el task interno no se cancela. El correlador sí
  espera la cancelación de su wrapper y libera capacidad, aunque la operación
  EPSS continúa y queda registrada en `_inflight`.
- Evidencia reproducida: con correlador real, `EPSSIntelligenceService` real,
  proveedor bloqueante y deadline de 0.01 s se obtuvo
  `CorrelationDeadlineError`, `provider_cancelled=False`, `inflight_count=1`,
  `pending_tasks=1` y la coroutine pendiente
  `EPSSIntelligenceService._fetch_and_cache`.
- Impacto: cancelaciones/deadlines repetidos con CVEs diferentes pueden liberar
  capacidad del correlador mientras acumulan tareas EPSS esperando el semáforo.
  El cliente limita HTTP concurrente, pero no el número de tasks `_inflight`.
- Reproducción: crear un proveedor EPSS que espere un `Event`, montar el servicio
  EPSS real en `VulnerabilityCorrelationService`, forzar deadline o cancelar el
  request y enumerar `asyncio.all_tasks()`/`_inflight`.
- Corrección propuesta: introducir ownership/refcount de waiters para cada tarea
  coalescida; cancelar y drenar la tarea upstream cuando desaparezca el último
  waiter; acotar también el número total de entradas inflight; cancelar y drenar
  inflight durante shutdown. Debe conservarse coalescing cuando aún exista otro
  waiter legítimo.
- Test requerido: integrar correlador y servicio EPSS reales; cubrir deadline y
  cancelación externa, un waiter cancelado con otro activo, muchos CVEs distintos,
  `_inflight` vacío, proveedor cancelado, respuesta cerrada y cero tasks huérfanos.
- Estado: **FIXED en 04.06.1; requiere aceptación final independiente**.

### P04-REL-002 — HEAD de 04.05 no está publicado en `origin/main`

- Severity: **Medium (bloqueante de release, no defecto de runtime)**.
- Clase: integridad de release.
- Ubicación: estado Git; commits `08c7f87..7600720`.
- Evidencia: `main...origin/main [ahead 6]`; `git ls-remote` confirmó que el
  remoto sigue en `32bf955c`.
- Impacto: un tag creado desde otro checkout o desde el remoto omitiría 04.05.
- Corrección propuesta: después de remediar y revisar, registrar los artefactos y
  publicar `main` según el flujo autorizado antes del tag.
- Test requerido: comparar `git rev-parse HEAD` con `git ls-remote origin
  refs/heads/main`.
- Estado: **OPEN**.

### P04-REL-003 — Identidad de versión de aplicación permanece en 0.1.0

- Severity: **Low**.
- Clase: defecto de metadata/release.
- Ubicación: `apps/api/pyproject.toml:7`, `app/core/config.py:27` y
  `apps/api/.env.example:2`.
- Evidencia: los tres valores son `0.1.0`; la release objetivo es `v0.4.0`.
- Impacto: paquete, OpenAPI y health pueden anunciar una versión distinta al tag.
- Corrección propuesta: definir una fuente de versión y política; actualizarla a
  0.4.0 como paso explícito de release si el tag representa la versión API/app.
- Test requerido: coherencia entre metadata, settings, health/OpenAPI y tag.
- Estado: **OPEN**.

### P04-REP-004 — No existe lockfile reproducible

- Severity: **Low**.
- Clase: riesgo residual conocido.
- Ubicación: `apps/api/pyproject.toml`; ausencia de lockfile.
- Evidencia: dependencias con rangos; búsqueda de `uv.lock`, `poetry.lock`,
  `Pipfile.lock` y `requirements*.txt` sin resultados.
- Impacto: instalaciones futuras dentro de los rangos pueden resolver versiones
  diferentes a las auditadas.
- Corrección propuesta: adoptar en un checkpoint separado el mecanismo de lock y
  hashes compatible con la política global; no cambiar versiones por preferencia.
- Test requerido: instalación limpia reproducible y Quality Gate.
- Estado: **ACCEPTED RESIDUAL RISK para desarrollo; pendiente de política**.

### P04-DEPLOY-005 — Boundary local sin controles de identidad

- Severity: **Info** para el alcance educativo local; **High exposure risk** si
  se publica sin una capa adicional.
- Clase: limitación explícita, no regresión de Phase 04.
- Ubicación: routers FastAPI y documentación de arquitectura.
- Evidencia: ninguna dependencia de autenticación/autorización; controles de
  capacidad y rate limit exclusivamente por proceso.
- Impacto: abuso anónimo, falta de cuotas distribuidas y exposición de inventario.
- Corrección propuesta: gateway/ingress autenticado, autorización, TLS,
  rate limiting distribuido, cuotas, política de datos y observabilidad antes de
  cualquier despliegue público.
- Test requerido: suite de controles de despliegue y pruebas multi-instancia.
- Estado: **LIMITACIÓN ABIERTA; bloquea producción pública**.

## M. Decisiones de aceptación originales (04.06)

| Área | Decisión | Motivo |
|---|---|---|
| A. Backend functionality | CONDITIONAL | Funciones correctas salvo lifecycle EPSS cancelado |
| B. Provider contract fidelity | PASS | Identidad, schema, precisión y procedencia verificadas |
| C. HTTP and resource security | FAIL | Acumulación de tareas inflight tras cancelación |
| D. CPE semantic safety | PASS | Lógica trivalente conservadora y límites verificados |
| E. Evidence correlation integrity | PASS | Evidencia exacta, reconstruible y sin score combinado |
| F. Test sufficiency | CONDITIONAL | Amplia cobertura; falta integración real de cancelación |
| G. Local educational readiness | BLOCKED | Requiere corregir P04-SEC-001 |
| H. Public production readiness | NOT READY | Sin auth/distributed controls y con finding abierto |
| I. Phase 04 final acceptance | **BLOCKED** | Finding Medium afecta aislamiento de recursos |

## N. Plan de remediación 04.06.1

El checkpoint correctivo debe limitarse a:

1. corregir ownership, cancelación, drenaje y límite de tareas inflight EPSS;
2. añadir los tests de integración y alta concurrencia local indicados;
3. revisar shutdown y cierre de respuestas con tareas coalescidas;
4. ejecutar el Quality Gate sin reducir umbrales;
5. resolver la identidad 0.4.0 según una política explícita;
6. crear `PHASE_04_ACCEPTANCE.md` solo si la reauditoría no encuentra bloqueos;
7. registrar documentos, sincronizar `origin/main` y verificar repositorio limpio.

No se recomienda ampliar funcionalidad ni iniciar Phase 05 dentro de 04.06.1.

## O. Recomendación de release y handoff

**No crear `v0.4.0` todavía.** No se creó ningún tag, rama, commit ni push. En
esta auditoría solo se añadió este informe; deliberadamente no se creó
`docs/PHASE_04_ACCEPTANCE.md` porque la fase está bloqueada.

Tras cerrar 04.06.1 y obtener reauditoría PASS, los comandos Git sugeridos —para
ejecución humana y no ejecutados aquí— son:

```powershell
git status --short --branch
git diff --check
git add docs/PHASE_04_AUDIT_REPORT.md docs/PHASE_04_ACCEPTANCE.md <archivos-remediados>
git commit -m "fix(intelligence): close phase 04 cancellation audit findings"
git push origin main
git ls-remote origin refs/heads/main
git tag -a v0.4.0 -m "iCYLENS Phase 04 — Vulnerability Intelligence"
git push origin v0.4.0
```

La lista `<archivos-remediados>` debe reemplazarse por rutas revisadas; no debe
copiarse literalmente.

## P. Siguiente fase

Phase 05 — Behavioral Analysis & MITRE ATT&CK permanece en roadmap. No debe
iniciarse automáticamente ni usarse para cerrar los hallazgos de Phase 04.

## Q. Reauditoría del correctivo 04.06.1

La causa fue la ausencia de ownership de consumidores: `_inflight` almacenaba
solo el `Task`, y `asyncio.shield()` protegía correctamente a consumidores
concurrentes pero no informaba al servicio cuando el último consumidor salía.
El único cleanup dependía de la finalización de una operación que podía seguir
esperando semáforo, backoff o I/O.

El correctivo introduce una operación por CVE con `task`, `active_waiters` y
`cancellation_requested`. Cada lookup registra exactamente un waiter y lo libera
en `finally`. La salida de un waiter conserva el task mientras existan otros; la
salida del último retira condicionalmente la misma operación del registro,
cancela el task si continúa activo y lo recolecta con `gather`. El task conserva
cleanup condicional por identidad, por lo que una operación antigua no puede
eliminar su reemplazo. `EPSSIntelligenceService.aclose()` cierra el registro,
cancela y recolecta todas las operaciones antes de que el lifespan cierre HTTP.
El lock solo protege cache/registro/contadores y nunca se mantiene durante I/O o
espera del task.

La reproducción que originalmente mostró
`provider_cancelled=False`, `_inflight=1`, `pending_tasks=1` ahora muestra:

```text
CorrelationDeadlineError
provider_cancelled=True
inflight_count=0
pending_tasks=0
pending_coroutines=[]
```

Ocho pruebas offline nuevas cubren deadline del correlador; un waiter cancelado
con otro activo; todos los waiters cancelados; CVEs distintos con el semáforo
HTTP saturado; rejoin durante cancelación; carrera de completion; shutdown del
lifespan; y error de proveedor cercano a cancelación. Verifican cancelación del
proveedor, contadores, registro vacío, cache sin resultados incompletos,
semáforo reutilizable, stream cerrado y ausencia de tasks pendientes.

Quality Gate posterior: 693/693 tests, 93.29% de cobertura combinada,
Ruff lint/format PASS, mypy strict PASS sobre 97 archivos, `pip check` PASS y
Quality Gate PASS. NVD, KEV, CVSS/CWE/CPE, correlación, Static Analysis y ML no
fueron modificados funcionalmente.

P04-SEC-001 queda **FIXED** con evidencia de comportamiento, no solo por el PASS
del test. Checkpoint 04.06.1 obtiene **PASS**. Puede repetirse la aceptación final
independiente de Phase 04. Continúan abiertos y fuera de este correctivo la
sincronización con `origin/main`, la identidad de versión 0.1.0, el riesgo de
reproducibilidad sin lockfile y la frontera de despliegue público sin identidad.

## R. Reauditoría final independiente posterior a 04.06.1

Fecha: 2026-10-26 (America/Managua)
HEAD: `91838a73c943df32535c5162623928c09d09503f`
Resultado: **BLOCKED**

### R.1 Estado Git y baseline

La reauditoría comenzó con working tree limpio, rama `main`, HEAD idéntico al
`origin/main` remoto y sin commits pendientes de push. Los commits del correctivo
estaban presentes:

- `cee74ba fix(epss): enforce waiter-owned coalesced task lifecycle`;
- `6f16738 test(epss): prove cancellation coalescing and shutdown safety`;
- `91838a7 docs(audit): record phase 04 async lifecycle remediation`.

Los tags seguían siendo `v0.1.0`, `v0.2.0` y `v0.3.0`; no existía `v0.4.0`.
No había cambios no relacionados.

El Quality Gate completo volvió a pasar: 693/693 tests, 93.29% de cobertura
combinada, Ruff lint/format PASS, mypy strict PASS sobre 97 archivos, `pip check`
PASS y Quality Gate PASS. `git diff --check` también pasó antes de registrar esta
actualización documental.

### R.2 Reproducción independiente de P04-SEC-001

Se repitió el escenario original ensamblando el correlador real, el servicio EPSS
real y un proveedor bloqueante. El deadline produjo:

```text
CorrelationDeadlineError
provider_cancelled=True
inflight_count=0
pending_tasks=0
pending_coroutines=[]
```

La inspección usó `asyncio.all_tasks()`, no solo contadores internos. La capacidad
quedó reutilizable. Las ocho pruebas deterministas A–H se ejecutaron nuevamente y
pasaron: un waiter cancelado no detuvo al segundo; el último waiter canceló y
recolectó; completion/error races no dejaron excepciones; cinco CVEs saturando el
semáforo liberaron capacidad y cerraron el stream; y shutdown drenó antes de
cerrar HTTP.

Conclusión: **P04-SEC-001 FIXED** respecto de tareas huérfanas, registro inflight,
propagación de cancelación, coalescing con consumidores activos y shutdown.

### R.3 Ownership y shutdown

`_InFlightOperation` hace explícitos task, waiters y cancelación solicitada. El
registro y los contadores se modifican bajo un único lock; el lock no se mantiene
durante I/O, espera de semáforo, espera del task ni cierre HTTP. Cada lookup
incrementa una vez y libera en `finally`; no se observaron decrementos dobles ni
negativos. `aclose()` marca el servicio cerrado, retira, cancela y recolecta sus
tasks antes de `epss_client.aclose()`. El correlador continúa siendo dueño de sus
wrappers NVD/EPSS y los cancela/recolecta juntos.

### R.4 Hallazgo nuevo P04-SEC-006 — Resultado abandonado puede sobrescribir cache nueva

- Severidad: **Medium (bloqueante)**.
- Clase: defecto confirmado de integridad de cache/evidencia y carrera de
  lifecycle.
- Componente: `EPSSIntelligenceService`.
- Archivo y línea: `apps/api/app/services/epss_intelligence.py:122-134`, en
  particular la escritura incondicional de cache en 126-133.
- Evidencia: `_release_waiter` retira y marca cancelada la operación antigua, pero
  `_fetch_and_cache` no verifica ownership ni `cancellation_requested` antes de
  escribir. Si el coroutine proveedor observa y suprime `CancelledError`, puede
  completar después de que una operación nueva para la misma CVE ya fue cacheada.
- Reproducción offline determinista: el primer fetch quedó bloqueado, recibió
  cancelación y la retuvo; un segundo fetch devolvió el fixture high y guardó
  `0.999990000`; al liberar el fetch antiguo, este devolvió el fixture low y
  sobrescribió la cache con `0.000010000`.

```text
new_score_before_old_finishes=0.999990000
first_outcome=CancelledError
cached_score_after_old_finishes=0.000010000
provider_calls=2
inflight_count=0
pending_tasks=0
```

- Impacto: una operación sin consumidores puede reemplazar evidencia EPSS más
  reciente obtenida por la operación actualmente válida. Una consulta posterior
  recibe el resultado tardío hasta que expire el TTL. La identidad CVE no se
  cruza, pero la precedencia temporal y la integridad del cache sí se rompen.
- Alcance real: el cliente FIRST actual propaga `CancelledError`; la reproducción
  exige un coroutine que retrase/suprima cancelación. Aun así, la garantía pedida
  era que una operación abandonada no pudiera hacer late commit, y el servicio no
  debe depender de la disciplina interna del proveedor para proteger su cache.
- Corrección requerida: antes del cache write, comprobar bajo `_lock` que
  `_inflight[cve_id]` sigue siendo exactamente la operación/task actual y que no
  tiene cancelación solicitada. Una operación retirada o reemplazada puede
  devolver/terminar para permitir su recolección, pero no debe publicar cache.
  Puede implementarse pasando la operación/generación al runner o comprobando la
  identidad del task actual contra el registro.
- Test propuesto: proveedor cancelation-resistant con dos generaciones para la
  misma CVE; la nueva devuelve high, la abandonada termina después con low; la
  cache final debe conservar high, con `_inflight` vacío, ambos tasks recolectados
  y ninguna excepción sin recuperar. Añadir variante durante shutdown.
- Estado: **OPEN — requiere checkpoint correctivo acotado 04.06.2**.

### R.5 Cache, correlación y seguridad de proveedores

Fuera de P04-SEC-006, TTL/LRU, Decimal, score date, freshness, identidad CVE,
errores no cacheados y coalescing normal permanecen correctos. El fan-out conserva
complete/partial/unavailable, errores tipados, evidencia válida de otras fuentes,
ausencia de score combinado y aplicabilidad nula sin inventario/UNKNOWN
conservador con inventario.

La suite completa volvió a verificar las protecciones NVD 04.01.1 (HTTPS fijo,
redirects, `trust_env=False`, streaming, límites decodificados, metadata,
deadlines y cancelación), snapshots KEV inmutables/promoción atómica/frescura sin
refresh de lookup, y transporte FIRST con límites, timeout, backoff, cierre y
semáforo. No se realizaron llamadas a proveedores reales.

Los límites científicos permanecen intactos: CVSS es gravedad; CWE clasifica
debilidades; CPE expresa aplicabilidad potencial; KEV es inclusión en catálogo;
EPSS es predicción fechada; y ML sintético no es detección validada. No se infiere
compromiso ni explotación observada.

### R.6 Readiness y decisión final

| Dimensión | Decisión |
|---|---|
| P04-SEC-001 | FIXED |
| P04-SEC-006 | OPEN — Medium bloqueante |
| Educational Local Readiness | BLOCKED hasta 04.06.2 |
| Public Production Readiness | NOT READY |
| Phase 04 final acceptance | BLOCKED |
| Release `v0.4.0` | NO RECOMENDADA |

La producción pública continúa además impedida por ausencia de autenticación y
autorización, rate limiting/caches/snapshots por proceso, ausencia de lockfile,
metadata de aplicación `0.1.0` y dependencia de proveedores externos. Esas
limitaciones son distintas del bloqueo funcional de cache.

No se crea `docs/PHASE_04_ACCEPTANCE.md`. Se recomienda un checkpoint 04.06.2
limitado a impedir late cache commits de operaciones retiradas, añadir la prueba
adversarial indicada y repetir esta aceptación. Phase 05 no fue iniciada.

## S. Remediación 04.06.2 — autorización atómica de cache commit

Fecha: 2026-10-26 (America/Managua)
HEAD base: `91838a73c943df32535c5162623928c09d09503f`
Resultado del checkpoint: **PASS**

P04-SEC-006 se originaba porque `_fetch_and_cache` conservaba autorización
implícita para publicar desde que comenzaba el fetch. Retirar la operación del
registro y llamar `task.cancel()` impedía que borrara el registro sucesor, pero no
impedía la escritura incondicional de cache si el coroutine proveedor suprimía la
cancelación y retornaba tarde.

El correctivo separa explícitamente lifecycle de autorización. El lifecycle aún
lo controlan waiters, retiro, cancelación y recolección de 04.06.1. La publicación
ahora pasa por `_commit_if_authorized`, que bajo el mismo `_lock` exige:

1. servicio abierto;
2. entrada vigente para la CVE;
3. identidad exacta entre el task actual y el task registrado;
4. operación sin `cancellation_requested`;
5. resultado ya validado y normalizado.

La comprobación y el cache write/orden LRU ocurren en una única sección crítica
sin `await` interno. El lock no cubre HTTP, parsing, backoff, semaphore wait,
espera de consumidores ni recolección. Una operación retirada puede finalizar
para poder recolectarse, pero su resultado queda aislado del estado compartido.

La reproducción original posterior al fix produjo:

```text
new_result=0.999990000
old_result=0.000010000
cached_score=0.999990000
retired_result_committed=False
first_outcome=CancelledError
inflight_count=0
pending_tasks=0
```

También se verificó que una operación retirada no publica cuando aún no existe
sucesor, no actúa como fallback si el sucesor falla, y no publica después de
iniciar shutdown. Permanecen pasando las pruebas de same-CVE multi-consumer,
último consumidor, completion race, CVEs distintas, TTL/LRU y frescura.

El Quality Gate posterior pasó con 697/697 pruebas y 93.30% de cobertura
statement/branch; Ruff lint/format PASS, mypy strict PASS sobre 97 archivos,
`pip check` PASS y `git diff --check` PASS. No se modificaron contratos públicos,
semántica Decimal/fecha/frescura, NVD, KEV, CVSS/CWE/CPE, correlación, Static
Analysis ni ML.

La revisión de write paths relacionados no confirmó otro defecto equivalente.
KEV serializa el fetch, validación y promoción completa bajo `_refresh_lock`; no
crea tasks separados y una cancelación libera el context manager. Por ello dos
refreshes no pueden promover fuera de orden dentro de un store. El correlador
cancela y recolecta explícitamente sus tasks hermanos.

P04-SEC-006 queda **FIXED** con fencing por identidad y evidencia adversarial.
Checkpoint 04.06.2 obtiene **PASS**. Debe realizarse otra reauditoría final
independiente antes de crear `PHASE_04_ACCEPTANCE.md` o recomendar `v0.4.0`.
Phase 05 no fue iniciada.

## T. Auditoría final independiente posterior a 04.06.2

Fecha: 2026-10-26 (America/Managua)
HEAD: `67da4239d738456469358a884b1d0098feb1a770`
Resultado: **BLOCKED**

### T.1 Git y baseline

La auditoría comenzó con working tree limpio en `main`. `HEAD` y `origin/main`
coincidían en `67da4239d738456469358a884b1d0098feb1a770`; por tanto, a diferencia de
reauditorías anteriores, los commits de 04.06.1 y 04.06.2 sí estaban publicados
en el remoto configurado. Se verificaron los seis commits de código, pruebas y
documentación:

- `cee74ba`, `6f16738`, `91838a7` para 04.06.1;
- `e561ea1`, `81c0382`, `67da423` para 04.06.2.

Los únicos tags existentes eran `v0.1.0`, `v0.2.0` y `v0.3.0`. No existía
`v0.4.0` ni `docs/PHASE_04_ACCEPTANCE.md`.

El Quality Gate ejecutado desde `apps/api` pasó sin reducir umbrales: Ruff lint
PASS, Ruff format PASS sobre 116 archivos, mypy strict PASS sobre 97 archivos,
697/697 tests PASS, cobertura statement/branch 93.30%, `pip check` PASS y Quality
Gate PASS. Una selección adicional de 16 pruebas de concurrencia se ejecutó con
`PYTHONASYNCIODEBUG=1` y warnings tratados como errores: 16/16 PASS.

### T.2 P04-SEC-001 — resultado independiente

**FIXED.** Cada lookup EPSS registra un consumidor exactamente una vez y lo
libera en `finally`. `asyncio.shield()` evita que la cancelación de un consumidor
se propague al fetch compartido mientras existe otro consumidor. El último
consumidor marca retiro, cancela, elimina por identidad y recolecta el task fuera
del lock. El cleanup del runner también elimina únicamente su propia operación.
El shutdown retira, cancela y recolecta antes de cerrar el cliente HTTP.

Un arnés independiente con `asyncio.Event` confirmó:

```text
un consumidor cancelado: active_waiters=1, provider_cancels=0
dos consumidores abandonando: provider_cancels=1
cache=0, inflight=0, pending_tasks=0
deadline corto + consumidor largo: timeout / score=0.999990000
provider_cancels=0, pending_tasks=0
```

El escenario original del deadline del correlador también pasó: el fan-out
cancela y recolecta sus wrappers, el último waiter retira el fetch EPSS y no
quedan tasks huérfanos ni capacidad retenida. No se observaron contadores
negativos, dobles liberaciones ni excepciones no recuperadas.

Límite explícito: la cancelación de asyncio es cooperativa. Si un proveedor
suprime `CancelledError` indefinidamente, el caller que está recolectando y el
shutdown pueden esperar indefinidamente; Python no ofrece terminación forzada
segura del coroutine. El fencing evita que ese coroutine publique, pero no puede
hacer que se detenga instantáneamente.

### T.3 P04-SEC-006 — resultado independiente

**FIXED.** `_commit_if_authorized` comprueba, bajo el mismo lock usado por el
registro, que el servicio sigue abierto, la operación continúa registrada, el
task actual es exactamente el task vigente y no existe retiro solicitado. La
comprobación, escritura, actualización LRU y eviction son una sola sección
crítica sin puntos de suspensión internos. El cleanup posterior se mantiene
condicionado por identidad y no puede borrar al sucesor.

La carrera original fue reproducida sin usar FIRST real:

```text
successor_score=0.999990000
cache_before_old_finishes=0.999990000
cache_after_old_finishes=0.999990000
old_outcome=CancelledError
provider_calls=2
inflight=0
pending_tasks=0
```

También se confirmó que una operación retirada sin sucesor no publica, que no se
usa como fallback si falla el sucesor, y que shutdown impide tanto su late commit
como nuevos lookups. Errores y cancelaciones no se guardan como evidencia.

### T.4 Auditoría conjunta A–O

| Escenario | Evidencia determinista | Resultado |
|---|---|---|
| A. Un consumidor cancelado y otro activo | Dos waiters, cancelación del primero, barrera del proveedor | PASS |
| B. Último consumidor cancelado sin sucesor | Cancelación observada, cache/registro vacíos | PASS |
| C. Último cancelado con sucesor inmediato | Dos generaciones y retiro por identidad | PASS |
| D. Antigua termina durante publicación nueva | High antes y después de liberar old | PASS |
| E. Antigua suprime `CancelledError` | Proveedor resistente controlado por eventos | PASS |
| F. Dos consumidores abandonan simultáneamente | Una cancelación de proveedor, cero tasks pendientes | PASS |
| G. Timeout global durante completion | Timeout del correlador y completion race | PASS |
| H. Shutdown con operación retirada | Registro retirado, late commit rechazado | PASS |
| I. Shutdown con operación vigente | Task cancelado/recolectado; nuevo lookup rechazado | PASS |
| J. Sucesor falla tras retirar antigua | Fallo tipado, cache vacía, antigua no revive | PASS |
| K. Varias CVEs compiten por capacidad | Semáforo saturado y luego totalmente liberado | PASS |
| L. TTL/LRU con reemplazo | Expiración, score nuevo y eviction acotada | PASS |
| M. Misma CVE con deadlines distintos | Corto expira; largo conserva fetch y resultado | PASS |
| N. CVEs diferentes | Dos identidades y scores sin contaminación | PASS |
| O. Excepción simultánea a cancelación | Error consumido/propagado, sin cache ni task | PASS |

Los escenarios usan events, barreras y Futures de las pruebas; los sleeps se
limitan a ceder control al event loop o activar un deadline explícito. No hubo
stress ni llamadas live contra FIRST.

### T.5 Integridad de cache y lifecycle

Se comprobaron los doce invariantes solicitados. Una operación retirada no
publica con o sin sucesor; una operación vigente solo recibe un resultado después
de validación y normalización; una generación antigua no sobrescribe ni elimina
la entrada posterior; errores y cancelaciones no producen entradas; score cero
permanece distinto de `None`; `Decimal`, fecha, provenance y recálculo de
frescura se preservan; las CVEs no se mezclan; LRU mantiene el límite; y `_closed`
impide publicaciones y lookups nuevos.

La propiedad de tasks está explícita en EPSS y en el fan-out del correlador. Los
waiters se contabilizan bajo lock, las tareas retiradas no se reutilizan y las
esperas de `gather` ocurren fuera del lock EPSS. No se observaron tasks huérfanos
con `asyncio.all_tasks()`.

### T.6 Hallazgo P04-SEC-007 — lock KEV mantenido durante I/O

- **ID:** P04-SEC-007.
- **Severidad:** Medium; bloqueante por la regla dura de aceptación.
- **Archivo y línea:** `apps/api/app/intelligence/kev_catalog.py:133-140`.
- **Evidencia:** `KEVCatalogStore.refresh()` entra en `_refresh_lock` en la línea
  135 y ejecuta `await client.fetch_catalog()` en la línea 139 sin liberar el
  lock. La operación incluye red, retries, backoff, espera de semáforo y lectura
  streaming del catálogo.
- **Reproducción:** un fetcher bloqueado por `asyncio.Event` dejó
  `store._refresh_lock.locked() == True`; un segundo refresh permaneció pendiente
  y no pudo progresar hasta liberar el primer I/O. Después de la barrera ambos
  recibieron el mismo snapshot y no quedaron tasks pendientes.
- **Impacto:** head-of-line blocking entre refreshes y acoplamiento de la
  exclusión de estado a la latencia/fallo del proveedor. El cliente actual posee
  deadline total, y los lookups leen el snapshot sin tomar este lock, por lo que
  no se confirmó corrupción, stale write ni indisponibilidad de consultas. Aun
  así, contradice expresamente el requisito «no locks durante I/O».
- **Corrección recomendada:** separar el fetch de la sección crítica y usar una
  operación de refresh explícitamente poseída/coalescida o una generación. Solo
  la autorización y promoción del candidato validado deben ocurrir bajo el lock;
  una operación antigua no debe poder reemplazar un snapshot posterior.
- **Estado:** OPEN.
- **Test asociado requerido:** barrera que pruebe que el lock de estado está
  libre durante el fetch, coalescing de refreshes, cancelación del único/todos los
  consumidores, promoción por generación, refresh fallido y shutdown.

No se confirmó otro stale write o task sin propietario. NVD no crea tasks de
background; EPSS y correlación recolectan los suyos; no existen callbacks de
cleanup. La promoción KEV sigue siendo validada, inmutable y ordenada, pero su
estrategia de exclusión incumple el criterio indicado.

### T.7 Regresión semántica, proveedores y API

La suite completa revalidó contratos CVE/NVD, CVSS 2.0/3.0/3.1/4.0, CWE,
CPE AND/OR/NOT, lógica trivaluada, rangos de versión, KEV, EPSS y correlación
unificada. Se conservaron provenance, estados complete/partial/unavailable y
aplicabilidad opcional. No existe score combinado. EPSS no se presenta como
prueba de explotación, CPE no confirma vulnerabilidad y el ML sintético continúa
marcado como demostración no validada.

NVD, CISA KEV y FIRST EPSS mantienen endpoints HTTPS allowlisted, TLS verificado,
redirects desactivados, `trust_env=False`, retries/deadlines acotados, límites de
respuesta decodificada, cierre de streams, límites de concurrencia y errores
sanitizados. La corrección EPSS no debilitó los clientes externos. Health, Static
Analysis, ML demo, endpoints NVD/CVSS/CWE/CPE/KEV/EPSS, Unified GET/POST, OpenAPI
y taxonomía de errores pasaron offline.

### T.8 Findings, readiness y release

| Hallazgo | Estado |
|---|---|
| P04-SEC-001 — ownership/cancelación EPSS | FIXED |
| P04-SEC-006 — late cache commit EPSS | FIXED |
| P04-SEC-007 — lock KEV durante I/O | OPEN — bloqueante |

**Educational Local Readiness:** READY WITH CONDITIONS. Las rutas educativas y
los contratos funcionan y el gate es reproducible, pero no debe declararse la
aceptación final de Phase 04 hasta cerrar P04-SEC-007.

**Public Production Readiness:** NOT READY. Además del hallazgo abierto, faltan
autenticación/autorización, rate limiting distribuido, caches compartidas,
orquestación externa de refresh KEV y lockfile reproducible. La metadata sigue en
`0.1.0` tanto en `apps/api/pyproject.toml:7` como en
`apps/api/app/core/config.py:27`; debe corregirse de forma controlada antes de un
eventual tag `v0.4.0`.

Decisión final: **BLOCKED**. No se crea `docs/PHASE_04_ACCEPTANCE.md`; no se
recomienda ni crea `v0.4.0`. El único archivo modificado por esta auditoría es el
presente informe; no se modificó ni eliminó código funcional. Phase 05 no fue
iniciada.

## U. Remediación 04.06.3 — lifecycle y lock scope de refresh KEV

Fecha: 2026-10-26 (America/Managua)
HEAD base: `67da4239d738456469358a884b1d0098feb1a770`
Resultado del checkpoint: **PASS**

P04-SEC-007 se originaba en `KEVCatalogStore.refresh()`: `_refresh_lock`
serializaba correctamente la promoción, pero también permanecía adquirido durante
`client.fetch_catalog()` y `build_snapshot()`. Por tanto cubría HTTP, streaming,
retries, backoff, parsing y validación, aunque solo las decisiones sobre la
operación vigente y el snapshot compartido requerían exclusión mutua.

El correctivo adopta ownership explícito por el servicio. El store registra como
máximo un `_refresh_task`; consumidores concurrentes esperan el mismo task con
`asyncio.shield()`. Cancelar un consumidor no cancela el refresh compartido. El
store supervisa el resultado, consume excepciones terminales y `aclose()` retira,
cancela y recolecta la tarea antes de cerrar el cliente HTTP.

El lock queda limitado a cinco transiciones breves:

1. rechazar refresh después de cierre;
2. localizar o registrar la operación activa;
3. comprobar identidad, cierre y cancelación antes de publicar;
4. validar precedencia contra el snapshot activo y promover atómicamente;
5. retirar por identidad la operación terminada.

El fetch, streaming, backoff, parsing, `build_snapshot()`, espera de consumidores
y drain de shutdown ocurren fuera del lock. `lookup()` continúa leyendo el
snapshot inmutable sin esperar al refresh ni iniciar I/O.

La autorización de commit exige store abierto, task actual idéntico al registrado
y ausencia de `task.cancelling()`. La comprobación, protección contra digest
contradictorio/rollback y asignación del snapshot ocurren en la misma sección
crítica sin `await` interno. Una prueba adversarial descubrió durante el desarrollo
que una cancelación solicitada inmediatamente después de validar podía no
suspenderse al adquirir un lock libre; la comprobación explícita de
`task.cancelling()` cerró esa carrera antes del gate final.

La reproducción independiente del defecto original ahora produce:

```text
lock_held_during_provider_wait=False
provider_calls_before_release=1
second_done_before_release=False
provider_calls_total=1
same_snapshot=True
refresh_task=None
pending_tasks=0
```

Nueve pruebas nuevas verifican lock libre durante I/O, dos consumidores/un fetch,
cancelación de uno y del único consumidor bajo ownership del servicio, fallo
coalescido, respuesta inválida coalescida, cancelación durante validación,
shutdown con proveedor resistente a cancelación, shutdown antes de promoción,
lookup durante refresh, cleanup y cancelación durante backoff. Las pruebas
existentes siguen cubriendo snapshot inválido, conflicto de digest, rollback,
freshness, stale positive/negative, never-loaded, límites, transporte y API.

El Quality Gate final pasó con 706/706 pruebas y 93.37% de cobertura combinada;
Ruff lint/format PASS sobre 116 archivos, mypy strict PASS sobre 97 archivos,
`pip check` PASS y Quality Gate PASS. El targeted gate KEV pasó con asyncio debug
y warnings tratados como errores.

P04-SEC-007 queda **FIXED**. Riesgos residuales: el refresh y snapshot continúan
siendo process-local; el digest prueba integridad de bytes, no autenticidad del
proveedor; y una coroutine que suprima cancelación indefinidamente puede retrasar
shutdown aunque ya no conserve autorización para publicar.

Checkpoint 04.06.3 obtiene **PASS** y queda apto para reauditoría final
independiente. No se crea `PHASE_04_ACCEPTANCE.md`, no se recomienda aún
`v0.4.0`, y Phase 05 no fue iniciada.
