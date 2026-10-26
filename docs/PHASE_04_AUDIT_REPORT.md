# Phase 04 / Checkpoint 04.06 — Informe de auditoría integral

Fecha de auditoría: 2026-10-25 (America/Managua)  
Repositorio: `C:\icylens`  
Backend: `C:\icylens\apps\api`  
HEAD auditado: `76007208ea0e3c50cc5d35b9b0ba87793dc038c0`  
Decisión original 04.06: **BLOCKED**  
Resultado de remediación 04.06.1: **PASS — apto para reauditoría de aceptación**

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
