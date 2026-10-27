# Phase 05 / Checkpoint 05.07 — Informe de auditoría integral

Fecha: 2026-10-26 (America/Managua)

Repositorio: `C:\icylens`

Backend: `C:\icylens\apps\api`

Rama: `main`

HEAD y `origin/main`: `8fbfbd3d917e445a0d53404865d960cdbe7d985a`

Veredicto: **BLOCKED**

## A. Resumen ejecutivo

Phase 05 implementa una arquitectura mayormente conservadora y bien tipada para
catálogo ATT&CK, telemetría declarada/sintética, doce reglas descriptivas,
correlación temporal no causal, mapping candidato y análisis unificado. La
revisión confirmó determinismo, separación entre PID e identidad de proceso,
preservación de procedencia, estados de incertidumbre, límites de cardinalidad,
ausencia de ejecución de payloads y fronteras científicas explícitas. El Quality
Gate coincide exactamente con el baseline: 892 pruebas, 94.43% de cobertura,
Ruff, formato, mypy strict y `pip check` en PASS.

La fase no se acepta porque pruebas independientes, fuera de los happy paths del
gate, confirmaron cuatro defectos materiales:

1. el loader confía en un campo de SHA-256 dentro del propio snapshot, pero no
   autentica los bytes ni el contenido que consume; una técnica alterada cargó
   conservando el digest oficial declarado;
2. un wheel construido desde un `git archive` limpio omite por completo el
   snapshot `enterprise-attack-19.2.json.gz`, por lo que la distribución instalada
   no contiene el catálogo central de 05.01;
3. los threads que sobreviven a timeout/cancelación quedan bajo una tarea de
   cleanup no registrada; una cancelación de shutdown antes de su primer ciclo
   pierde la supervisión y deja el contador de capacidad inconsistente;
4. el endpoint de reglas devuelve valores sensibles originales aun cuando los
   marca como `redacted=true`; además devuelve endpoints de red sin redacción.

Estos defectos afectan integridad de evidencia, reproducibilidad del artefacto,
ownership de workers y privacidad. El PASS del gate no los invalida. Conforme al
criterio del checkpoint, se crea únicamente este informe y se define 05.07.1; no
se crea `PHASE_05_ACCEPTANCE.md`.

## B. Integridad del repositorio

| Control | Resultado | Evidencia |
|---|---|---|
| Rama | PASS | `main` |
| HEAD | Registrado | `8fbfbd3d917e445a0d53404865d960cdbe7d985a` |
| `origin/main` | PASS | Coincide exactamente con HEAD |
| Working tree inicial | CONDITIONAL | Solo `?? apps/api/app/attack/__init__.py`, preexistente |
| `git diff --check` | PASS | Sin errores |
| Tags | CONDITIONAL | `v0.4.0` es el último; metadata declara `0.4.1`; no existe `v0.4.1` |
| Checkpoints 05.01–05.06 | PASS | 37 commits desde `v0.4.0`, incluyendo recovery 0.4.1 y contratos, implementación, API, tests y documentación de Phase 05 |
| Dependencias | CONDITIONAL | Rangos en `pyproject.toml`; no existe lockfile con resolución/hash reproducible |

La metadata `0.4.1` es coherente entre `pyproject.toml`, `Settings`, `.env.example`,
health/OpenAPI y tests. La ausencia del tag `v0.4.1` es una deuda de trazabilidad
de release; no se movió ni creó ningún tag durante la auditoría.

### Estado de `app/attack/__init__.py`

- Contenido: un docstring, `"""MITRE ATT&CK offline knowledge foundation."""`.
- Es un archivo legítimo de paquete Python y se ejecuta implícitamente al importar
  `app.attack.catalog`; no existe un import explícito de símbolos desde él.
- No está seguido por Git ni ignorado.
- El build limpio descubre `app.attack` como namespace package y contiene
  `app/attack/catalog.py` aunque falte el archivo; por ello el import no depende
  funcionalmente del `__init__.py` actual.
- Su ausencia en un clone limpio cambia la semántica de paquete regular a
  namespace y omite el docstring, pero no fue la causa del fallo distribuible.
- No se borró ni se incorporó. Antes de la release debe elegirse y probarse una
  política explícita: paquete regular con archivo seguido, o namespace deliberado.

El fallo reproducible de instalación es distinto: el wheel limpio no contiene
`app/attack/data/enterprise-attack-19.2.json.gz`.

## C. Arquitectura y trazabilidad de Phase 05

| Checkpoint | Componentes | Garantía revisada | Pruebas principales | Decisión |
|---|---|---|---|---|
| 05.01 | `app/attack/catalog.py`, schemas, knowledge service y rutas | STIX 2.1, 19.2, catálogo inmutable, objetos retirados, relaciones, API read-only | `test_attack_knowledge.py` y reproducciones de digest/wheel | **BLOCKED** |
| 05.02 | `schemas/behavior.py`, validation, generator y rutas | unions discriminadas, identidad, procedencia, límites, generación offline | `test_behavioral_telemetry.py` | PASS |
| 05.03 | registry, 12 reglas, rule engine y API | evaluación determinista, cuatro estados, evidencia acotada | `test_behavioral_rules.py` | CONDITIONAL por privacidad de respuesta |
| 05.04 | identidad, policy, correlation, evidence graph y API | UTC, orden canónico, relaciones weak/strong, no causalidad | `test_behavioral_temporal_correlation.py` | PASS |
| 05.05 | tres policies, registry, mapping service y API | evidencia backend, suficiencia, candidatos no confirmados | `test_attack_behavioral_mapping.py` | CONDITIONAL por dependencia del catálogo |
| 05.06 | schemas, orchestration, dos endpoints y descriptor | pipeline único, parciales, deadlines, capacidad, minimización | `test_unified_behavioral_analysis.py` y prueba adversarial de shutdown | **BLOCKED** |

Flujo efectivo de `POST /api/v1/behavior/analyze`:

1. middleware limita el body a 512 KiB;
2. Pydantic aplica contrato estricto y unions discriminadas;
3. la ruta crea un servicio sobre el store ATT&CK cargado;
4. `BehavioralAnalysisCapacity` admite hasta cuatro operaciones sin cola;
5. el pipeline síncrono corre en `asyncio.to_thread`;
6. el backend vuelve a validar el batch;
7. ejecuta una vez reglas y correlación;
8. `evaluate_trusted` recibe exclusivamente esos resultados backend en el flujo
   efectivo y resuelve el catálogo;
9. se construye una respuesta minimizada, sin payloads de evento crudos;
10. se mide el resultado serializado contra 1 MiB.

`POST /api/v1/behavior/scenarios/analyze` añade generación determinista y reutiliza
la validación inmutable producida por el generador. Su body está limitado a 64 KiB
y el número de eventos a 100.

No hay campo HTTP que permita suministrar findings, graph, mappings, provenance
backend o detecciones confirmadas. `AttackMappingRequest` solo acepta batch,
policy IDs y policy temporal. `evaluate_trusted` sí es una API Python pública del
servicio, pero sus dos call sites reales reciben motores internos; no se aceptó
el nombre del método como prueba y se siguió el flujo de datos completo.

## D. Catálogo ATT&CK

La constante fija Enterprise ATT&CK `19.2`, dominio `enterprise-attack`, URL
versionada y SHA-256 de fuente
`dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
El snapshot comprimido del checkout mide 1,541,193 bytes y su SHA-256 de archivo
es `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`.

La carga offline produjo 26,086 objetos, 15 tácticas, 858 técnicas, 493
subtécnicas, 21,262 relaciones, 697 técnicas activas y 161 retiradas. IDs STIX,
external IDs, dominio, tácticas, plataformas, referencias, duplicados, endpoints
de relaciones, tamaños, profundidad y cardinalidades se validan. Los objetos
retirados se excluyen por defecto de la API y el mapping nunca convierte un
objeto retirado en candidato.

Se identificaron exactamente las 16 subtécnicas revocadas sin relación histórica
`subtechnique-of`: `T1053.001`, `T1070.001`, `T1070.002`, `T1547.011`,
`T1562.001`, `T1562.002`, `T1562.003`, `T1562.004`, `T1562.006`, `T1562.007`,
`T1562.008`, `T1562.009`, `T1562.010`, `T1562.011`, `T1562.012` y `T1562.013`.
El fallback exige simultáneamente marker de subtécnica, `revoked=true`, external
ID con punto y padre presente en el bundle. Ninguna subtécnica activa carece de
la relación oficial, por lo que el fallback no alcanza objetos activos.

Las policies resuelven objetos activos: `AMP-CONF-001 → T1053.005`,
`AMP-NET-001 → T1071.001` y `AMP-PROC-001 → T1059`. No hay consulta MITRE por
request.

No obstante, `load_snapshot()` solo comprueba que `provenance.source_digest`
contenga el valor fijado. Una copia donde se cambió el nombre de `T1059` a
`TAMPERED EDUCATIONAL NAME`, manteniendo conteos y procedencia, cargó con éxito y
siguió declarando el digest oficial. Por tanto, el SHA prueba el bundle durante
`build_snapshot_from_stix`, pero no la integridad del artefacto consumido en
runtime. Véase P05-SEC-001.

## E. Telemetría de comportamiento

Los cuatro eventos usan unions discriminadas, UUIDs, timestamps timezone-aware,
host ID, source y provenance. `ProcessIdentity` combina UUID de instancia, PID y
`started_at`; PID solo no correlaciona procesos y el reuse está probado. IPv4,
IPv6 y puertos se validan. Los eventos sintéticos retienen naturaleza, source,
seed, scenario ID, plataforma y tiempos deterministas.

La validación distingue estructura de consistencia semántica. Duplicados,
orden inverso, parent/child contradictorio, host conflictivo, lifecycle
incompleto y transiciones file/network ausentes se reportan sin inventar eventos.
La ausencia de create, attempt, termination o parent dentro del batch se formula
como ausencia en ese lote, no como prueba de que nunca ocurrió.

Rutas, command lines, registry targets y valores son datos. No se pasan a shell,
filesystem, registry, socket ni HTTP. La generación tampoco realiza I/O,
persistencia ni herramientas de ataque reales.

Límites efectivos: 256 eventos declarados, 100 sintéticos, 32 KiB serializados
por evento, 512 KiB por batch, 64 KiB para request sintético, profundidad de
attributes 4, 64 items y strings generales acotadas. Un evento puede ser
estructuralmente válido y aun producir issues semánticos; el unificado devuelve
`partial` y omite motores posteriores cuando existe un error bloqueante.

## F. Motor de reglas

| Rule ID | Versión | Familia | Condición resumida | Evidencia mínima | Estados/limitación principal |
|---|---|---|---|---|---|
| BR-CONF-001 | 1.0.0 | configuration | cambio declarado | action, kind, target | Hecho administrativo, no malicia |
| BR-CONF-002 | 1.0.0 | configuration | scheduled task sin previo y con actual | kind, presencia previous/current | Creación declarada solamente |
| BR-CONF-003 | 1.0.0 | configuration | service con previo y actual | kind, presencia previous/current | Modificación no inherentemente maliciosa |
| BR-FILE-001 | 1.0.0 | file | modify después de create same-host/path | action, host, path | Orden dentro del batch solamente |
| BR-FILE-002 | 1.0.0 | file | rename con process o hash ausente | action, destination, presencia metadata | Ausencia puede ser normal |
| BR-FILE-003 | 1.0.0 | file | operación sin process identity | action, path, presencia process | La fuente puede no atribuir proceso |
| BR-NET-001 | 1.0.0 | network | attempt sin estado posterior conocido | action y tuple de conexión | El estado puede estar fuera del batch |
| BR-NET-002 | 1.0.0 | network | established sin process identity | action, remote endpoint, presencia process | Fuente network-only |
| BR-NET-003 | 1.0.0 | network | TCP hacia puerto 443 | protocol, remote port | Tráfico común, no ataque |
| BR-PROC-001 | 1.0.0 | process | start sin parent declarado | action, instance ID, parent | Ausencia de contexto, no sospecha |
| BR-PROC-002 | 1.0.0 | process | parent declarado que no precede child | started_at de ambos | Clock/source pueden explicar condición |
| BR-PROC-003 | 1.0.0 | process | start con command line presente | action, presencia y longitud | No interpreta ni devuelve el texto |

Todas están versionadas, habilitadas y ordenadas en un registry inmutable. El
engine conserva `matched`, `not_matched`, `insufficient_evidence` y
`not_applicable`; una familia ausente o regla disabled no se convierte en false.
La regla de parent incompleto usa `insufficient_evidence` cuando no puede resolver
la condición. Los missing fields no producen matches por contenido textual.
TCP/443, scheduled tasks, service changes y command lines están descritos como
condiciones declaradas, no ataques.

La evidencia está acotada a ocho eventos por finding, doce fields por evidencia,
32 reglas/findings y 256 KiB de respuesta. El defecto de privacidad de los valores
de evidencia se documenta en P05-PRIV-004.

## G. Correlación temporal

Los timestamps event/observed/received son timezone-aware y se normalizan a UTC.
El orden canónico usa tiempo e identidad estable; reordenar input no cambia la
semántica. Timestamps iguales producen relación indeterminada/presentación, nunca
precedencia estricta. La proximidad se etiqueta como no causal.

Las relaciones de lifecycle y same-process exigen UUID de instancia y host, no
PID. Parent-child requiere identidad explícita, parent presente y mismo host.
Paths iguales solo producen identidad file declarada weak y no cruzan hosts. La
tuple network requiere host, endpoints, protocolo y proceso; continúa weak y se
acota por ventana. El graph contiene exactamente nodos de eventos suministrados,
no eventos inferidos.

Los bounds son 1,024 edges, 16 relaciones por evento, 128 secuencias, 64 eventos
por secuencia, ocho facts por evidencia, 512 issues, 512 KiB de salida y deadline
cooperativo de un segundo. La construcción puede consumir memoria antes de medir
el JSON final; el límite de respuesta es fail-closed, no un hard memory cap.

## H. Mapping ATT&CK

Las tres policies son inmutables y versión `1.0.0`; declaran familia, plataformas,
rule requerida, técnica, evidencia mínima/opcional y limitaciones. La policy de
process exige más que command-line presente; la de network no acepta puerto 443
como web/C2; la de scheduled task no confirma persistence. Los requisitos
temporales weak permanecen weak y no satisfacen condiciones strong.

El endpoint independiente siempre recalcula rules y correlation desde el batch.
El unificado ejecuta ambos una vez y entrega esos objetos al mapping interno. El
cliente no puede suministrarlos. Candidate exige todos los mínimos, catálogo
activo y ausencia de contradicción. `insufficient_evidence`, `not_supported`,
`not_applicable`, `catalog_unavailable` y `retired_technique` permanecen distintos.
Cero candidatos positivos es un resultado válido.

La respuesta fija `confirmed_attack=false`, `malicious_activity_confirmed=false`,
`malware_detected=false`, `attribution_performed=false` y
`vulnerability_mapping_performed=false`. No hay mapping CVE/CWE/KEV/EPSS/ML.

## I. Análisis unificado y resultados parciales

Los resultados independientes y unificados conservan estados de findings,
relaciones, strengths, IDs de eventos/relaciones y evaluaciones. La optimización
`evaluate_trusted` no cambia conclusiones en los tests de equivalencia y ejecuta
cada engine una vez.

| Condición | Comportamiento observado |
|---|---|
| Batch válido, cero findings/candidates | `complete`; cero no equivale a fallo |
| Error semántico de validación | `partial`; rules/correlation/mapping `skipped` |
| Catálogo no cargado | `partial`; mapping `unavailable`; no inventa cero técnicas |
| Regla disabled | Finding `not_applicable` |
| Deadline/límite interno | HTTP 503 sanitizado; no respuesta exitosa engañosa |
| Capacidad agotada | HTTP 429 sin cola |
| Excepción inesperada | HTTP 500 sanitizado |
| Cancelación externa | Se propaga `CancelledError`; el thread puede continuar |

`BehavioralAnalysisStatus.UNAVAILABLE` está publicado pero el servicio actual no
lo emite: los errores totales fallan HTTP y el catálogo ausente produce
`partial`. Se considera una asimetría documental informativa, no corrupción de
evidencia.

## J. Seguridad de recursos, workers, cancelación y shutdown

Los engines síncronos completos corren dentro de un thread de executor. El event
loop ejecuta admisión, timeout y serialización HTTP. El deadline interno de tres
segundos es cooperativo entre stages; no interrumpe una stage que no retorna. El
timeout externo de cuatro segundos deja de esperar, pero Python/asyncio no puede
detener el thread.

La implementación acierta en una propiedad importante: tras timeout o
cancelación normal, el slot permanece ocupado mientras el worker continúa, y una
quinta solicitud recibe rechazo. No existe cola de admisión de la aplicación y
como máximo cuatro operaciones unificadas son admitidas. El endpoint standalone
de mapping posee otro capacity independiente de cuatro; el límite global del
proceso entre ambos endpoints no es cuatro sino potencialmente ocho threads de
Phase 05, además de otros executors del backend.

El ownership posterior falla. `execute_behavioral_analysis` y
`evaluate_attack_mapping` crean `release_after_worker()` con
`asyncio.create_task()` sin guardar el task en el servicio o `app.state`.
`lifespan` no cierra, cancela ni drena esos workers/supervisores. Si shutdown
cancela la tarea antes de que ejecute su primer ciclo, su `finally` nunca corre.

Reproducción determinista con worker instrumentado y timeout de 0.01 s:

```text
after_timeout {'active': 1, 'thread_running': True}
pending_tasks 2
after_shutdown_cancellation {'active': 1, 'thread_running': True}
after_thread_exit {'active': 1, 'thread_running': False}
```

El resultado tardío no se publica en estado compartido en el camino actual, pero
se pierde la supervisión, el contador queda inconsistente y shutdown depende del
comportamiento implícito del executor/event loop. Una función que ignore el
deadline cooperativo puede retrasar indefinidamente el cierre del proceso. Véase
P05-CONC-003.

## K. Privacidad y fronteras de confianza

El resultado unificado minimiza datos: devuelve UUIDs, resúmenes y explicaciones,
no eventos, command lines, rutas, targets ni endpoints crudos. Los mensajes de
validación/correlación son plantillas controladas y se vinculan por UUID. Las
rutas HTTP sanitizan excepciones y los logs registran tipos, no mensajes privados.

El endpoint de reglas no cumple la misma garantía. `_field()` conserva el valor
y solo pone `redacted=True`. Reproducción:

```text
{'field': 'file_path',
 'value': 'C:\\Users\\alice\\secrets\\token.txt',
 'redacted': True}
```

Los configuration targets se comportan igual. Los endpoints local/remote de red
se retornan directamente y ni siquiera se marcan sensibles. Command-line content
sí se reduce a presencia/longitud. El solicitante suministró originalmente los
datos, pero la respuesta crea una copia innecesaria y contradice la semántica de
redacción, con riesgo en logs de clientes, exports o interfaces posteriores.

No se encontró una vía HTTP para promover evidencia del cliente a backend
trusted, ni para declarar ataque, malware, causalidad, attribution o compromiso.

## L. API y OpenAPI

Se verificó el OpenAPI efectivo y los métodos:

| Path | Método |
|---|---|
| `/api/v1/behavior/events/validate` | POST |
| `/api/v1/behavior/scenarios/generate` | POST |
| `/api/v1/behavior/rules` | GET |
| `/api/v1/behavior/rules/evaluate` | POST |
| `/api/v1/behavior/sequences/correlate` | POST |
| `/api/v1/behavior/sequences/schema` | GET |
| `/api/v1/behavior/attack/policies` | GET |
| `/api/v1/behavior/attack/map` | POST |
| `/api/v1/behavior/analyze` | POST |
| `/api/v1/behavior/scenarios/analyze` | POST |
| `/api/v1/behavior/analysis/schema` | GET |

Requests usan `extra="forbid"`, tipos y cardinalidades estrictas. Los readers
acotan bytes observados aun sin `Content-Length` y rechazan length inválido. Los
códigos 413/422/429/500/503 se sanitizan. No existe configuración ejecutable,
URL arbitraria, expression language ni registry mutable por HTTP.

## M. Regresión, validez científica y Quality Gate

No se encontró acoplamiento nuevo hacia Static Analysis, ML, NVD, CVSS/CWE/CPE,
KEV o EPSS. Phase 05 no convierte CVE, CWE, KEV, EPSS ni predicciones ML en
ATT&CK. Las búsquedas de afirmaciones problemáticas no encontraron declaraciones
positivas de malware/compromise/detección real; las apariciones son negaciones o
límites explícitos.

Los contratos distinguen: evento sintético, evento declarado, validación
estructural, condición de regla, relación temporal y asociación ATT&CK candidata.
No afirman observación operacional independiente ni compromiso confirmado.

Pruebas focalizadas de los seis módulos, con `PYTHONASYNCIODEBUG=1` y warnings
como errores: **186 passed en 79.80 s**.

Quality Gate completo desde `apps/api`:

| Etapa | Resultado |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 155 archivos |
| mypy strict | PASS — 130 archivos fuente |
| pytest | PASS — 892/892 |
| Coverage statement/branch | PASS — 94.43% |
| `pip check` | PASS |
| Unified Quality Gate | PASS |
| `git diff --check` inicial | PASS |

El gate tardó 646.68 s en pytest. La suite sí cubre timeout y cancelación durante
operación normal, pero no la cancelación de la tarea supervisora durante shutdown,
no construye un wheel limpio, no verifica digest del snapshot consumido y acepta
la falsa redacción porque solo comprueba que el flag esté presente.

## N. Registro de hallazgos

### P05-SEC-001 — El snapshot consumido no tiene verificación criptográfica

- **Severity:** High; bloqueante por integridad de evidencia.
- **Archivo y línea:** `apps/api/app/attack/catalog.py:415-477`.
- **Evidencia:** un snapshot modificado en `T1059.name` cargó correctamente y
  conservó `source_digest=dc1639...`.
- **Reproducción:** descomprimir el snapshot, cambiar un campo semánticamente
  válido sin alterar estadísticas/provenance, recomprimir y llamar
  `load_snapshot(path)`.
- **Impacto:** una alteración de filesystem, paquete o supply chain puede cambiar
  nombres, estados, tácticas, parents o referencias y aun presentarse como
  derivada del bundle oficial; mappings y explicaciones consumirían esos datos.
- **Condición de explotación:** capacidad de reemplazar/modificar el artefacto
  local o distribuir un wheel alterado; no requiere acceso HTTP por sí solo.
- **Corrección recomendada:** fijar y comprobar SHA-256 del snapshot exacto antes
  de descomprimir/parsear, o distribuir el bundle fuente fijado y reconstruir
  verificando sus bytes. Separar claramente source digest de artifact digest.
- **Test requerido:** alteraciones válidas de technique, status, relationship y
  provenance deben fallar por digest antes de publicación; el snapshot oficial
  debe cargar offline.
- **Estado:** OPEN.

### P05-REL-002 — El wheel limpio omite el catálogo ATT&CK

- **Severity:** High; bloqueante para reproducibilidad/funcionalidad de 05.01.
- **Archivo y línea:** `apps/api/pyproject.toml:33-36` y ausencia de configuración
  package-data para `app/attack/data/*.json.gz`.
- **Evidencia:** wheel `icylens_api-0.4.1-py3-none-any.whl` de 183,040 bytes,
  construido desde `git archive HEAD`, contiene `app/attack/catalog.py` pero no
  contiene `enterprise-attack-19.2.json.gz`.
- **Reproducción:** exportar HEAD limpio, ejecutar `pip wheel <clean>/apps/api
  --no-deps`, listar el ZIP del wheel.
- **Impacto:** una instalación normal arranca sin el artefacto central y el store
  queda unavailable; tests/editable install esconden el defecto al leer source.
- **Condición de explotación:** cualquier instalación desde wheel/sdist generado
  por la configuración actual.
- **Corrección recomendada:** declarar package data explícita, comprobar wheel y
  sdist, instalar el wheel en entorno aislado y cargar el catálogo desde resources.
- **Test requerido:** build limpio, assert de archivo/digest/tamaño, instalación
  no editable, import y `ATTACKCatalogStore.load()` offline.
- **Estado:** OPEN.

### P05-CONC-003 — Supervisores de workers no tienen ownership de lifecycle

- **Severity:** Medium; bloqueante por el criterio explícito de worker ownership.
- **Archivo y línea:** `apps/api/app/services/behavior_analysis.py:567-602`,
  `apps/api/app/services/attack_mapping.py:429-465`, `apps/api/app/main.py:61-120`.
- **Evidencia:** reproducción anterior: worker terminado y `capacity.active == 1`
  después de cancelar tareas de shutdown antes del primer ciclo del cleanup.
- **Reproducción:** forzar timeout con un `threading.Event`, enumerar/cancelar
  tasks pendientes como en shutdown, liberar el thread y observar capacidad.
- **Impacto:** task sin supervisor, contador inconsistente, falta de drain y
  shutdown dependiente de executor; una función no cooperativa puede impedir
  cierre controlado. El problema existe también en mapping standalone.
- **Condición de explotación:** timeout/cancelación coincidente con shutdown o
  cancelación externa del supervisor; trabajo síncrono que no retorna a tiempo.
- **Corrección recomendada:** un manager process-local dueño de worker y
  supervisor, registry acotado, done callbacks seguros, capacity asociada a la
  vida real del future, `aclose()` idempotente y drain explícito en lifespan con
  política documentada para threads no cancelables. Definir además si el límite
  global entre mapping y unified debe ser compartido.
- **Test requerido:** timeout, cancelación antes/después de start, race de
  completion, excepción, shutdown inmediato, cuatro workers activos, capacidad
  agotada, worker resistente, cero supervisors pendientes y contador cero.
- **Estado:** OPEN.

### P05-PRIV-004 — `redacted=true` conserva valores sensibles

- **Severity:** Medium; bloqueante de la garantía de privacidad declarada.
- **Archivo y línea:** `apps/api/app/behavior/rule_engine.py:60-65,101-127` y
  `apps/api/app/schemas/behavior_rules.py:77-89`.
- **Evidencia:** file path y configuration target originales se serializan con
  `redacted=true`; local/remote endpoint se serializa en claro.
- **Reproducción:** evaluar `BR-FILE-003` con path que contenga username/secret y
  serializar `finding.evidence.fields`.
- **Impacto:** duplicación y propagación innecesaria de rutas, usernames
  embebidos, targets y endpoints; flag engañoso para consumidores.
- **Condición de explotación:** consumidor que envía telemetría sensible y almacena,
  reenvía o muestra la respuesta de `/behavior/rules/evaluate`.
- **Corrección recomendada:** reemplazar valores sensibles por presencia,
  longitud o fingerprint no reversible/contextual; aplicar una política uniforme
  a endpoints y source IDs; reservar `redacted=true` para un valor realmente
  eliminado o sustituido.
- **Test requerido:** canaries de command line, username, path, hostname, target,
  registry value, IP/port y secret no deben aparecer en ninguna sección de todas
  las respuestas y errores.
- **Estado:** OPEN.

### P05-REL-005 — Metadata 0.4.1 sin tag correspondiente

- **Severity:** Low; no bloquea runtime, sí handoff de release.
- **Ubicación:** `apps/api/pyproject.toml:7`, `app/core/config.py:27`, tags Git.
- **Evidencia:** metadata `0.4.1`; último tag `v0.4.0`.
- **Impacto:** el artefacto no tiene referencia de release publicada equivalente.
- **Corrección recomendada:** no mover `v0.4.0`; resolver primero 05.07.1 y luego
  decidir si publicar la versión correctiva o avanzar directamente a `v0.5.0`.
- **Test requerido:** coherencia tag/package/health/OpenAPI sobre commit aceptado.
- **Estado:** OPEN.

### P05-REP-006 — Dependencias sin lock reproducible

- **Severity:** Low; riesgo residual de supply chain.
- **Ubicación:** `apps/api/pyproject.toml`; ausencia de lock/constraints con hash.
- **Evidencia:** dependencias por rangos; el gate auditado resolvió Python 3.13.17,
  FastAPI 0.162.0, Pydantic 2.14.1, httpx 0.28.1, pytest 9.1.1, Ruff 0.17.2 y
  mypy 1.20.2.
- **Impacto:** una instalación futura puede ejecutar versiones distintas dentro
  del rango aunque la fuente sea idéntica.
- **Corrección recomendada:** adoptar lock/constraints verificable para release.
- **Test requerido:** instalación limpia reproducible y Quality Gate offline.
- **Estado:** OPEN; no es por sí solo el bloqueo de Phase 05.

### P05-DEPLOY-007 — API sin autenticación ni controles distribuidos

- **Severity:** Informational en local; High exposure risk si se publica.
- **Ubicación:** composición FastAPI y deployment boundary.
- **Evidencia:** rutas sin autenticación/autorización; capacity, estado y límites
  son process-local; no hay persistencia, cuotas por identidad ni rate limiter
  distribuido.
- **Impacto:** no es un SOC/EDR ni un servicio público multi-tenant seguro.
- **Corrección recomendada:** mantener loopback/local o añadir gateway, TLS,
  identidad, autorización, cuotas, aislamiento y observabilidad antes de Internet.
- **Estado:** LIMITATION ACCEPTED únicamente para alcance educativo local.

## O. Matriz de decisión

| Área | Decisión | Razón |
|---|---|---|
| A. Integridad del catálogo ATT&CK | BLOCKED | P05-SEC-001 y P05-REL-002 |
| B. Contratos de telemetría | PASS | Identidad, provenance, límites y validación correctos |
| C. Corrección del rule engine | CONDITIONAL PASS | Semántica correcta; evidencia HTTP viola privacidad |
| D. Integridad de correlación temporal | PASS | Determinista, no causal, identities/strengths preservados |
| E. Fidelidad de mapping ATT&CK | CONDITIONAL PASS | Engine conservador; depende de catálogo no autenticado/distribuido |
| F. Corrección del análisis unificado | PASS | Stages, partials y equivalencia semántica correctos |
| G. Privacidad | BLOCKED | P05-PRIV-004 |
| H. Seguridad de recursos | BLOCKED | Ownership/shutdown incompleto; límites individuales no globales |
| I. Cancelación y lifecycle | BLOCKED | P05-CONC-003 |
| J. Compatibilidad API | PASS | Paths, métodos, schemas, límites y errores verificados |
| K. Suficiencia de tests | CONDITIONAL PASS | Gate fuerte, pero omite cuatro reproducciones críticas |
| L. Educational local readiness | BLOCKED | Requiere 05.07.1 antes de release |
| M. Public production readiness | NOT READY | Sin auth, controles distribuidos ni hard isolation |
| N. Aceptación final Phase 05 | **BLOCKED** | Cuatro findings materiales abiertos |

## P. Readiness, release y siguiente fase

**Educational Local Readiness: BLOCKED.** El uso desde este checkout ofrece muchas
garantías correctas, pero no debe declararse release aceptado mientras el wheel
carezca del catálogo, el snapshot pueda alterarse sin detección, shutdown pierda
ownership y la API de reglas contradiga su redacción.

**Public Production Readiness: NOT READY.** A los findings se suman ausencia de
authn/authz, TLS/ingress definido, rate limiting/cuotas distribuidas, aislamiento
duro de CPU, persistencia/estado compartido y operación multi-instancia.

No corresponde preparar ni crear `v0.5.0`. Tampoco corresponde mover tags
históricos. Primero debe cerrarse 05.07.1, repetir build instalado y auditoría
independiente, crear `PHASE_05_ACCEPTANCE.md` solo si pasa, sincronizar el commit
aceptado y decidir la estrategia de versión.

Phase 06 — Multilayer Correlation & Explainability — no debe iniciarse hasta que
Phase 05 preserve estas garantías en el artefacto distribuido y durante shutdown.

## Q. Alcance correctivo requerido — Checkpoint 05.07.1

05.07.1 debe limitarse a:

1. autenticar criptográficamente el snapshot realmente cargado y separar digest
   de fuente de digest de artefacto;
2. incluir snapshot y package semantics explícitas en wheel/sdist y añadir prueba
   de instalación no editable limpia;
3. introducir ownership registrado y drain de workers/supervisores de unified y
   mapping, incluyendo shutdown y worker resistente;
4. aplicar redacción real y uniforme a toda evidencia de reglas;
5. añadir reproducciones deterministas para los cuatro findings;
6. repetir 186 tests focalizados con asyncio debug/warnings, Quality Gate completo,
   `git diff --check`, OpenAPI y build/install offline;
7. reauditar sin alterar thresholds ni introducir funcionalidades de Phase 06.

No requiere nuevas reglas, policies, técnicas, endpoints ni detecciones.

## R. Git handoff

Archivo creado por 05.07:

- `docs/PHASE_05_AUDIT_REPORT.md`

No se modificó código funcional, tests, thresholds, metadata, tags ni el archivo
preexistente no seguido `apps/api/app/attack/__init__.py`. No se creó
`docs/PHASE_05_ACCEPTANCE.md`.

Conventional Commit sugerido para registrar únicamente este informe:

```text
docs(phase-05): document blocked security audit
```

Los correctivos de 05.07.1 deben usar commits separados por causa (catalog
integrity/package data, worker lifecycle, privacy evidence y tests) para conservar
trazabilidad.

## S. Veredicto final

**BLOCKED.** Phase 05 demuestra buena corrección semántica y un gate sólido, pero
todavía no preserva de extremo a extremo la integridad del catálogo distribuido,
la privacidad de toda respuesta ni el ownership de CPU work bajo shutdown. Esas
propiedades son parte central del alcance solicitado y no pueden sustituirse por
cobertura alta o por el éxito de los caminos unitarios existentes.

## T. Remediación 05.07.1

Fecha: 2026-10-26 (America/Managua)

HEAD base: `8fbfbd3d917e445a0d53404865d960cdbe7d985a`

Resultado del checkpoint correctivo: **PASS — apto para reauditoría final
independiente**.

Las reproducciones y el veredicto original de las secciones A–S se conservan como
registro histórico. Este apartado registra la corrección, no constituye la
aceptación final de Phase 05 y no crea `PHASE_05_ACCEPTANCE.md`.

### T.1 P05-SEC-001 — FIXED

`app/attack/catalog.py` separa ahora `ATTACK_SOURCE_SHA256` del nuevo
`ATTACK_ARTIFACT_SHA256`. `load_snapshot()` lee como máximo 2 MiB comprimidos,
calcula SHA-256 sobre esos bytes y los compara con la constante externa al
artefacto antes de invocar gzip. Solo entonces aplica el límite expandido de
16 MiB y las validaciones de schema, provenance, identidades y referencias.

El snapshot distribuido conserva SHA-256
`916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`; el
source digest permanece
`dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
Mutaciones de nombre, estado, relación, táctica y provenance, un cambio mínimo de
bytes, truncamiento y contenido corrupto son rechazados. Un reemplazo rechazado
no sustituye el snapshot publicado previamente.

El artifact digest detecta divergencia respecto de esta versión confiable del
código; no es una firma independiente de MITRE y no protege contra un atacante
que pueda modificar simultáneamente código y recurso.

### T.2 P05-REL-002 — FIXED

`app.attack` se define como paquete regular: el `__init__.py` preexistente forma
parte necesaria del handoff, package discovery usa `namespaces=false` y
`app.attack.data` también es un paquete regular. `pyproject.toml` declara
`*.json.gz` como package data y `MANIFEST.in` lo incluye expresamente en sdist.
El loader obtiene el recurso predeterminado mediante `importlib.resources`.

Build desde una copia preparada del working tree:

```text
wheel: icylens_api-0.4.1-py3-none-any.whl, 1,725,078 bytes
sdist: icylens_api-0.4.1.tar.gz, 1,672,353 bytes
wheel snapshot: present, 1,541,193 bytes, sha256=916eabb1...a0bc88
sdist snapshot: present, 1,541,193 bytes, sha256=916eabb1...a0bc88
```

Una instalación no editable en un venv temporal, ejecutada fuera del checkout,
importó `app` desde ese venv, anunció versión `0.4.1`, cargó Enterprise ATT&CK
19.2 offline, reprodujo los conteos 26,086/15/858/493/21,262 y resolvió `T1059`
como `Command and Scripting Interpreter`, active. `pip check` pasó.

La validación definitiva debe repetirse desde el commit limpio que incluya todos
los archivos de 05.07.1; `git archive HEAD` todavía representa el HEAD base
porque esta tarea no realiza commits.

### T.3 P05-CONC-003 — FIXED

El nuevo `SynchronousWorkerManager` posee un `ThreadPoolExecutor` acotado y cada
`concurrent.futures.Future` desde admisión hasta terminación real. No crea tareas
supervisoras detached. El callback del future consume excepciones, retira el
worker y libera exactamente un slot únicamente cuando el trabajo síncrono
termina. Timeout y cancelación del request esperan con shield y no cancelan ni
liberan el worker.

Mapping standalone y análisis unificado comparten una sola instancia en
`app.state`, por lo que el presupuesto global efectivo de Phase 05 es cuatro y
la quinta operación se rechaza sin cola. `aclose()` cierra admisión, drena los
futures fuera de locks, cierra el executor y es idempotente. FastAPI lifespan lo
espera antes de cerrar los demás recursos.

Las pruebas cubren timeout con thread activo, cancelación de request, cuatro
workers, quinta admisión, excepción, submit fallido, shutdown inmediato,
shutdown bloqueado hasta terminación real, cierre idempotente y manager compartido.
Al final se observa `active=0` y `owned_workers=0`, sin `Task exception was never
retrieved` bajo asyncio debug/warnings.

Un thread Python no puede terminarse con `asyncio.cancel()`. La política local es
esperar su finalización durante shutdown; un worker que nunca coopere puede
retrasar indefinidamente el cierre. Terminación forzada requeriría aislamiento en
otro proceso y permanece fuera de 05.07.1.

### T.4 P05-PRIV-004 — FIXED

`EvidenceField` exige ahora que `redacted=true` implique exactamente
`value="[REDACTED]"`, y rechaza el marker sin el flag. La política central del
rule engine sustituye host IDs, source IDs, file paths, configuration targets,
command-line length sensible y endpoints local/remote. Event UUID, rule ID,
field name, naturaleza, condiciones satisfechas y facts estructurales seguros se
conservan.

Canaries para command line, token, executable path, username, hostname, source,
producer, file path, IPs, puerto, registry target/values y attributes no aparecen
en `RuleFinding`, `RuleEvaluationResult`, JSON ni respuesta HTTP. Las cuatro reglas
de la prueba continúan matched.

### T.5 Regresión y evidencia final

Phase 05 focalizada con `PYTHONASYNCIODEBUG=1` y warnings como errores: **202
passed en 39.51 s**. La suite correctiva aislada: **16 passed en 9.33 s**.

Quality Gate final:

| Etapa | Resultado |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 158 archivos |
| mypy strict | PASS — 132 archivos fuente |
| pytest | PASS — 908/908 |
| Coverage statement/branch | PASS — 94.50% |
| `pip check` | PASS |
| Unified Quality Gate | PASS |

Los 16 tests nuevos no cambian técnicas, policies, reglas, inferencias científicas
ni rutas públicas. Phase 04, Static Analysis y Synthetic ML permanecen cubiertos
por el gate completo.

### T.6 Registro actualizado

| Finding | Estado 05.07.1 | Evidencia de cierre |
|---|---|---|
| P05-SEC-001 | FIXED | Digest externo del artifact antes de gzip y mutaciones rechazadas |
| P05-REL-002 | FIXED | Wheel/sdist/instalación no editable con snapshot verificado |
| P05-CONC-003 | FIXED | Owner compartido, cuatro slots, drain de lifespan y cero workers finales |
| P05-PRIV-004 | FIXED | Sustitución real y canaries ausentes de engine/HTTP |
| P05-REL-005 | OPEN | Metadata 0.4.1 continúa sin tag; no bloquea el correctivo |
| P05-REP-006 | OPEN | Continúa sin lockfile; riesgo residual conocido |
| P05-DEPLOY-007 | LIMITATION | Producción pública continúa no preparada |

05.07.1 obtiene **PASS** como remediación y puede someter los cuatro findings a
cierre independiente. Phase 05 aún no obtiene aceptación final hasta esa
reauditoría. No se recomienda crear tags ni iniciar Phase 06 en este checkpoint.
