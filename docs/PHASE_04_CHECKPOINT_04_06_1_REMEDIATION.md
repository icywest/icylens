# Phase 04 / Checkpoint 04.06.1 — EPSS async lifecycle remediation

Fecha: 2026-10-25 (America/Managua)  
HEAD base: `76007208ea0e3c50cc5d35b9b0ba87793dc038c0`  
Resultado: **PASS**

## A. Auditoría inicial

La rama era `main`, el working tree contenía únicamente el informe de auditoría
04.06 sin registrar y el HEAD estaba seis commits por delante de `origin/main`.
El remoto real permanecía en `32bf955c`; existían los tags `v0.1.0`, `v0.2.0` y
`v0.3.0`. No existía `v0.4.0`.

El baseline confirmado era 685 tests, 93.28% de cobertura, Ruff, mypy strict,
`pip check` y Quality Gate en PASS. El informe original registraba
P04-SEC-001 como Medium bloqueante.

## B. Causa raíz

`EPSSIntelligenceService.lookup()` creaba un task `_fetch_and_cache`, lo guardaba
por CVE y esperaba `asyncio.shield(task)`. Shield impedía que la cancelación de un
consumidor destruyera trabajo compartido, pero el servicio no contaba consumidores.
Cuando el correlador cancelaba `_resolve_epss`, el waiter exterior terminaba y el
task protegido seguía ejecutándose. `_inflight` solo se limpiaba en el `finally`
de ese task, por lo que una espera de capacidad/I/O podía sobrevivir sin dueño.

Antes del correctivo se observó:

```text
provider_cancelled=False
inflight_count=1
pending_tasks=1
pending_coroutines=['EPSSIntelligenceService._fetch_and_cache']
```

## C. Arquitectura de ownership

Cada CVE tiene como máximo una `_InFlightOperation` compartible:

```text
InFlightOperation
  task
  active_waiters
  cancellation_requested
```

Invariantes implementadas:

1. La creación y el registro ocurren bajo `_lock` antes de ceder control.
2. Cada lookup incrementa un waiter exactamente una vez.
3. Su `finally` decrementa exactamente una vez.
4. Shield impide que un waiter cancelado afecte a otros waiters activos.
5. El último waiter elimina por identidad, cancela y recolecta el task.
6. El task también elimina por identidad al completar/fallar/cancelarse.
7. Una operación condenada retirada no puede ser reutilizada ni borrar su reemplazo.
8. Solo `_fetch_and_cache` completado escribe cache; cancelaciones y errores no.
9. `aclose()` impide nuevos lookups y cancela/recolecta todas las operaciones.

El único lock cubre estructuras en memoria. Nunca se conserva durante HTTP,
semaphore wait, backoff, streaming ni recolección de tasks; no existe inversión
de orden de locks en el servicio.

## D. Cambios de código

- `app/services/epss_intelligence.py`: operación compartida, waiters, liberación
  del último consumidor, cleanup condicional y `aclose()`.
- `app/main.py`: el lifespan drena el servicio EPSS antes de cerrar su cliente.
- `tests/test_epss_integration.py`: siete pruebas adversariales de lifecycle.
- `tests/test_unified_vulnerability_intelligence.py`: prueba del deadline con el
  correlador y el servicio EPSS reales.
- `docs/PHASE_04_AUDIT_REPORT.md`: cierre verificable del finding original.
- Este documento: evidencia y handoff del checkpoint.

No se modificaron contratos públicos, scores, frescura, NVD, KEV, CPE, Static
Analysis ni ML.

## E. Prueba adversarial A–H

| Caso | Test exacto | Evidencia observada |
|---|---|---|
| A. Single consumer timeout | `test_total_deadline_cancels_real_coalesced_epss_operation` | correlador termina; provider cancelado; `_inflight={}`; 0 tasks |
| B. One of two cancelled | `test_one_cancelled_waiter_does_not_cancel_a_shared_fetch` | waiters 2→1; un fetch; segundo recibe resultado |
| C. Both cancelled | `test_last_cancelled_waiter_cancels_collects_and_does_not_cache` | provider cancelado una vez; registry/cache vacíos; 0 tasks |
| D. Distinct CVEs saturated | `test_distinct_cancelled_cves_release_saturated_client_capacity` | cinco operaciones limpiadas; semáforo 0→1; stream cerrado; 0 tasks |
| E. Cancellation/rejoin | `test_cancelled_operation_is_not_reused_by_a_rejoining_waiter` | reemplazo inicia segundo fetch correcto sin ser borrado por el primero |
| F. Completion race | `test_provider_completion_and_last_waiter_cancellation_race_is_collected` | registry vacío; máximo un cache write; 0 tasks |
| G. Shutdown | `test_lifespan_shutdown_cancels_service_tasks_before_closing_client` | provider cancelado, cliente cerrado, registry vacío, 0 tasks |
| H. Error/cleanup | `test_provider_error_near_cancellation_is_retrieved_and_cleaned` | error o cancelación recolectados; registry/cache vacíos; 0 tasks |

La reproducción independiente posterior mostró:

```text
CorrelationDeadlineError
provider_cancelled=True
inflight_count=0
pending_tasks=0
pending_coroutines=[]
```

## F. Integridad de cache

TTL, recalculo de freshness, precisión Decimal, fecha, identidad CVE y eviction
LRU permanecen sin cambios. La escritura sigue ocurriendo únicamente después de
fetch, validación y normalización exitosos. Un task cancelado durante espera de
capacidad, backoff, streaming o normalización no llega al bloque de escritura.
Las pruebas confirman que operaciones abandonadas no generan cache y que una
solicitud posterior crea trabajo nuevo. CVEs distintas conservan task y cache
independientes.

Una carrera en la que el proveedor ya completó válidamente puede dejar como
máximo una entrada válida de cache; no se duplica la escritura ni se conserva una
respuesta parcial.

## G. Regresión del correlador

El correlador sigue creando NVD y EPSS concurrentemente, cancela y recolecta sus
wrappers y libera `CorrelationCapacity` en `finally`. La diferencia es que ahora
la cancelación del wrapper EPSS informa al registro de waiters. Un deadline global
cancela el provider cuando no quedan consumidores; si otro request comparte la
misma CVE, el task continúa legítimamente. Estados complete/partial/unavailable,
taxonomía HTTP, evidencia y response limits no cambiaron.

## H. Seguridad de recursos asíncronos

Se verificó cancelación durante el semáforo del cliente y durante streaming. El
semáforo recuperó su capacidad y la respuesta fue cerrada. Las rutas ya existentes
cubren timeout FIRST, rate limits, parsing, backoff, gzip y cierre HTTP; el nuevo
ownership no modifica esas ramas. Los tasks se cancelan fuera de I/O síncrono y
se recolectan explícitamente con `gather(return_exceptions=True)`, sin suprimir el
`CancelledError` del consumidor.

Shutdown ejecuta este orden:

1. rechazar nuevos lookups del servicio;
2. retirar, cancelar y recolectar operaciones activas;
3. cerrar el cliente EPSS;
4. cerrar KEV y NVD;
5. revocar el runtime ML.

## I. Auditoría de patrones relacionados

La búsqueda cubrió `asyncio.shield`, `create_task`, registries y locks de refresh.
No existe otro shield en Phase 04. El correlador es dueño explícito de sus dos
tasks y los cancela/recolecta. Los clientes HTTP no crean background tasks. KEV
coalesce refreshes manteniendo un lock mientras ejecuta el fetch; la cancelación
se propaga directamente, libera el lock por el context manager y no deja una
tarea separada ni registry. No se confirmó un segundo defecto equivalente y no
se modificó KEV.

## J. Quality Gate

Ejecutado desde `apps/api`:

| Control | Resultado |
|---|---|
| Tests | 693/693 PASS (8 nuevos) |
| Cobertura statement/branch | 93.29% PASS |
| Ruff lint | PASS |
| Ruff format | PASS — 116 archivos |
| mypy strict | PASS — 97 archivos fuente |
| `pip check` | PASS |
| Quality Gate | PASS |
| `git diff --check` | PASS |

No se realizaron llamadas a FIRST ni estrés contra proveedores públicos.

## K. Registro de hallazgos

### P04-SEC-001

- Severidad: Medium.
- Código afectado: servicio EPSS, integración con correlador y shutdown.
- Evidencia original: provider no cancelado, una entrada inflight y un task vivo.
- Corrección: ownership con waiters, cancelación/recolección del último consumidor,
  cleanup por identidad y drain en shutdown.
- Tests: los ocho casos A–H de la sección E.
- Resultado: provider cancelado, task recolectado, registry vacío, otros waiters
  preservados, semáforo/stream recuperados y cero tasks pendientes.
- Estado final: **FIXED**.

No se detectaron findings nuevos del mismo patrón. Permanecen fuera de alcance
los findings de release, reproducibilidad y deployment del informe 04.06.

## L. Decisión final

Checkpoint 04.06.1: **PASS**.

Las once condiciones de aceptación del correctivo se cumplen. Esta decisión
cierra P04-SEC-001, pero no constituye todavía la aceptación final independiente
de toda Phase 04 ni autorización para crear `v0.4.0`.

## M. Handoff Git

Archivos funcionales modificados:

- `apps/api/app/services/epss_intelligence.py`
- `apps/api/app/main.py`

Pruebas modificadas:

- `apps/api/tests/test_epss_integration.py`
- `apps/api/tests/test_unified_vulnerability_intelligence.py`

Documentación creada/modificada:

- `docs/PHASE_04_AUDIT_REPORT.md` — modificado, aún no registrado desde 04.06.
- `docs/PHASE_04_CHECKPOINT_04_06_1_REMEDIATION.md` — creado.

Archivos eliminados: ninguno. `PHASE_04_ACCEPTANCE.md` no fue creado.

Conventional Commits sugeridos, no ejecutados:

```text
fix(epss): enforce waiter-owned coalesced task lifecycle
test(epss): prove cancellation coalescing and shutdown safety
docs(audit): record phase 04 async lifecycle remediation
```

## N. Recomendación de reauditoría

Puede repetirse la aceptación final independiente de Phase 04. Esa reauditoría
debe confirmar el diff exacto, volver a ejecutar el gate, revisar los findings no
funcionales aún abiertos y solo entonces decidir si crea
`docs/PHASE_04_ACCEPTANCE.md` y recomienda `v0.4.0`. No crear el tag todavía.
