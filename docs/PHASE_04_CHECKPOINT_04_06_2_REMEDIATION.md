# Phase 04 / Checkpoint 04.06.2 — EPSS cache commit authorization

Fecha: 2026-10-26 (America/Managua)
HEAD base: `91838a73c943df32535c5162623928c09d09503f`
Resultado: **PASS**

## A. Auditoría inicial

La auditoría comenzó en `main`, sincronizado con `origin/main`, con los commits
04.06.1 presentes y sin `v0.4.0`. El working tree contenía únicamente la
actualización no registrada del informe final que documentaba P04-SEC-006; se
preservó. El baseline era 693 tests, 93.29% de cobertura y Quality Gate PASS.

## B. Reproducción original

Un provider sintético inició el fetch antiguo, observó `CancelledError`, lo
suprimió temporalmente y esperó una barrera. Una operación sucesora para la misma
CVE publicó el fixture high. Al liberar la antigua, esta devolvió el fixture low
y, antes del fix, sobrescribió el cache:

```text
new_result=0.999990000
old_result=0.000010000
final_cache=0.000010000
```

La prueba fue offline, determinista y no contactó FIRST.

## C. Causa raíz

La operación compartida tenía ownership de consumidores y cleanup por identidad,
pero la autorización del cache commit no estaba vinculada al registro vigente.
`_fetch_and_cache` escribía cualquier resultado validado aunque su task ya hubiera
sido retirado, reemplazado o cancelado. `task.cancel()` es una solicitud
cooperativa y no constituye por sí sola una barrera de publicación.

## D. Arquitectura de fencing

Se eligió fencing por identidad del task, sin historial de generaciones. Para
cada CVE, `_commit_if_authorized` compara el task actual con la
`_InFlightOperation` vigente. También exige servicio abierto y operación no
retirada. Una operación reemplazada encuentra otra identidad o ninguna entrada y
queda desautorizada.

Las identidades nunca se comparan entre CVEs y no existe registro histórico que
pueda crecer sin límite.

## E. Semántica de commit atómico

Después de fetch y normalización, el runner solicita publicación. Bajo `_lock`,
sin ningún `await` dentro de la sección crítica, se ejecuta:

1. comprobar `_closed`;
2. leer `_inflight[cve_id]`;
3. comprobar identidad del task;
4. comprobar `cancellation_requested`;
5. escribir cache, actualizar LRU y ejecutar eviction.

Retiro, reemplazo, shutdown y commit usan el mismo lock. I/O, parsing, backoff,
semaphore wait y task collection quedan fuera, evitando deadlocks y serialización
remota innecesaria.

## F. Cambios y archivos

Código modificado:

- `apps/api/app/services/epss_intelligence.py`: `_commit_if_authorized` y uso
  desde `_fetch_and_cache`.

Pruebas modificadas:

- `apps/api/tests/test_epss_integration.py`: provider resistente a cancelación y
  cuatro casos nuevos de fencing.

Documentación:

- `docs/PHASE_04_AUDIT_REPORT.md`: historia y cierre de P04-SEC-006.
- `docs/PHASE_04_CHECKPOINT_04_06_2_REMEDIATION.md`: este documento.

No se eliminó ningún archivo ni se modificó otro subsistema.

## G. Pruebas adversariales A–J

| Caso | Evidencia |
|---|---|
| A. Old task completa tarde | `test_retired_late_completion_cannot_overwrite_successor_cache` conserva high |
| B. Old termina antes del sucesor | `test_retired_completion_cannot_publish_before_successor_exists` deja cache vacío |
| C. Completion/retirement | La prueba 04.06.1 de completion race sigue pasando; commit o retiro linearizan bajo lock |
| D. Same-CVE consumers | Un fetch compartido; cancelar uno conserva al otro |
| E. Last consumer | Cancela provider, limpia registro y recolecta task |
| F. Successor fails | `test_retired_completion_is_not_fallback_when_successor_fails` deja cache vacío |
| G. Different CVEs | Pruebas de aislamiento y saturación siguen pasando |
| H. Shutdown | `test_shutdown_fences_late_completion_from_cache` impide publicación tardía |
| I. TTL/LRU | Expiración, eviction y frescura existentes siguen pasando |
| J. Cancellation suppression | El provider sintético suprime cancelación; cache final conserva high |

La reproducción posterior observó:

```text
cached_score=0.999990000
retired_result_committed=False
inflight_count=0
pending_tasks=0
```

## H. Integridad de cache EPSS

Se preservan Decimal exacto, score date, retrieved-at, freshness, CVE identity,
TTL, capacidad LRU, retries y distinción score cero/not-scored. Excepciones,
respuestas inválidas, cancelaciones y resultados de operaciones retiradas no se
cachean. La autorización no usa score ni percentile como proxy de frescura.

## I. Regresión de coalescing y cancelación

P04-SEC-001 permanece cerrado. Shield solo protege la tarea compartida mientras
existen consumidores; el último retira, cancela y recolecta. El sucesor recibe
otra identidad y no puede ser borrado ni sobrescrito por su predecesor. No se
observaron tareas huérfanas ni entradas inflight obsoletas.

## J. Revisión de write paths relacionados

KEV mantiene un único `_refresh_lock` durante fetch, validación y promoción; no
crea background tasks. Un segundo refresh no puede adelantar al primero dentro de
un store, y una cancelación libera el lock sin promover candidato incompleto. El
correlador cancela/recolecta sus tasks NVD/EPSS. No se confirmó otro late writer.

## K. Quality Gate

| Control | Resultado |
|---|---|
| Tests | 697/697 PASS — 4 nuevos |
| Cobertura statement/branch | 93.30% PASS |
| Ruff lint | PASS |
| Ruff format | PASS — 116 archivos |
| mypy strict | PASS — 97 archivos |
| `pip check` | PASS |
| Quality Gate | PASS |
| `git diff --check` | PASS |

## L. Findings y riesgos residuales

### P04-SEC-006

- Severidad: Medium.
- Evidencia inicial: old low sobrescribió new high.
- Corrección: fencing atómico por identidad/estado bajo `_lock`.
- Evidencia posterior: high permanece; retired commit false; registry/tasks cero.
- Estado: **FIXED**.

P04-SEC-001 permanece **FIXED**. Los riesgos residuales no alterados son ausencia
de autenticación/autorización para uso público, controles por proceso, ausencia
de lockfile, metadata 0.1.0 y dependencia de proveedores externos.

## M. Decisión final

Checkpoint 04.06.2: **PASS**.

Se cumplen las catorce condiciones del checkpoint. Esto autoriza una reauditoría
final independiente, no la aceptación automática de Phase 04.

## N. Handoff Git

Estado esperado al entregar: los dos archivos de código/pruebas modificados, el
informe de auditoría modificado y este documento nuevo. No se ejecutó add, commit,
tag ni push.

Conventional Commits sugeridos:

```text
fix(epss): fence cache commits to active operations
test(epss): cover retired task late completion races
docs(audit): record phase 04 cache fencing remediation
```

## O. Recomendación

Repetir la aceptación final independiente de Phase 04 sobre el diff registrado y
un working tree limpio. No crear `PHASE_04_ACCEPTANCE.md` ni `v0.4.0` dentro de
este checkpoint. Phase 05 no fue iniciada.
