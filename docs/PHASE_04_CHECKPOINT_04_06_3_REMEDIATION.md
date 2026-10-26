# Phase 04 / Checkpoint 04.06.3 — KEV refresh lifecycle hardening

Fecha: 2026-10-26 (America/Managua)
Resultado: **PASS**

## A. Initial Audit

La rama era `main`; `HEAD` y `origin/main` coincidían en
`67da4239d738456469358a884b1d0098feb1a770`. El working tree contenía únicamente
la actualización documental de la auditoría independiente que abrió
P04-SEC-007; se preservó íntegramente. Los tags eran `v0.1.0`, `v0.2.0` y
`v0.3.0`. No existían `v0.4.0` ni `PHASE_04_ACCEPTANCE.md`.

Baseline: 697 tests, 93.30% de cobertura, Ruff PASS, mypy strict PASS,
`pip check` PASS y Quality Gate PASS.

## B. Root Cause

`KEVCatalogStore.refresh()` adquiría `_refresh_lock` antes de llamar al proveedor
y lo liberaba solo después de descargar, validar y promover. El estado realmente
compartido era únicamente la selección de operación, el snapshot activo, la
autorización de promoción y el estado de cierre. HTTP y construcción del candidato
no requerían el lock.

Reproducción original:

```text
lock_held_during_provider_wait=True
second_done_before_release=False
provider_calls_total=1
pending_tasks=0
```

## C. Lock Scope Remediation

`_refresh_lock` ahora protege solo registro/selección del task, autorización y
promoción atómica, cleanup por identidad y transición a cerrado. Quedan fuera:

- fetch HTTP, streaming, retries y backoff;
- parsing y validación del catálogo;
- construcción del snapshot inmutable;
- espera de consumidores;
- cancelación y drain de shutdown.

Evidencia posterior:

```text
lock_held_during_provider_wait=False
provider_calls_before_release=1
provider_calls_total=1
same_snapshot=True
refresh_task=None
pending_tasks=0
```

## D. Refresh Ownership

La política es **service-owned refresh**. El store posee un único task hasta que
termina o hasta shutdown. Los consumidores usan `asyncio.shield()`: cancelar uno,
incluso si era el único, no transfiere ni destruye ownership. El task permanece
registrado y supervisado, y su callback consume el resultado terminal para evitar
excepciones no observadas.

`aclose()` marca cierre y retira/cancela bajo lock; luego espera con `gather()`
fuera del lock. El lifespan invoca `kev_store.aclose()` antes de
`kev_client.aclose()`.

## E. Coalescing

Dos consumidores concurrentes localizan el mismo `_refresh_task`. La descarga y
el candidato son únicos. Una cancelación individual no afecta a los restantes.
Después de éxito, fallo o cancelación, el registro se limpia por identidad.

## F. Atomic Snapshot Promotion

El candidato se construye y valida completamente antes de intentar publicación.
Dentro del lock se exige:

1. store abierto;
2. task actual existente;
3. ausencia de cancelación solicitada mediante `task.cancelling()`;
4. identidad exacta con `_refresh_task`;
5. ausencia de conflicto de versión/digest;
6. fecha no anterior al snapshot activo.

La autorización y asignación son atómicas y no contienen puntos de suspensión.
Snapshots inválidos, fallos y operaciones retiradas preservan el último snapshot
válido.

## G. Cancellation and Shutdown

Se probaron cancelación de consumidores, fetch, backoff, validación y frontera de
promoción. Shutdown impide nuevos refreshes, retira autorización antes de
cancelar, drena fuera del lock y precede al cierre HTTP. Una operación que
suprime temporalmente `CancelledError` no puede publicar al regresar.

Cancelación es cooperativa: una coroutine que la suprima indefinidamente puede
retrasar el drain; no puede recuperar autorización ni ser terminada de forma
forzada segura por asyncio.

## H. Adversarial Tests A–L

| Caso | Evidencia | Resultado |
|---|---|---|
| A. Lock libre durante provider wait | Adquisición concurrente con timeout | PASS |
| B. Dos consumidores | Una llamada y mismo snapshot | PASS |
| C. Consumidor cancelado | Refresh service-owned continúa | PASS |
| D. Fallo de proveedor | Snapshot anterior preservado | PASS |
| E. Late completion | Operación retirada no publica | PASS |
| F. Shutdown durante I/O | Cancelación y recolección | PASS |
| G. Shutdown vs promotion | Cierre gana antes del commit | PASS |
| H. Respuesta inválida concurrente | Un fetch, dos errores tipados, sin promoción | PASS |
| I. Catálogo antiguo vs nuevo | Rollback rechazado | PASS |
| J. Freshness y lookup | Lectura activa no bloquea ni hace fetch | PASS |
| K. Cleanup | Registro vacío tras éxito/fallo/cancelación | PASS |
| L. Supresión de cancelación | Sin late publication | PASS |

Las pruebas son offline y usan `asyncio.Event`, barreras, tasks instrumentados y
transportes mock. No se realizaron llamadas reales a CISA.

## I. Regression

La suite completa preservó NVD, CVSS/CWE/CPE, semántica KEV, ownership/fencing
EPSS, correlación unificada, Static Analysis, ML demo y OpenAPI. `never_loaded`,
`unavailable`, fresh/stale positive y stale negative mantienen sus contratos.

## J. Quality Gate

| Control | Resultado |
|---|---|
| Tests | 706/706 PASS — 9 nuevos |
| Cobertura statement/branch | 93.37% PASS |
| Ruff lint | PASS |
| Ruff format | PASS — 116 archivos |
| mypy strict | PASS — 97 archivos |
| `pip check` | PASS |
| Quality Gate | PASS |

## K. Findings Register

| ID | Estado |
|---|---|
| P04-SEC-001 — EPSS task ownership | FIXED |
| P04-SEC-006 — EPSS cache commit fencing | FIXED |
| P04-SEC-007 — KEV lock durante I/O | FIXED |

Riesgos residuales: estado process-local, ausencia de persistencia distribuida,
digest sin firma de contenido y límite inherente de cancelación cooperativa.

## L. Final Decision

Checkpoint 04.06.3: **PASS**. Las doce condiciones de aceptación del correctivo
quedan satisfechas. Esto no constituye aceptación final de Phase 04.

## M. Exact Git Handoff and Conventional Commits

Archivos funcionales y de prueba esperados:

- `apps/api/app/intelligence/kev_catalog.py`;
- `apps/api/app/main.py`;
- `apps/api/tests/test_kev_integration.py`;
- `docs/KEV_CATALOG_LIFECYCLE.md`;
- `docs/PHASE_04_AUDIT_REPORT.md`;
- `docs/PHASE_04_CHECKPOINT_04_06_3_REMEDIATION.md`.

Commits sugeridos:

```text
fix(kev): move refresh I/O outside coordination lock
test(kev): prove refresh ownership fencing and shutdown
docs(audit): record phase 04 KEV lifecycle remediation
```

No se ejecutaron `git add`, commit, tag ni push.

## N. Recommendation for Final Independent Reaudit

Repetir la auditoría final independiente y verificar especialmente lock libre
durante I/O, una sola descarga concurrente, cancelación durante validación,
shutdown contra promoción y ausencia de tasks pendientes. Solo esa reauditoría
puede crear `PHASE_04_ACCEPTANCE.md` y decidir sobre `v0.4.0`. Phase 05 no fue
iniciada.
