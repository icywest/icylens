# Phase 05 — Independent Security Reaudit

Fecha: 2026-10-26  
Rol: auditoría independiente de seguridad, packaging, concurrencia y QA  
Veredicto: **BLOCKED**

## A. Initial Audit

La reauditoría partió de `main` en `b821eb9e2f71967de8fdff0e87351c4a84d0102b`.
`HEAD` y `origin/main` coincidían y el árbol estaba limpio antes de generar este
informe. Los seis commits correctivos sobre `8fbfbd3` estaban presentes:

1. `77e3536` — pin criptográfico del artefacto ATT&CK.
2. `83f5304` — empaquetado del recurso ATT&CK.
3. `8ff53d6` — ownership y drain de workers síncronos.
4. `85783dd` — sustitución de evidencia sensible.
5. `7c61d77` — pruebas de seguridad del correctivo.
6. `b821eb9` — documentación de auditoría y remediación.

La metadata declara `0.4.1`; el tag más reciente continúa siendo `v0.4.0`.
La trazabilidad del correctivo es válida, pero no constituye por sí sola evidencia
de cierre.

## B. ATT&CK Integrity Reaudit

El camino predeterminado de `load_snapshot()` lee los bytes comprimidos reales,
calcula SHA-256 y lo compara, antes de gzip/JSON, con una constante externa al
artefacto:

```text
expected = 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88
official = 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88
```

Se descomprimió una copia temporal del snapshot, se mantuvieron versión,
conteos, source digest y estructura, y se reprodujeron seis mutaciones. El camino
con pin rechazó todas con `ATTACKCatalogValidationError: Snapshot artifact digest
does not match the pin`:

| Mutación | SHA-256 calculado del artefacto mutado | Camino con pin |
|---|---|---|
| Nombre de técnica | `ce733f5b53a8b16f6f75424f2ca2588ec08ed1e96d68398a418536e4f3ed6d5b` | REJECT |
| Estado revoked | `7219862cfdbabb2a4526ce0985f96ef36fe46a56b16e9ac7ba9281552c39c15b` | REJECT |
| Relación | `ed5e50396197ea78f59cd1964f957c7872ef70943b5d73ee27508b85546d257e` | REJECT |
| Táctica | `a800a9fd90287d5238dbcf09a6e3080c5357fee39877a0cc68ecfe75d440b23e` | REJECT |
| Referencia externa | `f5a6050970af1b2077d8b997823c053a0e0c73ec42e2aee9f4c163fbd3fb294b` | REJECT |
| Metadata de provenance | `f2b108d16b8f70413b79c59409eb5f3f7cbb3fb8233ab6050e879fac8a482d8a` | REJECT |

Un fallo de reemplazo preservó el snapshot previamente válido.

Sin embargo, la misma API pública permite
`load_snapshot(path, expected_artifact_digest=None)`. Las seis copias mutadas
fueron aceptadas por ese camino como ATT&CK 19.2. Además,
`ATTACKCatalogStore.publish()` instala un `ATTACKCatalogSnapshot` sin repetir la
verificación del artefacto. Ninguno de estos caminos es alcanzable directamente
por el HTTP actual, pero incumplen el requisito expreso de que no exista una API
alternativa capaz de omitir la verificación.

**Decisión P05-SEC-001: PARTIAL.** El runtime predeterminado quedó protegido; la
frontera de integridad aún tiene bypass programático.

## C. Wheel/sdist Distribution Reaudit

Se creó un `git archive` de `HEAD`, se construyeron wheel y sdist desde ese árbol
versionado y se inspeccionaron ambos:

```text
wheel: icylens_api-0.4.1-py3-none-any.whl (1,726,436 bytes)
sdist: icylens_api-0.4.1.tar.gz (1,765,869 bytes)
resource: app/attack/data/enterprise-attack-19.2.json.gz
resource bytes: 1,541,193
resource SHA-256: 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88
```

Wheel y sdist incluyeron el snapshot, `app.attack.__init__` y
`app.attack.data.__init__`. El wheel se instaló de forma no editable con
`pip --target` y se ejecutó con Python aislado desde un directorio temporal. Los
módulos efectivos procedieron del destino instalado, no de `C:\icylens`.

La carga offline produjo Enterprise ATT&CK 19.2, T1059 activo con nombre
`Command and Scripting Interpreter`, y estos conteos:

```text
objects=26086, tactics=15, techniques=858, subtechniques=493,
relationships=21262, active=697, retired=161
```

**Decisión P05-REL-002: FIXED.** La advertencia no bloqueante del sdist por falta
de README dentro de `apps/api` permanece como limpieza de release.

## D. Worker Ownership Reaudit

El manager compartido conserva cada `concurrent.futures.Future` hasta su término
real. La reproducción independiente confirmó:

- timeout del cliente: `active=1`, `owned_workers=1` mientras el thread seguía;
- shutdown normal esperó al worker y terminó con `active=0`, `owned_workers=0`;
- cuatro workers simultáneos fueron admitidos y el quinto rechazado;
- una excepción tardía fue observada y el slot liberado;
- cancelar al cliente no canceló ni liberó prematuramente el worker;
- dos subsistemas usan la misma instancia con límite global cuatro;
- lifespan normal terminó con manager cerrado, cero workers y executor apagado.

Un worker resistente mantuvo visible el drain pendiente; el sistema no declaró
un cierre exitoso mientras seguía ejecutándose. Esto es correcto.

La reproducción requerida de cancelación durante shutdown descubrió una brecha:

```text
shutdown_cancel_signal=CancelledError
worker_running=False
active=0
owned_workers=0
closed=True
shutdown_complete=False
executor_shutdown=False
executor_threads_alive=['audit-close-cancel_0']
```

El callback conservó ownership hasta que el worker terminó, pero la cancelación
interrumpió `aclose()` antes de `ThreadPoolExecutor.shutdown()`. El executor y su
thread quedaron vivos hasta una segunda llamada manual a `aclose()`. El lifespan
espera `aclose()` directamente y no garantiza ese segundo intento.

**Decisión P05-CONC-003: PARTIAL.** Timeout y shutdown normal están corregidos;
shutdown cancelado todavía puede quedar incompleto sin recuperación automática.

## E. Privacy Reaudit

Se enviaron canaries únicos de command line, token, executable path, username,
hostname, file path, registry target, valores de configuración, IPs, puertos,
endpoint, source identifier, producer y attributes.

Resultados serializados:

| Ruta | HTTP | Canary filtrado | Resultado funcional |
|---|---:|---|---|
| `/api/v1/behavior/rules/evaluate` | 200 | Ninguno | 4 reglas matched; IDs conservados; `[REDACTED]` presente |
| `/api/v1/behavior/analyze` | 200 | Ninguno | `complete` |
| `/api/v1/behavior/attack/map` | 200 | Ninguno | assessment generado |

No aparecieron canaries en los logs capturados. El modelo impide combinar
`redacted=true` con el valor original y exige `redacted=true` para el marcador.

**Decisión P05-PRIV-004: FIXED.** La sustitución es efectiva y no altera el
resultado lógico de reglas.

## F. Cross-Module Regression

El wheel usa el mismo loader estricto predeterminado que el checkout. Mapping y
análisis unificado comparten una capacidad global de cuatro. Los resultados
unificados conservaron contratos y estados conservadores, sin convertir
asociaciones ATT&CK en afirmaciones de compromiso. No se introdujo I/O de host,
ejecución de comandos ni persistencia en Phase 05.

## G. Independent Adversarial Tests

Además de las suites existentes se ejecutaron arneses temporales independientes
para:

- seis alteraciones semánticamente válidas del snapshot;
- preservación del snapshot anterior ante reemplazo fallido;
- carga con pin y con pin explícitamente deshabilitado;
- build desde `git archive`, inspección e instalación no editable;
- timeout, cancelación del cliente, excepción tardía, cuatro workers y quinto
  rechazo, worker resistente, cierre repetido y cancelación durante shutdown;
- canaries de privacidad por tres endpoints y logs;
- OpenAPI, ATT&CK status, T1059 y lifespan normal.

La suite correctiva pasó **16/16 en 12.40 s**. La suite Phase 05 con
`PYTHONASYNCIODEBUG=1` y warnings como errores pasó **202/202 en 49.68 s**.

## H. Quality Gate

El gate obligatorio, sin reducir thresholds, produjo:

| Control | Resultado |
|---|---|
| Ruff lint | PASS |
| Ruff format | PASS — 158 archivos |
| mypy strict | PASS — 132 archivos fuente |
| pytest | PASS — 908/908 en 218.72 s |
| statement/branch coverage | PASS — 94.50% |
| pip check | PASS |
| `git diff --check` antes del informe | PASS |
| OpenAPI smoke | PASS |

## I. Findings Matrix

| Finding | Original Failure | Independent Reproduction | Current Behavior | Decision |
|---|---|---|---|---|
| P05-SEC-001 | Snapshot modificado aceptado | Seis mutaciones con provenance/conteos conservados | Camino predeterminado rechaza; `expected_artifact_digest=None` acepta todas y `publish()` omite el artefacto | **PARTIAL** |
| P05-REL-002 | Snapshot ausente del wheel | Build desde `git archive`, inspección, instalación y carga offline | Wheel y sdist contienen el recurso correcto; import instalado verificado | **FIXED** |
| P05-CONC-003 | Worker perdido durante shutdown | Timeout, cancelaciones, excepción, saturación y cancelación de `aclose()` | Ownership normal correcto; cancelación de shutdown deja executor abierto hasta segundo cierre | **PARTIAL** |
| P05-PRIV-004 | Valores sensibles expuestos con `redacted=true` | Canaries completos por rules/analyze/map y logs | Sin filtraciones; marcador representa sustitución real | **FIXED** |

## J. Residual Risks

Bloqueantes de aceptación Phase 05:

1. API programática capaz de deshabilitar el pin del snapshot o publicar un
   snapshot sin acreditar el artefacto.
2. `aclose()` no es resistente a la cancelación del propio shutdown; puede dejar
   el executor abierto y el lifecycle incompleto.

Riesgos conocidos no bloqueantes para uso educativo local una vez corregidos los
anteriores: ausencia de tag `v0.4.1`, dependencias sin lock reproducible y warning
de README del sdist. Para producción pública siguen faltando autenticación,
autorización, controles distribuidos, aislamiento fuerte y hardening operativo.

## K. Educational Readiness

**BLOCKED.** La funcionalidad educativa nominal es estable y las dos correcciones
restantes no son explotables directamente por el HTTP actual, pero las reglas de
aceptación exigen cuatro hallazgos completamente FIXED. Dos permanecen PARTIAL.

## L. Public Production Readiness

**NOT READY.** Además de los dos bloqueantes de esta reauditoría, el servicio no
dispone de los controles de identidad, aislamiento y coordinación distribuida
necesarios para exposición pública hostil.

## M. Final Phase 05 Decision

**BLOCKED.** No se crea `docs/PHASE_05_ACCEPTANCE.md`. Un Quality Gate verde no
compensa los fallos reproducibles de frontera de integridad y cancelación de
shutdown.

## N. Git Handoff

No se modificó código funcional, tests, thresholds ni configuración. No se
crearon ramas, commits, tags ni pushes. El árbol estaba limpio al iniciar; este
informe y la actualización histórica del audit report son los únicos cambios de
la reauditoría.

## O. Release Recommendation

No publicar ni etiquetar `0.4.1` todavía. Realizar un checkpoint correctivo
acotado para eliminar el bypass del pin en APIs de runtime y hacer que el cierre
sea cancellation-safe o deje una señal pública y recuperable de cierre
incompleto. Repetir exactamente las reproducciones independientes antes de una
nueva decisión.

## P. Phase 06 Authorization

**NO AUTORIZADA.** Phase 06 debe permanecer detenida hasta que P05-SEC-001 y
P05-CONC-003 obtengan decisión FIXED en una nueva reauditoría.

## Q. Post-Audit Remediation Addendum — Checkpoint 05.07.2

Date: 2026-10-26. Base: `b821eb9e2f71967de8fdff0e87351c4a84d0102b`, branch
`main`. This addendum records changes made after the independent audit above. It
does not retroactively rewrite the historical PARTIAL decisions, and it is not a
substitute for the required independent re-run on a clean commit.

### Q.1 P05-SEC-001 — Remediated and ready for independent closure

The production trust boundary no longer exposes a caller-controlled digest or an
unverified publication path:

- `build_snapshot_from_stix()` always pins `ATTACK_SOURCE_SHA256`; the
  `expected_source_digest` parameter was removed.
- `load_snapshot()` always verifies the artifact; the
  `expected_artifact_digest` parameter was removed.
- `VerifiedAttackCatalogSnapshot` checks the compressed bytes against the
  repository pin with `hmac.compare_digest` before gzip/JSON/parse.
- `ATTACKCatalogStore.load()` uses only the verified path.
- `ATTACKCatalogStore.publish()` requires the exact verified type, rechecks the
  pin and assigns atomically.
- Unverified fixture helpers are private (`_build_fixture_snapshot_from_stix`,
  `_load_fixture_snapshot`) and cannot be published. The runtime never calls
  them.

Final reproduction:

```text
load_snapshot(expected_artifact_digest=None): TypeError
build_snapshot_from_stix(expected_source_digest=None): TypeError
load_verified_snapshot(mutated): REJECT (artifact digest)
load_snapshot(mutated): REJECT (artifact digest)
publish(unverified fixture): REJECT
```

The new suite covers five semantic mutations, corrupt/empty/truncated input, a
single compressed-byte change, unverified publication, subclass spoofing,
failed-load preservation, repeated loads, the packaged resource and application
composition.

### Q.2 P05-CONC-003 — Remediated and ready for independent closure

A single internal close task now owns shutdown. It is registered before any
await, `aclose()` waits through `asyncio.shield`, and worker release is
idempotent. Cancelling one, several or every waiter cannot cancel the drain or
leave the executor open. The manager exposes `shutdown_complete`, consumes late
worker exceptions, drains futures outside the state lock and verifies zero
workers/active before completing.

Final reproduction with one resistant worker and three cancelled waiters:

```text
after all waiters cancelled: closed=True, shutdown_complete=False,
  active=1, owned_workers=1, executor_shutdown=False
after worker release: shutdown_complete=True, active=0,
  owned_workers=0, executor_shutdown=True
```

The second state was reached without another `aclose()` call. Tests cover no
workers, first/second/remaining/all waiters cancelled, immediate cancellation,
cancellation before the coroutine's first step, late failure, resistant worker,
four workers plus fifth rejection, and the shared manager.

Documented semantics: cancelling a task before its coroutine's first step means
close never started; no state was mutated and the caller can retry. Python
threads cannot be force-killed, so shutdown waits for real completion.

### Q.3 Verification and distribution evidence

- Focused Phase 05 suite with `PYTHONASYNCIODEBUG=1` and warnings as errors:
  **228 passed**.
- Affected ATT&CK/security suites: **84 passed** (42 + 16 + 26).
- Full Quality Gate: **934/934 passed**, **94.51%** coverage, Ruff, format,
  mypy strict and `pip check` PASS.
- `git diff --check`: no errors (only Windows CRLF notices).
- OpenAPI smoke: HTTP 200, 33 paths.
- Prepared-tree build: wheel **1,726,161 bytes**, sdist **1,771,175 bytes**.
  Both contain the 1,541,193-byte snapshot with SHA-256
  `916eabb1...a0bc88`; the sdist includes the new test file.
- Non-editable install into an isolated temporary target outside the checkout:
  `app` imported from that target, version `0.4.1`, ATT&CK 19.2 offline with
  counts 26,086/15/858/493/21,262 and active `T1059`. `pip check` PASS.

P05-REL-002 and P05-PRIV-004 remain **FIXED** with no regression.

### Q.4 Current status

| Finding | Historical decision | Current remediation state |
|---|---|---|
| P05-SEC-001 | PARTIAL | **FIXED, pending independent confirmation** |
| P05-REL-002 | FIXED | **FIXED** |
| P05-CONC-003 | PARTIAL | **FIXED, pending independent confirmation** |
| P05-PRIV-004 | FIXED | **FIXED** |

Checkpoint 05.07.2 is **PASS as remediation**. Phase 05 final acceptance remains
**BLOCKED** until a new independent reaudit repeats the adversarial scenarios on
a clean commit. No `PHASE_05_ACCEPTANCE.md`, tag or Phase 06 authorization is
created here.

## R. Final Independent Reaudit - 2026-10-26 - BLOCKED

### R.1 Repository state

- Branch: `main`.
- `HEAD` and `origin/main`:
  `b821eb9e2f71967de8fdff0e87351c4a84d0102b`.
- Latest tag: `v0.4.0`; package metadata remains `0.4.1`.
- No 05.07.2 commit exists. The fixes, new test file and checkpoint documents
  are uncommitted working-tree changes.
- The audit did not modify application code, existing tests, thresholds or
  configuration. It did not add, commit, tag, branch or push.

### R.2 Result matrix

| Finding | Final decision | Independent evidence |
|---|---|---|
| P05-SEC-001 | **PARTIAL / BLOCKED** | Byte-level tampering and unverified publication are rejected, but a verified object can be mutated after verification and then published. |
| P05-REL-002 | **FIXED for produced artifacts** | Wheel and sdist contain the pinned snapshot; isolated install loads ATT&CK 19.2 offline. Release provenance still lacks a commit. |
| P05-CONC-003 | **FIXED for worker ownership** | All waiters can be cancelled, a resistant worker still drains, `shutdown_complete=True`, zero active/owned workers and executor shut down. |
| P05-PRIV-004 | **FIXED** | Canaries absent from rule, unified-analysis and mapping responses, status, and captured logs. |

### R.3 P05-SEC-001 residual bypass

The expected rejections still work:

```text
artifact 1541193 916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88
load_snapshot(expected_artifact_digest=None): TypeError
build_snapshot_from_stix(expected_source_digest=None): TypeError
five semantic mutations / byte variants: REJECT (artifact digest)
publish(mutated _artifact): REJECT (artifact digest)
publish(unverified fixture): REJECT
manual verified(tampered bytes): REJECT (artifact digest)
```

The residual bypass is that `VerifiedAttackCatalogSnapshot` exposes mutable
slots. `publish()` checks the current `_artifact` pin but trusts `_snapshot`:

```python
verified = load_verified_snapshot()
tampered = dataclasses.replace(
    verified.snapshot,
    techniques_by_id={
        **verified.snapshot.techniques_by_id,
        "T1059": verified.snapshot.techniques_by_id["T1059"].model_copy(
            update={"name": "TAMPERED AFTER VERIFICATION"}
        ),
    },
)
verified._snapshot = tampered
ATTACKCatalogStore().publish(verified)
```

Observed:

```text
post-set verified.snapshot T1059: TAMPERED AFTER VERIFICATION
publish(mutated _snapshot): ACCEPTED -> TAMPERED AFTER VERIFICATION
```

The same result is possible through `object.__setattr__` or by constructing an
empty verified instance with `object.__new__` and assigning an official
`_artifact` plus a tampered `_snapshot`. This is an in-process integrity bypass,
not an HTTP-reachable route: no request handler accepts a verified object. It
nevertheless breaks the claimed publication boundary and prevents Phase 05
acceptance.

Required correction: make the verified result effectively immutable, or make
`publish()` derive a fresh snapshot from the pinned artifact bytes instead of
trusting a caller-visible cached object. Add a regression that mutates
`_snapshot` and confirms rejection. Do not implement that correction in this
audit.

### R.4 Worker and lifespan evidence

Independent manager scenarios passed with warnings as errors:

```text
all waiters cancelled mid: closed=True, shutdown_complete=False,
  active=1, owned=1, executor_shutdown=False
after release: closed=True, shutdown_complete=True, active=0,
  owned=0, executor_shutdown=True
```

Also passed: immediate cancellation before the first step with retry, no
workers, four workers plus fifth rejection, late worker exception, and no
remaining manager tasks. Actual FastAPI lifespan cancellation drained the
worker and reached `shutdown_complete=True`.

Additional observation `P05-CONC-008` (LOW): when the lifespan exit task itself
is cancelled, the shielded worker manager still drains, but the subsequent
`kev_store`, `epss_service`, KEV client and NVD client `aclose()` calls are
skipped. In a process that continues after a cancelled shutdown, those are
orphaned resources. This is outside the worker-ownership repair but should be
recorded as a lifecycle residual risk.

### R.5 Distribution, privacy and quality evidence

- Wheel: `1,726,161` bytes, SHA-256
  `078de40021b88ca10b95a77c686baa6be38840e3b8f3b56a493140c74ae3f11a`.
- Sdist: `1,771,175` bytes, SHA-256
  `d01576229f8f1305ed48b1db2f76006821280ca939741945d906931bb2a1fbb9`.
- Both contain the `1,541,193`-byte snapshot with SHA-256
  `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`.
- Isolated non-editable install outside the checkout: `app` imported from the
  target, version `0.4.1`, ATT&CK 19.2 provenance pinned, 858 techniques,
  15 tactics, 21,262 relationships, active `T1059`.
- Privacy canaries were absent from `/api/v1/behavior/rules/evaluate` (200),
  `/api/v1/behavior/analyze` (200), `/api/v1/behavior/attack/map` (200),
  `/api/v1/attack/status` (200), serialized results and captured logs.
- Full Quality Gate: **934 passed**, **94.51%** coverage, Ruff, Ruff format,
  mypy strict and `pip check` PASS.
- New checkpoint suite with debug/warnings-as-errors: **26 passed**. It does not
  cover the verified-object mutation above.
- OpenAPI: 200, 33 paths; behavior analyze, behavior attack map and attack status
  present.

### R.6 Final decision

Phase 05 final acceptance: **BLOCKED**. P05-SEC-001 remains partially open and
requires a new remediation plus independent reproduction. P05-REL-002 is fixed
in the produced artifacts but not represented by a clean release commit.
P05-CONC-003 worker ownership is fixed; the non-worker lifespan cleanup caveat
remains. P05-PRIV-004 is fixed.

No `docs/PHASE_05_ACCEPTANCE.md` was created. No tag, commit, push, branch or
release was created or changed. Phase 06 remains **NOT AUTHORIZED**.

Educational/local readiness: **READY WITH CONDITIONS** for the current local
API/demo, because the HTTP surface and offline catalog work and the residual
bypass is in-process only. Public production readiness: **NOT READY**.

Required next action: fix the verified-object publication boundary, add a
regression for `_snapshot` mutation, commit the complete checkpoint, rebuild
from that commit, and repeat the A-R acceptance audit. The non-worker lifespan
cleanup caveat should be decided explicitly before any production claim.

### S. Post-Reaudit Correction - 2026-10-26

This section records remediation after section R. Section R remains the
historical independent verdict. This is remediation evidence, not a new
independent acceptance audit.

#### S.1 P05-SEC-001 correction

`ATTACKCatalogStore.publish()` no longer trusts the caller-visible cached
snapshot:

- `VerifiedAttackCatalogSnapshot` blocks normal attribute assignment and deletion.
- `validated_snapshot()` re-verifies the artifact pin and reparses the pinned
  bytes, ignoring `_snapshot`.
- `publish()` installs that freshly derived snapshot under `_snapshot_lock`.
- `load()` uses the same verified publication path.
- A rejected publication preserves the previously published catalog.

Three regressions were added to
`tests/test_phase05_security_remediation_0572.py`:

- post-verification `_snapshot` mutation cannot change published content;
- a synthetic cached snapshot is ignored in favor of the artifact-derived one;
- failed republish does not replace a valid catalog.

Two existing identity assertions were changed from `is` to `==`
(`test_attack_knowledge.py:116`,
`test_phase05_security_remediation.py:157`). Publication now intentionally
installs a fresh artifact-derived object, so identity is no longer the contract.
No security threshold or test count was reduced.

Direct reproduction:

```text
official T1059: Command and Scripting Interpreter
normal assignment: REJECT VerifiedAttackCatalogSnapshot is immutable
cached snapshot after mutation: TAMPERED AFTER VERIFICATION
published T1059: Command and Scripting Interpreter
synthetic cached snapshot ignored; published official catalog
mutated artifact publish: REJECT Snapshot artifact digest does not match the pin
previous catalog preserved
tampered bytes load: REJECT Snapshot artifact digest does not match the pin
P05-SEC-001 CORRECTION PASS
```

#### S.2 Verification evidence

- Corrective suite with `PYTHONASYNCIODEBUG=1` and warnings as errors:
  **29 passed**.
- Focused Phase 05 suite: **231 passed** (previous baseline was 228; three new
  regressions were added).
- Full Quality Gate: **937 passed**, coverage **94.49%** (threshold unchanged),
  Ruff, Ruff format, mypy strict and `pip check` PASS.
- Wheel: **1,726,481** bytes, SHA-256
  `81e729aa7420cbb002b1c01749dc2be9d004e058d9f758230a712fbceb4f3525`.
- Sdist: **1,772,448** bytes, SHA-256
  `10e502865c8c24c1bd4842b1fcda281111b33313860835867f4fa76e744170d8`.
- Both archives contain the corrected `catalog.py` (SHA-256
  `1de36702df5b66c367e88a837fa0d0220674bb86de65839e8f28df18ad411f15`) and the
  **1,541,193**-byte snapshot with SHA-256
  `916eabb166a794e881f23be2fe9bf5590bdba5117db892fc405af636eaa0bc88`.
- Isolated non-editable install outside the checkout: `app` imported from the
  target, version `0.4.1`, ATT&CK 19.2 with 858 techniques, 15 tactics, 21,262
  relationships and active `T1059`; cached-mutation and tampered-artifact
  checks passed.

#### S.3 P05-CONC-008 review

The observation remains unchanged and was not expanded into this security
correction: when the lifespan exit task itself is cancelled, the shielded worker
manager still completes, but the later non-worker `aclose()` calls are skipped.

```text
manager complete True
resource closes after cancelled lifespan []
resource closes after explicit cleanup ['kev_store', 'epss_service', 'kev_client', 'nvd_client']
```

This is a low-severity lifecycle residual for a process that continues after a
cancelled shutdown, not a worker-ownership or P05-SEC-001 regression. It should
be decided separately before any production claim.

#### S.4 Decision

P05-SEC-001 technical remediation passes its reproduction, focused tests, full
gate and rebuilt-install checks. Phase 05 final acceptance remains **BLOCKED**
until an independent audit repeats the A-R checks on a clean commit containing
these changes. No `PHASE_05_ACCEPTANCE.md`, tag, commit, push, branch or release
was created. Phase 06 remains **NOT AUTHORIZED**.
