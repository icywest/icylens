from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import CancelledError as FutureCancelledError
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Lock
from typing import TypeVar, cast

T = TypeVar("T")


class SynchronousWorkerManager:
    """Own a bounded set of synchronous workers until their real completion."""

    def __init__(self, maximum: int, *, thread_name_prefix: str = "icylens-phase05"):
        if maximum < 1:
            raise ValueError("worker capacity must be positive")
        self.maximum = maximum
        self._active = 0
        self._closed = False
        self._shutdown_complete = False
        self._state_lock = Lock()
        self._close_task: asyncio.Task[None] | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=maximum,
            thread_name_prefix=thread_name_prefix,
        )
        self._workers: set[Future[object]] = set()
        self._waiters: set[asyncio.Future[object]] = set()

    @property
    def active(self) -> int:
        with self._state_lock:
            return self._active

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    @property
    def owned_workers(self) -> int:
        with self._state_lock:
            return len(self._workers)

    @property
    def shutdown_complete(self) -> bool:
        with self._state_lock:
            return self._shutdown_complete

    async def try_acquire(self) -> bool:
        """Compatibility reservation used by direct capacity tests."""
        with self._state_lock:
            if self._closed or self._active >= self.maximum:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        """Release a compatibility reservation exactly once."""
        with self._state_lock:
            if self._active <= 0:
                raise RuntimeError("worker capacity release is unbalanced")
            self._active -= 1

    def try_submit(self, operation: Callable[[], T]) -> Future[T] | None:
        """Admit without queueing and retain the future through real completion."""
        with self._state_lock:
            if self._closed or self._active >= self.maximum:
                return None
            self._active += 1
            try:
                future = self._executor.submit(operation)
            except BaseException:
                self._active -= 1
                raise
            worker = cast(Future[object], future)
            self._workers.add(worker)
        worker.add_done_callback(self._worker_completed)
        return future

    def _release_worker(self, future: Future[object]) -> None:
        with self._state_lock:
            if future in self._workers:
                self._workers.remove(future)
                if self._active <= 0:
                    raise RuntimeError("worker capacity release is unbalanced")
                self._active -= 1

    def _worker_completed(self, future: Future[object]) -> None:
        try:
            future.exception()
        except FutureCancelledError:
            pass
        finally:
            self._release_worker(future)

    async def wait(self, future: Future[T], *, timeout: float) -> T:
        """Wait without transferring cancellation to the owned worker future."""
        waiter = asyncio.wrap_future(future)
        tracked = cast(asyncio.Future[object], waiter)
        self._waiters.add(tracked)

        def consume_and_remove(completed: asyncio.Future[object]) -> None:
            self._waiters.discard(completed)
            if completed.cancelled():
                return
            completed.exception()

        tracked.add_done_callback(consume_and_remove)
        return await asyncio.wait_for(asyncio.shield(waiter), timeout=timeout)

    @staticmethod
    def _consume_close_exception(task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        task.exception()

    def _start_close(self) -> asyncio.Task[None]:
        with self._state_lock:
            if self._close_task is None:
                self._closed = True
                task = asyncio.get_running_loop().create_task(
                    self._close_impl(),
                    name="icylens-worker-manager-close",
                )
                self._close_task = task
                task.add_done_callback(self._consume_close_exception)
            return self._close_task

    async def _close_impl(self) -> None:
        with self._state_lock:
            workers = tuple(self._workers)

        if workers:
            drains = tuple(asyncio.wrap_future(worker) for worker in workers)
            await asyncio.gather(*drains, return_exceptions=True)
            for worker in workers:
                self._release_worker(worker)

        self._executor.shutdown(wait=True, cancel_futures=False)
        with self._state_lock:
            if self._workers or self._active:
                raise RuntimeError("worker manager closed before complete drain")
            self._shutdown_complete = True

    async def aclose(self) -> None:
        """Stop admission and drain every owned worker; safe to call repeatedly.

        A single internal close task owns the real shutdown. Callers await it
        through ``asyncio.shield`` so cancelling one or all waiters cannot cancel
        the shared drain or leave the executor open.
        """
        task = self._start_close()
        await asyncio.shield(task)
