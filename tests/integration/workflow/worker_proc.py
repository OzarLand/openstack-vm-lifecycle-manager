"""A real worker process running the dummy strategy, for kill/stop tests (L2).

Same ``Worker`` main loop and engine as production; only the registry (dummy definition) and the DB URL source
differ. ``OVLM_TEST_CRASHPOINT`` is honoured here (the production entry point refuses it).
"""

from __future__ import annotations

import os
import signal
import sys
from types import FrameType

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from ovlm.config import Settings
from ovlm.observability.logging import configure_logging
from ovlm.worker.main import Worker
from ovlm.workflow.crashpoint import install_from_env
from ovlm.workflow.engine import EngineConfig, WorkflowEngine
from ovlm.workflow.ids import new_id
from ovlm.workflow.registry import Registry
from tests.integration.workflow.dummy import DummyDefinition


def main() -> int:
    settings = Settings(process_role="worker")
    configure_logging("worker", "INFO")
    install_from_env()
    db = create_engine(make_url(os.environ["WF_WORKER_URL"]), pool_pre_ping=True)
    wid = new_id()
    engine = WorkflowEngine(
        db,
        Registry([DummyDefinition(db, wid)]),
        EngineConfig.from_settings(settings),
        worker_id=wid,
    )
    worker = Worker(settings, db, engine)

    def _handler(signum: int, _frame: FrameType | None) -> None:
        worker.request_stop(signal.Signals(signum).name)

    signal.signal(signal.SIGTERM, _handler)
    print(f"worker-id {wid}", flush=True)  # noqa: T201
    worker.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
