import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from server.lifecycle import Lifecycle, ServerState, LifecycleError


def test_valid_transition_sequence():
    lc = Lifecycle()
    assert lc.state == ServerState.INITIALIZING
    lc.transition(ServerState.CONFIGURED)
    lc.transition(ServerState.BINDING)
    lc.transition(ServerState.RUNNING)
    lc.transition(ServerState.DRAINING)
    lc.transition(ServerState.STOPPING)
    lc.transition(ServerState.STOPPED)
    assert lc.state == ServerState.STOPPED


def test_invalid_transition_rejected():
    lc = Lifecycle()
    with pytest.raises(LifecycleError):
        lc.transition(ServerState.RUNNING)


def test_binding_failure_path():
    lc = Lifecycle()
    lc.transition(ServerState.CONFIGURED)
    lc.transition(ServerState.BINDING)
    lc.transition(ServerState.FAILED)
    assert lc.state == ServerState.FAILED
