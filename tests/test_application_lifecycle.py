import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deploy_platform.application_lifecycle import (
    ApplicationLifecycle, ApplicationState, ApplicationLifecycleError
)


def test_initial_state_is_created():
    lc = ApplicationLifecycle()
    assert lc.state == ApplicationState.CREATED


def test_happy_path_transitions():
    lc = ApplicationLifecycle()
    lc.transition(ApplicationState.STARTING)
    lc.transition(ApplicationState.RUNNING)
    lc.transition(ApplicationState.HEALTHY)
    assert lc.state == ApplicationState.HEALTHY


def test_running_can_crash_directly():
    lc = ApplicationLifecycle(ApplicationState.RUNNING)
    lc.transition(ApplicationState.CRASHED)
    assert lc.state == ApplicationState.CRASHED


def test_healthy_can_oscillate_to_unhealthy_and_back():
    lc = ApplicationLifecycle(ApplicationState.HEALTHY)
    lc.transition(ApplicationState.UNHEALTHY)
    lc.transition(ApplicationState.HEALTHY)
    assert lc.state == ApplicationState.HEALTHY


def test_stopped_can_restart():
    lc = ApplicationLifecycle(ApplicationState.STOPPED)
    lc.transition(ApplicationState.STARTING)
    assert lc.state == ApplicationState.STARTING


def test_crashed_can_restart():
    lc = ApplicationLifecycle(ApplicationState.CRASHED)
    lc.transition(ApplicationState.STARTING)
    assert lc.state == ApplicationState.STARTING


def test_invalid_transition_rejected():
    lc = ApplicationLifecycle()
    try:
        lc.transition(ApplicationState.HEALTHY)
        assert False, "deveria ter rejeitado CREATED -> HEALTHY"
    except ApplicationLifecycleError:
        pass
    assert lc.state == ApplicationState.CREATED


def test_stopped_cannot_go_directly_to_healthy():
    lc = ApplicationLifecycle(ApplicationState.STOPPED)
    try:
        lc.transition(ApplicationState.HEALTHY)
        assert False
    except ApplicationLifecycleError:
        pass


def test_force_set_bypasses_transition_map():
    lc = ApplicationLifecycle(ApplicationState.CREATED)
    lc.force_set(ApplicationState.UNHEALTHY)
    assert lc.state == ApplicationState.UNHEALTHY
