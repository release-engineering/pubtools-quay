try:
    import mock
except ImportError:
    from unittest import mock

import pytest

from pubtools._quay.utils.stepper import Step, StepFailedError, Stepper, Secret


class StepOK(Step):
    """Test step with not functionality.

    Step stores "result-of-useless-step" in the results
    """

    NAME = "StepOK"

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        self.results.results["value"] = "result-of-useless-step"


class StepOKCounter(Step):
    """Test step with counter functionality.

    Step updates counter with every run
    """

    NAME = "StepOKCounter"

    def _init_details(self):
        self._details["counter"] = 0

    def _update_details(self, counter_inc):
        self._details["counter"] += counter_inc

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        self.update_details(1)


class StepError(Step):
    """Test step rasing ValueError exception."""

    NAME = "StepError"

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        raise ValueError("Step Error")


class StepFailure(Step):
    """Test step raising SteFailedError exception."""

    NAME = "StepFailure"

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        raise StepFailedError()


class StepError2(Step):
    """Test step raising ValueError exception when executed less then x times.

    How many times step can beexecuted before stopping raising exception
    is indicate by first step argument
    """

    NAME = "StepError2"

    def _init_details(self):
        self._details["counter"] = 0

    def _update_details(self, counter_inc):
        self._details["counter"] += counter_inc

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        self.update_details(1)
        if self._details["counter"] < self.step_args[0]:
            raise ValueError("Step Error")


class StepWithDetails(Step):
    """Test step generating some details."""

    NAME = "StepWithDetails"

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        for i, _ in enumerate(self.step_args):
            self.update_details({"index": i, "value": "done"})

    def _init_details(self):
        self._details["items"] = []
        for _ in self.step_args:
            self._details["items"].append("ready")

    def _update_details(self, details):
        self._details["items"][details["index"]] = details["value"]


class StepWithCondition(Step):
    """Test step depending on another step results."""

    NAME = "StepWithCondition"

    def _run(self, on_update=None):  # pylint: disable=unused-argument
        self.results.results["value"] = "result-step-with-condition"

    def _pre_run(self):
        condition_step_name = self.step_kwargs["condition_step_name"]
        if self._shared_results[condition_step_name].results["value"]:
            self.skip = True


@pytest.fixture
def fixture_isodate_now():
    counter = {"i": 0}
    with mock.patch("pubtools._quay.utils.stepper.isodate_now") as mocked:
        mocked.side_effect = lambda: [
            counter.__setitem__("i", counter["i"] + 1),
            "isodate_now_" + str(counter["i"]),
        ][1]
        yield mocked


def test_stepper_ok():
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepOK("2", (), {}, shared_storage))
    stepper.run()


def test_stepper_ok_dump(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (Secret("password"),), {}, shared_storage))
    stepper.add_step(StepOK("2", ("foo param",), {}, shared_storage))
    stepper_dump1 = stepper.dump()
    stepper.run()
    stepper_dump2 = stepper.dump()
    expected_output1 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": ["*CENSORED*"],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": None,
                    "skip": False,
                    "skip_reason": "",
                    "finished": None,
                    "skipped": None,
                    "state": "ready",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepOK",
                "step_args": ["foo param"],
                "step_kwargs": {},
                "uid": "2",
                "details": {},
                "stats": {
                    "started": None,
                    "skip": False,
                    "skip_reason": "",
                    "finished": None,
                    "skipped": None,
                    "state": "ready",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump1 == expected_output1
    expected_output2 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": ["*CENSORED*"],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepOK",
                "step_args": ["foo param"],
                "step_kwargs": {},
                "uid": "2",
                "details": {},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump2 == expected_output2


def test_stepper_error(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepError("1", (), {}, shared_storage))
    with pytest.raises(ValueError):
        stepper.run()
    stepper_dump2 = stepper.dump()
    expected_output2 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepError",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "error",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump2 == expected_output2


def test_stepper_failure(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {
            "StepOK": StepOK,
            "StepFailure": StepFailure,
            "StepWithDetails": StepWithDetails,
        }
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepFailure("1", (), {}, shared_storage))
    stepper.run()
    stepper_dump2 = stepper.dump()
    expected_output2 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepFailure",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "failed",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump2 == expected_output2


def test_stepper_on_error(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepError("1", (), {}, shared_storage))
    on_error_clbk = mock.MagicMock()
    with pytest.raises(ValueError):
        stepper.run(on_error=on_error_clbk)
    assert len(on_error_clbk.mock_calls) > 0


def test_stepper_with_details(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepWithDetails("1", ("item1", "item2"), {}, shared_storage))
    stepper_dump1 = stepper.dump()
    stepper.run()
    stepper_dump2 = stepper.dump()
    expected_output1 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": None,
                    "finished": None,
                    "skip": False,
                    "skip_reason": "",
                    "skipped": None,
                    "state": "ready",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepWithDetails",
                "step_args": ["item1", "item2"],
                "step_kwargs": {},
                "uid": "1",
                "details": {"items": ["ready", "ready"]},
                "stats": {
                    "started": None,
                    "finished": None,
                    "skip": False,
                    "skip_reason": "",
                    "skipped": None,
                    "state": "ready",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump1 == expected_output1
    expected_output2 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepWithDetails",
                "step_args": ["item1", "item2"],
                "step_kwargs": {},
                "uid": "1",
                "details": {"items": ["done", "done"]},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump2 == expected_output2


def test_stepper_state_set_invalid(
    fixture_isodate_now,
):  # pylint: disable=unused-argument
    step = StepOK("2", (), {}, {})
    with pytest.raises(ValueError):
        step.set_state("some_invalid_state")


def test_stepper_load_unstarted(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepWithDetails("1", ("item1", "item2"), {}, shared_storage))
    stepper_dump1 = stepper.dump()

    stepper2 = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    stepper2.load(stepper_dump1)
    stepper_dump2 = stepper2.dump()

    assert stepper_dump1 == stepper_dump2


def test_stepper_load_started(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(StepWithDetails("1", ("item1", "item2"), {}, shared_storage))
    stepper.add_step(StepError("1", (), {}, shared_storage))
    with pytest.raises(ValueError):
        stepper.run()
    stepper_dump1 = stepper.dump()
    stepper2 = Stepper(
        {"StepOK": StepOK, "StepError": StepError, "StepWithDetails": StepWithDetails}
    )
    stepper2.load(stepper_dump1)
    stepper_dump2 = stepper2.dump()
    assert stepper_dump1 == stepper_dump2


def test_stepper_skip(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {
            "StepOK": StepOK,
            "StepError": StepError,
            "StepWithDetails": StepWithDetails,
            "StepWithCondition": StepWithCondition,
        }
    )
    shared_storage = {}
    stepper.add_step(StepOK("1", (), {}, shared_storage))
    stepper.add_step(
        StepWithCondition("1", (), {"condition_step_name": "StepOK:1"}, shared_storage)
    )
    stepper.run()
    stepper_dump1 = stepper.dump()
    expected_output1 = {
        "steps": [
            {
                "name": "StepOK",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {
                    "results": {"value": "result-of-useless-step"},
                    "errors": {},
                },
            },
            {
                "name": "StepWithCondition",
                "step_args": [],
                "step_kwargs": {"condition_step_name": "StepOK:1"},
                "uid": "1",
                "details": {},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": True,
                    "skip_reason": "",
                    "skipped": True,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump1 == expected_output1


def test_stepper_rerun(fixture_isodate_now):  # pylint: disable=unused-argument
    stepper = Stepper(
        {
            "StepOKCounter": StepOKCounter,
            "StepError": StepError,
            "StepError2": StepError2,
            "StepWithDetails": StepWithDetails,
        }
    )
    shared_storage = {}
    stepper.add_step(StepOKCounter("1", (), {}, shared_storage))
    stepper.add_step(StepError2("1", (2,), {}, shared_storage))
    stepper.add_step(StepWithDetails("1", ("item1", "item2"), {}, shared_storage))
    with pytest.raises(ValueError):
        stepper.run()
    stepper_dump1 = stepper.dump()
    stepper.run()
    stepper_dump2 = stepper.dump()
    expected_output1 = {
        "steps": [
            {
                "name": "StepOKCounter",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {"counter": 1},
                "stats": {
                    "started": "isodate_now_1",
                    "finished": "isodate_now_2",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
            {
                "name": "StepError2",
                "step_args": [2],
                "step_kwargs": {},
                "uid": "1",
                "details": {"counter": 1},
                "stats": {
                    "started": "isodate_now_3",
                    "finished": "isodate_now_4",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "error",
                },
                "results": {"results": {}, "errors": {}},
            },
            {
                "name": "StepWithDetails",
                "step_args": ["item1", "item2"],
                "step_kwargs": {},
                "uid": "1",
                "details": {"items": ["ready", "ready"]},
                "stats": {
                    "started": None,
                    "finished": None,
                    "skip": False,
                    "skip_reason": "",
                    "skipped": None,
                    "state": "ready",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump1 == expected_output1
    expected_output2 = {
        "steps": [
            {
                "name": "StepOKCounter",
                "step_args": [],
                "step_kwargs": {},
                "uid": "1",
                "details": {"counter": 1},
                "stats": {
                    "started": None,
                    "finished": "isodate_now_5",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
            {
                "name": "StepError2",
                "step_args": [2],
                "step_kwargs": {},
                "uid": "1",
                "details": {"counter": 2},
                "stats": {
                    "started": None,
                    "finished": "isodate_now_6",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
            {
                "name": "StepWithDetails",
                "step_args": ["item1", "item2"],
                "step_kwargs": {},
                "uid": "1",
                "details": {"items": ["done", "done"]},
                "stats": {
                    "started": "isodate_now_7",
                    "finished": "isodate_now_8",
                    "skip": False,
                    "skip_reason": "",
                    "skipped": False,
                    "state": "finished",
                },
                "results": {"results": {}, "errors": {}},
            },
        ],
        "shared_results": {},
    }
    assert stepper_dump2 == expected_output2
