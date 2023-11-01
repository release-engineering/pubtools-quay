import os

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from pubtools._quay.utils.tracing import instrument_func, TracingWrapper

from unittest.mock import Mock
import pytest


def test_instrument_func():
    os.environ["PUB_OTEL_TRACING"] = "true"

    mock_export = Mock()
    OTLPSpanExporter.export = mock_export

    @instrument_func(args_to_attr=True)
    def func_normal():
        return 1

    @instrument_func()
    def func_with_exception():
        raise Exception()

    assert TracingWrapper()
    assert func_normal() == 1
    with pytest.raises(Exception):
        func_with_exception()

    TracingWrapper.processor.force_flush()
    mock_export.assert_called()
