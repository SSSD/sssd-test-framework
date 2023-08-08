"""Pytest fixtures."""

from __future__ import annotations

from functools import partial

import pytest

from .roles.client import Client


def pytest_configure(config: pytest.Config):
    """
    Pytest hook: register multihost plugin.
    """

    # register additional markers
    config.addinivalue_line(
        "markers",
        "builtwith(feature): Run test only if SSSD was built with given feature",
    )


def builtwith(item: pytest.Function, feature: str, client: Client) -> bool:
    if feature not in client.features:
        raise ValueError(f"{item.nodeid}::{item.originalname}: unknown feature '{feature}' for @pytest.mark.builtwith")

    return client.features[feature]


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if not isinstance(item, pytest.Function):
        raise TypeError(f"Unexpected item type: {type(item)}")

    for mark in item.iter_markers("builtwith"):
        if len(mark.args) != 1:
            raise ValueError(f"{item.nodeid}::{item.originalname}: invalid arguments for @pytest.mark.builtwith")

        feature = mark.args[0]
        item.add_marker(
            pytest.mark.require(partial(builtwith, item=item, feature=feature), f"SSSD was not built with {feature}")
        )
