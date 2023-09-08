"""Pytest fixtures."""

from __future__ import annotations

from functools import partial

import pytest

from .misc import to_list_of_strings
from .roles.base import BaseRole


def pytest_configure(config: pytest.Config):
    """
    Pytest hook: register multihost plugin.
    """

    # register additional markers
    config.addinivalue_line(
        "markers",
        "builtwith(feature): Run test only if SSSD was built with given feature",
    )


def builtwith(item: pytest.Function, requirements: dict[str, str], **kwargs: BaseRole):
    def value_error(msg: str) -> ValueError:
        return ValueError(f"{item.nodeid}::{item.originalname}: @pytest.mark.builtwith: {msg}")

    errors: list[str] = []
    for role, features in requirements.items():
        if role not in kwargs:
            raise value_error(f"unknown fixture '{role}'")

        if not isinstance(kwargs[role], BaseRole):
            raise value_error(f"fixture '{role}' is not instance of BaseRole")

        obj = kwargs[role]
        for feature in to_list_of_strings(features):
            if feature not in obj.features:
                raise value_error(f"unknown feature '{feature}' in '{role}'")

            if not obj.features[feature]:
                errors.append(f'{role} does not support "{feature}"')

    if len(errors) == 1:
        return (False, errors[0])
    elif len(errors) > 1:
        return (False, str(errors))

    # All requirements were passed
    return True


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> None:
    if not isinstance(item, pytest.Function):
        raise TypeError(f"Unexpected item type: {type(item)}")

    for mark in item.iter_markers("builtwith"):
        requirements: dict[str, str] = {}

        if len(mark.args) == 1 and not mark.kwargs:
            # @pytest.mark.builtwith("files-provider")
            #  -> check if "files-provider" is supported by client
            requirements["client"] = mark.args[0]
        elif not mark.args and mark.kwargs:
            # @pytest.mark.builtwith(client="passkey", ipa="passkey") ->
            # -> check if "passkey" is supported by both client and ipa
            requirements = dict(mark.kwargs)
        else:
            raise ValueError(f"{item.nodeid}::{item.originalname}: invalid arguments for @pytest.mark.builtwith")

        item.add_marker(pytest.mark.require(partial(builtwith, item=item, requirements=requirements)))
