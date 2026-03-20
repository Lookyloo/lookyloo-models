#!/usr/bin/env python3

from __future__ import annotations

import re

from datetime import datetime, timedelta
from io import BufferedIOBase
from typing import Literal, Any, Mapping
from urllib.parse import urlparse

import dateparser
import orjson

from pydantic import BaseModel, field_validator, model_validator, ValidationError
from pydantic_core import from_json


# Refang from https://bitbucket.org/johannestaas/defang/src/master/defang/__init__.py
# to avoid the dependency.


def refang(line: str) -> str:
    """
    Refangs a line of text.

    :param str line: the line of text to reverse the defanging of.
    :return: the "dirty" line with actual URIs
    """
    ZERO_WIDTH_CHARACTER = "​"
    if all(char == ZERO_WIDTH_CHARACTER for char in line[1::2]):
        return line[::2]
    dirty_line = re.sub(r"\((\.|dot)\)", ".", line, flags=re.IGNORECASE)
    dirty_line = re.sub(r"\[(\.|dot)\]", ".", dirty_line, flags=re.IGNORECASE)
    dirty_line = re.sub(
        r"(\s*)h([x]{1,2})p([s]?)\[?:\]?//",
        r"\1http\3://",
        dirty_line,
        flags=re.IGNORECASE,
    )
    dirty_line = re.sub(
        r"(\s*)(s?)fxp(s?)\[?:\]?//", r"\1\2ftp\3://", dirty_line, flags=re.IGNORECASE
    )
    dirty_line = re.sub(
        r"(\s*)\(([-.+a-zA-Z0-9]{1,12})\)\[?:\]?//",
        r"\1\2://",
        dirty_line,
        flags=re.IGNORECASE,
    )
    return dirty_line


class LookylooModelsException(Exception):
    pass


class UnexpectedTypeDump(LookylooModelsException):
    pass


class CaptureSettingsError(LookylooModelsException):
    """Can handle Pydantic validation errors"""

    def __init__(
        self, message: str, pydantic_validation_errors: ValidationError | None = None
    ) -> None:
        super().__init__(message)
        self.pydantic_validation_errors = pydantic_validation_errors


class LookylooCaptureSettingsError(CaptureSettingsError):
    pass


class BaseModelDump(BaseModel):
    def redis_dump(self) -> Mapping[str | bytes, bytes | float | int | str]:
        """Redis/Valkey compatible dump"""
        mapping_capture: dict[str | bytes, bytes | float | int | str] = {}
        for key, value in dict(self).items():
            if value is None:
                continue
            if isinstance(value, bool):
                mapping_capture[key] = 1 if value else 0
            elif isinstance(value, BaseModelDump):
                mapping_capture[key] = value.redis_dump()
            elif isinstance(value, BaseModel):
                mapping_capture[key] = value.model_dump_json()
            elif isinstance(value, set):
                if value:
                    mapping_capture[key] = orjson.dumps(list(value))
            elif isinstance(value, (list, dict)):
                if value:
                    mapping_capture[key] = orjson.dumps(value)
            elif isinstance(value, (bytes, float, int, str)):
                if value in ["", b""]:
                    # Just ignore
                    pass
                else:
                    mapping_capture[key] = value
            else:
                raise UnexpectedTypeDump(f'Unexpected type "{type(value)}" for "{key}"')
        return mapping_capture


class ViewportSettings(BaseModel):
    width: int
    height: int


class GeolocationSettings(BaseModel):
    latitude: float
    longitude: float


class HttpCredentialsSettings(BaseModel):
    username: str
    password: str


class Cookie(BaseModelDump):
    name: str
    value: str
    url: str | None = None
    domain: str | None = None
    path: str | None = None
    expires: float | None = None
    httpOnly: bool | None = None
    secure: bool | None = None
    sameSite: Literal["Lax", "None", "Strict"] | None = None
    partitionKey: str | None = None


class CaptureSettings(BaseModelDump):
    """The capture settings that can be passed to Lacus."""

    url: str | None = None
    document_name: str | None = None
    document: str | None = None
    browser: Literal["chromium", "firefox", "webkit"] | None = None
    device_name: str | None = None
    user_agent: str | None = None
    proxy: str | dict[str, str] | None = None
    general_timeout_in_sec: int | None = None
    cookies: list[Cookie] | None = None
    # NOTE: should be that, but StorageState doesn't define the indexeddb
    # storage: StorageState | None = None
    storage: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    http_credentials: HttpCredentialsSettings | None = None
    geolocation: GeolocationSettings | None = None
    timezone_id: str | None = None
    locale: str | None = None
    color_scheme: Literal["dark", "light", "no-preference", "null"] | None = None
    java_script_enabled: bool = True
    viewport: ViewportSettings | None = None
    referer: str | None = None
    with_screenshot: bool = True
    with_favicon: bool = True
    allow_tracking: bool = False
    headless: bool = True
    init_script: str | None = None
    with_trusted_timestamps: bool = False
    final_wait: int = 5

    # for automatic depth capture
    depth: int = 0
    rendered_hostname_only: bool = True  # Note: only used if depth is > 0

    # internal
    socks5_dns_resolver: str | list[str] | None = None
    force: bool = False
    recapture_interval: int = 300
    priority: int = 0
    max_retries: int | None = None
    uuid: str | None = None

    @model_validator(mode="before")
    @classmethod
    def empty_str_to_none(cls, data: Any) -> dict[str, Any] | Any:
        if isinstance(data, dict):
            # Make sure all the strings are stripped, and None if empty.
            to_return: dict[str, Any] = {}
            for k, v in data.items():
                if isinstance(v, str):
                    if v_stripped := v.strip():
                        if v_stripped[0] in ["{", "["]:
                            to_return[k] = from_json(v_stripped)
                        else:
                            to_return[k] = v_stripped
                else:
                    to_return[k] = v
            return to_return
        return data

    @model_validator(mode="after")
    def check_capture_element(self) -> CaptureSettings:
        if self.document_name and not self.document:
            raise CaptureSettingsError(
                "You must provide a document if you provide a document name"
            )
        if self.document and not self.document_name:
            raise CaptureSettingsError(
                "You must provide a document name if you provide a document"
            )

        if self.url and (self.document or self.document_name):
            raise CaptureSettingsError(
                "You cannot provide both a URL and a document to capture"
            )
        if not self.url and not (self.document and self.document_name):
            raise CaptureSettingsError(
                "You must provide either a URL or a document to capture"
            )
        return self

    @field_validator("url", mode="after")
    @classmethod
    def load_url(cls, url: str | None) -> str | None:
        if isinstance(url, str):
            #  In case we get a defanged url at this stage.
            _url = refang(url)
            if re.match("(http(s?)|data|file):", _url, re.I):
                # if the URL starts with any of that, return immediately
                return _url
            return f"http://{_url}"
        return url

    @field_validator("document_name", mode="after")
    @classmethod
    def load_document_name(cls, document_name: str | None) -> str | None:
        if isinstance(document_name, str):
            if "." not in document_name:
                # The browser will simply display the file as text if there is no extension.
                # Just add HTML as a fallback, as it will be the most comon one.
                document_name = f"{document_name}.html"
            return document_name
        return None

    @field_validator("browser", mode="before")
    @classmethod
    def load_browser(cls, browser: Any) -> str | None:
        if isinstance(browser, str) and browser in ["chromium", "firefox", "webkit"]:
            return browser
        # There are old captures where the browser is not a playwright browser name, so we ignore it.
        return None

    @field_validator("proxy", mode="before")
    @classmethod
    def load_proxy_json(cls, proxy: Any) -> str | dict[str, str] | None:
        if not proxy:
            return None
        if isinstance(proxy, str):
            # Just the proxy
            return proxy
        elif isinstance(proxy, dict):
            return proxy
        return None

    @field_validator("cookies", mode="before")
    @classmethod
    def load_cookies_json(cls, cookies: Any) -> list[dict[str, Any]] | None:

        def __prepare_cookie(cookie: dict[str, Any]) -> dict[str, str | float | bool]:
            if len(cookie) == 1:
                # {'name': 'value'} => {'name': 'name', 'value': 'value'}
                name, value = cookie.popitem()
                if name and value:
                    cookie = {"name": name, "value": value}
            if not cookie.get("name") or not cookie.get("value"):
                # invalid cookie, ignoring
                return {}

            if "expires" in cookie and isinstance(cookie["expires"], str):
                # Make it a float, as expected by Playwright
                try:
                    cookie["expires"] = datetime.fromisoformat(
                        cookie["expires"]
                    ).timestamp()
                except ValueError:
                    # if it ends with a Z, it fails in python < 3.12
                    # And we don't really care.
                    # make it expire 10 days from now
                    cookie["expires"] = (
                        datetime.now() + timedelta(days=10)
                    ).timestamp()

            if "sameSite" in cookie and isinstance(cookie["sameSite"], str):
                # we may get the value as lax, none, or strict when it should be Lax, None, or Strict
                # the values from browser.cookies.getAll are weird (used in the web extension):
                # https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/cookies/SameSiteStatus
                if cookie["sameSite"] in ["lax", "unspecified"]:
                    cookie["sameSite"] = "Lax"
                if cookie["sameSite"] == "strict":
                    cookie["sameSite"] = "Strict"
                if cookie["sameSite"] in ["none", "no_restriction"]:
                    cookie["sameSite"] = "None"

            if "partitionKey" in cookie and cookie["partitionKey"] is None:
                # We expect a string, pop the entry if None.
                del cookie["partitionKey"]

            return cookie

        if not cookies:
            return None
        if isinstance(cookies, str):
            # might be a json dump, try to load it and ignore otherwise
            try:
                cookies = orjson.loads(cookies)
            except orjson.JSONDecodeError as e:
                # Cookies are invalid, ignoring.
                print(f"Broken cookie: {e}")
                return None
        if isinstance(cookies, dict):
            # might be a single cookie in the format name: value, make it a list
            cookies = [cookies]
        if isinstance(cookies, list):
            # make sure the cookies are in the right format
            to_return = []
            for cookie in cookies:
                if isinstance(cookie, dict):
                    to_return.append(__prepare_cookie(cookie))
            return to_return
        return None

    @field_validator("storage", mode="before")
    @classmethod
    def load_storage_json(cls, storage: Any) -> dict[str, Any] | None:
        """That's the storage as exported from Playwright:
        https://playwright.dev/python/docs/api/class-browsercontext#browser-context-storage-state
        """
        if not storage:
            return None
        if isinstance(storage, str):
            # might be a json dump, try to load it and ignore otherwise
            try:
                storage = orjson.loads(storage)
            except orjson.JSONDecodeError:
                # storage is invalid, ignoring.
                return None
        if isinstance(storage, dict) and "cookies" in storage and "origins" in storage:
            return storage
        return None

    @field_validator("headers", mode="before")
    @classmethod
    def load_headers_json(cls, headers: Any) -> dict[str, str] | None:
        if not headers:
            return None
        if isinstance(headers, str):
            # make it a dict
            new_headers = {}
            for header_line in headers.splitlines():
                if header_line and ":" in header_line:
                    splitted = header_line.split(":", 1)
                    if splitted and len(splitted) == 2:
                        header, h_value = splitted
                        if header.strip() and h_value.strip():
                            new_headers[header.strip()] = h_value.strip()
            return new_headers
        elif isinstance(headers, dict):
            return headers
        return None


class AutoReportSettings(BaseModel):
    email: str | None = None
    comment: str | None = None


class MonitorCaptureSettings(BaseModel):
    capture_settings: LookylooCaptureSettings | None = None
    frequency: str | None = None
    never_expire: bool = False
    expire_at: float | None = None
    collection: str | None = None

    compare_settings: CompareSettings | None = None
    notification: NotificationSettings | None = None

    # This UUID is used when we trigger an update on the settings
    monitor_uuid: str | None = None

    @field_validator("expire_at", mode="before")
    @classmethod
    def load_expire_at(cls, v: Any) -> float | None:
        if not v:
            return None
        if isinstance(v, datetime):
            return v.timestamp()
        elif isinstance(v, str):
            # try to make it a timestamp
            if d := dateparser.parse(v):
                return d.timestamp()
        return v


class LookylooCaptureSettings(CaptureSettings):
    """The capture settings that can be passed to Lookyloo"""

    listing: bool = False
    not_queued: bool = False
    auto_report: bool | AutoReportSettings | None = None  # {'email': , 'comment':}
    dnt: str | None = None  # Legacy, merged in the headers if present.
    parent: str | None = None
    remote_lacus_name: str | None = None
    categories: list[str] | None = None
    monitor_capture: MonitorCaptureSettings | None = None

    @field_validator("cookies", mode="before")
    @classmethod
    def load_cookies(cls, v: Any) -> list[dict[str, Any]] | None:
        # NOTE: Lookyloo can get the cookies in somewhat weird formats, mornalizing them
        if v:
            cookies: list[dict[str, str | bool]]
            if isinstance(v, BufferedIOBase):
                v = v.read()
            if isinstance(v, (str, bytes)):
                cookies = orjson.loads(v)
            elif isinstance(v, list):
                cookies = v
            else:
                raise LookylooCaptureSettingsError(
                    f"Unexpected type {type(v)} for cookies"
                )

            to_return: list[dict[str, str | bool]] = []
            for cookie in cookies:
                to_add: dict[str, str | bool]
                if "Host raw" in cookie and isinstance(cookie["Host raw"], str):
                    # Cookie export format for Cookie Quick Manager
                    u = urlparse(cookie["Host raw"]).netloc.split(":", 1)[0]
                    to_add = {
                        "path": cookie["Path raw"],
                        "name": cookie["Name raw"],
                        "httpOnly": cookie["HTTP only raw"] == "true",
                        "secure": cookie["Send for"] == "Encrypted connections only",
                        "expires": (datetime.now() + timedelta(days=10)).strftime(
                            "%Y-%m-%dT%H:%M:%S"
                        )
                        + "Z",
                        "domain": u,
                        "value": cookie["Content raw"],
                    }
                else:
                    # Cookie from lookyloo/playwright
                    to_add = cookie
                to_return.append(to_add)
            return to_return
        return None


class CompareSettings(BaseModelDump):
    """The settings that can be passed to the compare method on lookyloo side to filter out some differences"""

    ressources_ignore_domains: set[str] = set()
    ressources_ignore_regexes: set[str] = set()

    ignore_ips: bool = False

    skip_failed_captures: bool = True


class NotificationSettings(BaseModelDump):
    """The notification settings for a monitoring"""

    email: str
