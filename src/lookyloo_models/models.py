#!/usr/bin/env python3

from __future__ import annotations

import re

from datetime import datetime, timedelta
from io import BufferedIOBase
from typing import Literal, Any, Mapping
from urllib.parse import urlparse, urlsplit

import dateparser
import ua_parser
import orjson

from pydantic import (
    BaseModel,
    field_validator,
    model_validator,
    ValidationError,
    ValidationInfo,
)


def refang(line: str) -> str:
    """
    Refangs a line of text.

    :param str line: the line of text to reverse the defanging of.
    :return: the "dirty" line with actual URIs
    """
    # Refang from https://bitbucket.org/johannestaas/defang/src/master/defang/__init__.py
    # to avoid the dependency.
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


class CookieError(LookylooModelsException):
    """Can handle Pydantic validation errors"""

    def __init__(
        self, message: str, pydantic_validation_errors: ValidationError | None = None
    ) -> None:
        super().__init__(message)
        self.pydantic_validation_errors = pydantic_validation_errors


class LookylooCaptureSettingsError(CaptureSettingsError):
    pass


def orjson_custom(obj: Any) -> Any:
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, BaseModelDump):
        return obj.redis_dump()
    if isinstance(obj, BaseModel):
        return obj.model_dump(exclude_none=True)
    return obj


class BaseModelDump(BaseModel):
    _domain_for_cookies: str | None = None

    @model_validator(mode="before")
    @classmethod
    def empty_str_to_none(cls, data: Any) -> dict[str, Any] | Any:
        if isinstance(data, dict):
            # Make sure all the strings are stripped, and None if empty.
            to_return: dict[str, Any] = {}
            for k, v in data.items():
                if isinstance(v, (bytes, str)):
                    if v_stripped := v.strip():
                        to_return[k] = v_stripped
                else:
                    to_return[k] = v

            if "url" in to_return and to_return["url"]:
                # if we have the URL, we can initialize the domain that can then be
                # used in the cookies, if needed.
                url = to_return["url"]
                if isinstance(url, str):
                    #  In case we get a defanged url at this stage.
                    _url = refang(url)
                    if not re.match("(http(s?)|data|file):", _url, re.I):
                        # without a prefix, urlsplit fails.
                        _url = f"http://{_url}"
                    try:
                        cls._domain_for_cookies = urlsplit(_url).hostname
                    except Exception:
                        pass
            return to_return

        return data

    def redis_dump(self) -> Mapping[str | bytes, bytes | float | int | str]:
        """Redis/Valkey compatible dump"""
        mapping_capture: dict[str | bytes, bytes | float | int | str] = {}
        for key, value in dict(self).items():
            if value is None:
                continue
            if isinstance(value, bool):
                mapping_capture[key] = 1 if value else 0
            elif isinstance(value, (BaseModel, BaseModelDump, set, list, dict)):
                if value:
                    mapping_capture[key] = orjson.dumps(
                        value, default=orjson_custom
                    ).decode()
            elif isinstance(value, (bytes, float, int, str)):
                # NOTE: ignore if empty str/bytes, keep for 0 / 0.0
                if value not in ["", b""]:
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

    @model_validator(mode="after")
    def check_complete_cookie(self) -> Cookie:
        # a cookie must have a name, a value and either a URL OR a domain and a path
        if not self.name or not self.value:
            raise CookieError("A cookie requires a name and a value")
        if not self.url and not (self.domain and self.path):
            raise CookieError("A cookie requires either a url, or a domain and a path")
        return self

    @field_validator("expires", mode="before")
    @classmethod
    def load_expires(cls, expires: datetime | str | float | int | None) -> float | None:
        if isinstance(expires, (float, int)):
            return expires
        if isinstance(expires, str):
            try:
                if _expires := dateparser.parse(expires):
                    return _expires.timestamp()
            except ValidationError as e:
                raise CookieError(f"Invalid expire entry: {expires}.", e)
        if isinstance(expires, datetime):
            return expires.timestamp()

        # When the expires value is something else, just make it 10 days from now
        return (datetime.now() + timedelta(days=10)).timestamp()


class CaptureSettings(BaseModelDump):
    """The capture settings that can be passed to Lacus."""

    url: str | None = None
    document_name: str | None = None
    document: str | None = None
    browser: Literal["chromium", "firefox", "webkit"] = 'chromium'
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

    # for interactive sessions
    interactive: bool = False
    interactive_ttl: int = 600

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

    @model_validator(mode="after")
    def check_capture_element(self) -> CaptureSettings:
        # set browser based on UA if not set yet
        if not self.browser:
            if self.user_agent:
                parsed_string = ua_parser.parse(self.user_agent).with_defaults()
                browser_family = parsed_string.user_agent.family.lower()
                if browser_family.startswith('chrom'):
                    self.browser = 'chromium'
                elif browser_family.startswith('firefox'):
                    self.browser = 'firefox'
                else:
                    self.browser = 'webkit'
            else:
                self.browser = 'chromium'

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

    @field_validator("viewport", mode="before")
    @classmethod
    def load_viewport_json(cls, viewport: Any) -> dict[str, Any] | None:
        if not viewport:
            return None
        if isinstance(viewport, str):
            # might be a json dump, try to load it and ignore otherwise
            try:
                viewport = orjson.loads(viewport)
            except orjson.JSONDecodeError:
                # Viewport invalid, ignoring.
                return None
        return viewport

    @field_validator("http_credentials", mode="before")
    @classmethod
    def load_http_credentials_json(cls, http_credentials: Any) -> dict[str, Any] | None:
        if not http_credentials:
            return None
        if isinstance(http_credentials, str):
            # might be a json dump, try to load it and ignore otherwise
            try:
                http_credentials = orjson.loads(http_credentials)
            except orjson.JSONDecodeError:
                # Credentials invalid, ignoring.
                return None
        return http_credentials

    @field_validator("geolocation", mode="before")
    @classmethod
    def load_geolocation_json(cls, geolocation: Any) -> dict[str, Any] | None:
        if not geolocation:
            return None
        if isinstance(geolocation, str):
            # might be a json dump, try to load it and ignore otherwise
            try:
                geolocation = orjson.loads(geolocation)
            except orjson.JSONDecodeError:
                # Geolocation invalid, ignoring.
                return None
        return geolocation

    @field_validator("cookies", mode="before")
    @classmethod
    def load_cookies_json(
        cls, cookies: Any, info: ValidationInfo
    ) -> list[dict[str, Any]] | None:

        def __prepare_cookie(cookie: dict[str, Any]) -> dict[str, str | float | bool]:
            if len(cookie) == 1:
                # {'name': 'value'} => {'name': 'name', 'value': 'value'}
                name, value = cookie.popitem()
                if name and value:
                    cookie = {
                        "name": name,
                        "value": value,
                    }
            if not cookie.get("name") or not cookie.get("value"):
                # invalid cookie, ignoring
                return {}

            # set a domain and path on case we're missing it
            if not cookie.get("url") or not (
                cookie.get("domain") and cookie.get("path")
            ):
                if isinstance(info.context, dict):
                    cookie["domain"] = info.context.get("domain", None)
                elif cls._domain_for_cookies:
                    cookie["domain"] = cls._domain_for_cookies
                cookie["path"] = "/"

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
            except orjson.JSONDecodeError:
                # Cookies are invalid, ignoring.
                return None
        if isinstance(cookies, dict):
            # might be a single cookie in the format name: value, make it a list
            cookies = [cookies]
        if isinstance(cookies, list):
            # make sure the cookies are in the right format
            to_return = []
            for cookie in cookies:
                if isinstance(cookie, dict):
                    if _c := __prepare_cookie(cookie):
                        to_return.append(_c)
                elif isinstance(cookie, Cookie):
                    to_return.append(cookie)
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

    @field_validator("interactive_ttl", mode="after")
    @classmethod
    def check_interactive_ttl(cls, interactive_ttl: int) -> int:
        if interactive_ttl < 1 or interactive_ttl > 600:
            raise CaptureSettingsError(
                f"interactive_ttl must be between 1 and 600 seconds, got {interactive_ttl}."
            )
        return interactive_ttl


class AutoReportSettings(BaseModel):
    email: str | None = None
    comment: str | None = None


class MonitorCaptureSettings(BaseModelDump):
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

            # In order to properly pass the cookies to playwright,
            # each of then must have a name, a value and either a domain + path or a URL
            # Name and value are mandatory, and we cannot auto-fill them.
            # If the cookie doesn't have a domain + path OR a URL, we fill the domain
            # with the hostname of the URL we try to capture and the path with "/"
            if isinstance(cookies, dict):
                # single cookie, most probably
                cookies = [cookies]

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

    ressources_ignore_domains: tuple[str, ...] = tuple()
    ressources_ignore_regexes: tuple[str, ...] = tuple()

    ignore_ips: bool = False

    skip_failed_captures: bool = True


class NotificationSettings(BaseModelDump):
    """The notification settings for a monitoring"""

    email: str
