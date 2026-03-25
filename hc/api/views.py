from __future__ import annotations

import email.policy
import logging
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from datetime import timedelta as td
from email import message_from_bytes
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID

from cronsim import CronSim, CronSimError
from django.conf import settings
from django.core.signing import BadSignature
from django.db import connection, transaction
from django.db.models import Prefetch
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import get_object_or_404
from django.utils.text import slugify
from django.utils.timezone import now
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from oncalendar import OnCalendar, OnCalendarError
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator
from pydantic_core import PydanticCustomError

from hc.accounts.models import Profile, Project
from hc.api.decorators import ApiRequest, authorize, authorize_read, cors
from hc.api.forms import FlipsFiltersForm
from hc.api.models import Channel, Check, Flip, Notification, Ping, prepare_durations
from hc.lib.badges import check_signature, get_badge_svg, get_badge_url
from hc.lib.signing import unsign_bounce_id
from hc.lib.string import is_valid_uuid_string, match_keywords
from hc.lib.tz import all_timezones, legacy_timezones

# added a logger so that when something goes wrong, there is a trace in logs,
# used __name__ as the logger name meaning log output is traceable to this exact file
logger = logging.getLogger(__name__)


class BadChannelException(Exception):
    def __init__(self, message: str):
        self.message = message


def guess_kind(schedule: str) -> str:
    if "\n" not in schedule.strip() and len(schedule.split()) == 5:
        return "cron"
    return "oncalendar"


class Spec(BaseModel):
    channels: str | None = None
    desc: str | None = None
    failure_kw: str | None = Field(None, max_length=200)
    filter_subject: bool | None = None
    filter_body: bool | None = None
    filter_http_body: bool | None = None
    filter_default_fail: bool | None = None
    grace: td | None = Field(None, ge=60, le=31536000)
    manual_resume: bool | None = None
    methods: Literal["", "POST"] | None = None
    name: str | None = Field(None, max_length=100)
    schedule: str | None = Field(None, max_length=100)
    slug: str | None = Field(None, max_length=100, pattern="^[a-z0-9-_]*$")
    start_kw: str | None = Field(None, max_length=200)
    subject: str | None = Field(None, max_length=200)
    subject_fail: str | None = Field(None, max_length=200)
    success_kw: str | None = Field(None, max_length=200)
    tags: str | None = None
    timeout: td | None = Field(None, ge=60, le=31536000)
    tz: str | None = None
    unique: list[Literal["name", "slug", "tags", "timeout", "grace"]] | None = None

    @model_validator(mode="before")
    @classmethod
    def check_nulls(cls, data: dict[str, Any]) -> dict[str, Any]:
        for k, v in data.items():
            if v is None:
                data[k] = 0.0
        return data

    @field_validator("timeout", "grace", mode="before")
    @classmethod
    def convert_to_timedelta(cls, v: Any) -> Any:
        if isinstance(v, int):
            return td(seconds=v)
        return v

    @field_validator("tz")
    @classmethod
    def check_tz(cls, v: str) -> str:
        if v in legacy_timezones:
            v = legacy_timezones[v]
        if v not in all_timezones:
            raise PydanticCustomError("tz_syntax", "not a valid timezone")
        return v

    @field_validator("schedule")
    @classmethod
    def check_schedule(cls, v: str) -> str:
        if guess_kind(v) == "cron":
            try:
                it = CronSim(v, datetime(2000, 1, 1))
                next(it)
            except (CronSimError, StopIteration):
                # log a warning with the bad value so operators can see what expressions clients are submitting 
                logger.warning("Invalid cron expression submitted: %r", v)
                raise PydanticCustomError("cron_syntax", "not a valid cron expression")
        else:
            try:
                oncalendar_it = OnCalendar(v, datetime(2000, 1, 1, tzinfo=timezone.utc))
                next(oncalendar_it)
            except (OnCalendarError, StopIteration):
                logger.warning("Invalid OnCalendar expression submitted: %r", v)
                raise PydanticCustomError("cron_syntax", "not a valid expression")
        return v

    def kind(self) -> str | None:
        if self.schedule:
            return guess_kind(self.schedule)
        if self.timeout:
            return "simple"
        return None


CUSTOM_ERRORS = {
    "too_long": "%s is too long",
    "string_too_long": "%s is too long",
    "string_type": "%s is not a string",
    "string_pattern_mismatch": "%s does not match pattern",
    "less_than_equal": "%s is too large",
    "greater_than_equal": "%s is too small",
    "int_type": "%s is not a number",
    "bool_type": "%s is not a boolean",
    "literal_error": "%s has unexpected value",
    "list_type": "%s is not an array",
    "cron_syntax": "%s is not a valid cron or OnCalendar expression",
    "tz_syntax": "%s is not a valid timezone",
    "time_delta_type": "%s is not a number",
}


def format_first_error(exc: ValidationError) -> str:
    first_error = exc.errors()[0]
    subject = first_error["loc"][0]
    if len(first_error["loc"]) == 2:
        subject = f"an item in '{subject}'"
    tmpl = CUSTOM_ERRORS[first_error["type"]]
    return "json validation error: " + tmpl % subject


def valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False


@csrf_exempt
@never_cache
def ping(
    request: HttpRequest,
    code: UUID,
    check: Check | None = None,
    action: str = "success",
    exitstatus: int | None = None,
) -> HttpResponse:
    if check is None:
        try:
            check = Check.objects.get(code=code)
        except Check.DoesNotExist:
            # logging to help the operators spot issues
            logger.info("Ping received for unknown check code: %s", code)
            return HttpResponseNotFound("not found")

    if exitstatus is not None and exitstatus > 255:
        # originally returned 400 with no log entry.
        # Exit status > 255 suggests a client bug and logging it with the check code helps with identifying the misbehaving client.
        logger.warning(
            "Invalid exit status %d received for check %s", exitstatus, check.code
        )
        return HttpResponseBadRequest("invalid url format")

    headers = request.META
    remote_addr = headers.get("HTTP_X_FORWARDED_FOR", headers["REMOTE_ADDR"])
    remote_addr = remote_addr.split(",")[0]

    if not valid_ip(remote_addr):
        parts = remote_addr.split(".")
        if len(parts) == 4 and ":" in parts[-1]:
            remote_addr = remote_addr.split(":")[0]

    scheme = headers.get("HTTP_X_FORWARDED_PROTO", "http")
    method = headers["REQUEST_METHOD"]
    ua = headers.get("HTTP_USER_AGENT", "")
    body = request.body[: settings.PING_BODY_LIMIT]

    if exitstatus is not None and exitstatus > 0:
        action = "fail"

    if check.methods == "POST" and method != "POST":
        action = "ign"

    if action != "ign" and check.filter_http_body:
        body_text = body.decode()
        if check.failure_kw and match_keywords(body_text, check.failure_kw):
            action = "fail"
        elif check.success_kw and match_keywords(body_text, check.success_kw):
            action = "success"
        elif check.start_kw and match_keywords(body_text, check.start_kw):
            action = "start"
        elif check.filter_default_fail:
            action = "fail"
        else:
            action = "ign"

    rid, rid_str = None, request.GET.get("rid")
    if rid_str is not None:
        if not is_valid_uuid_string(rid_str):
            # A malformed UUID in 'rid' suggests a client formatting bug and logging the bad value speeds up debugging.
            logger.warning(
                "Malformed rid parameter %r for check %s", rid_str, check.code
            )
            return HttpResponseBadRequest("invalid uuid format")
        rid = UUID(rid_str)

    # logging each ping with its check code, action, and source IP to give operators an audit trail and helps diagnose why a check changed state.
    logger.debug(
        "Ping received: check=%s action=%s remote_addr=%s method=%s",
        check.code,
        action,
        remote_addr,
        method,
    )

    check.ping(remote_addr, scheme, method, ua, body, action, rid, exitstatus)

    response = HttpResponse("OK")
    if settings.PING_BODY_LIMIT is not None:
        response["Ping-Body-Limit"] = str(settings.PING_BODY_LIMIT)
    response["Access-Control-Allow-Origin"] = "*"
    return response


@csrf_exempt
def ping_by_slug(
    request: HttpRequest,
    ping_key: str,
    slug: str,
    action: str = "success",
    exitstatus: int | None = None,
) -> HttpResponse:
    if slug != slug.lower():
        # logging the slug and ping_key helps identify which project/check is misconfigured.
        logger.warning(
            "Ping rejected: slug %r is not lowercase (ping_key=%s)", slug, ping_key
        )
        return HttpResponseBadRequest("invalid url format")

    created = False
    try:
        check = Check.objects.get(slug=slug, project__ping_key=ping_key)
    except Check.DoesNotExist:
        if request.GET.get("create") != "1":
            logger.info(
                "Ping for unknown slug=%r ping_key=%s (create not requested)",
                slug,
                ping_key,
            )
            return HttpResponseNotFound("not found")

        try:
            project = Project.objects.get(ping_key=ping_key)
        except Project.DoesNotExist:
            logger.warning(
                "Auto-create failed: no project with ping_key=%s slug=%r",
                ping_key,
                slug,
            ) 
            # tells operators that auto-create was attempted with an invalid ping_key, which may indicate a misconfigured integration.
            return HttpResponseNotFound("not found")

        check = Check(project=project, name=slug, slug=slug)
        check.save()
        check.assign_all_channels()
        created = True

        # log auto-created checks.
        logger.info(
            "Auto-created check: slug=%r project=%s", slug, project.code
        )

    except Check.MultipleObjectsReturned:
        # an error log for multiple checks sharing a slug.
        logger.error(
            "Ambiguous slug collision: slug=%r ping_key=%s", slug, ping_key
        )
        return HttpResponse("ambiguous slug", status=409)

    response = ping(request, check.code, check, action, exitstatus)
    if response.status_code == 200 and created:
        response.content = b"Created"
        response.status_code = 201
    return response


def _lookup(project: Project, spec: Spec) -> Check | None:
    if not spec.unique:
        return None

    for field_name in spec.unique:
        if getattr(spec, field_name) is None:
            return None

    existing_checks = Check.objects.filter(project=project)
    if "name" in spec.unique:
        existing_checks = existing_checks.filter(name=spec.name)
    if "slug" in spec.unique:
        existing_checks = existing_checks.filter(slug=spec.slug)
    if "tags" in spec.unique:
        existing_checks = existing_checks.filter(tags=spec.tags)
    if "timeout" in spec.unique:
        existing_checks = existing_checks.filter(timeout=spec.timeout)
    if "grace" in spec.unique:
        existing_checks = existing_checks.filter(grace=spec.grace)

    return existing_checks.first()


def _update(check: Check, spec: Spec, v: int) -> None:
    new_channels: Iterable[Channel] | None
    if spec.channels is None:
        new_channels = None
    elif spec.channels == "*":
        new_channels = Channel.objects.filter(project=check.project)
    elif spec.channels == "":
        new_channels = []
    else:
        new_channels = set()
        available = list(Channel.objects.filter(project=check.project))

        for s in spec.channels.split(","):
            if s == "":
                raise BadChannelException("empty channel identifier")

            matches = [c for c in available if str(c.code) == s or c.name == s]
            if len(matches) == 0:
                raise BadChannelException(f"invalid channel identifier: {s}")
            elif len(matches) > 1:
                raise BadChannelException(f"non-unique channel identifier: {s}")

            new_channels.add(matches[0])

    need_save = False
    if check.pk is None:
        need_save = True

    if spec.name is not None and check.name != spec.name:
        check.name = spec.name
        if v < 3:
            check.slug = slugify(spec.name)
        need_save = True

    kind = spec.kind()
    if kind == "simple":
        if check.kind != "simple" or check.timeout != spec.timeout:
            check.kind = "simple"
            check.timeout = spec.timeout
            need_save = True

    if kind in ("cron", "oncalendar"):
        if check.kind != kind or check.schedule != spec.schedule:
            check.kind = kind
            assert spec.schedule is not None
            check.schedule = spec.schedule
            need_save = True

    if spec.subject is not None:
        check.success_kw = spec.subject
        check.filter_subject = bool(check.success_kw or check.failure_kw)
        need_save = True

    if spec.subject_fail is not None:
        check.failure_kw = spec.subject_fail
        check.filter_subject = bool(check.success_kw or check.failure_kw)
        need_save = True

    for key in (
        "slug", "tags", "desc", "manual_resume", "methods", "tz", "start_kw",
        "success_kw", "failure_kw", "filter_subject", "filter_body",
        "filter_http_body", "filter_default_fail", "grace",
    ):
        val = getattr(spec, key)
        if val is not None and getattr(check, key) != val:
            setattr(check, key, val)
            need_save = True

    if need_save:
        check.alert_after = check.going_down_after()
        check.save()

    if new_channels is not None:
        check.channel_set.set(new_channels)


@authorize_read
def get_checks(request: ApiRequest) -> JsonResponse:
    q = Check.objects.filter(project=request.project)
    if not request.readonly:
        channel_q = Channel.objects.only("code")
        q = q.prefetch_related(Prefetch("channel_set", queryset=channel_q))

    tags = set(request.GET.getlist("tag"))
    for tag in tags:
        q = q.filter(tags__contains=tag)

    if slug := request.GET.get("slug"):
        q = q.filter(slug=slug)

    checks = []
    for check in q:
        if not tags or check.matches_tag_set(tags):
            checks.append(check.to_dict(readonly=request.readonly, v=request.v))

    # logging the project and number of returned checks to trace unexpected empty responses or large payload issues in production.
    logger.debug(
        "get_checks: project=%s returned %d checks (tags=%r, slug=%r)",
        request.project.code,
        len(checks),
        tags,
        request.GET.get("slug"),
    )

    return JsonResponse({"checks": checks})


@authorize
def create_check(request: ApiRequest) -> HttpResponse:
    try:
        spec = Spec.model_validate(request.json, strict=True)
    except ValidationError as e:
        error_msg = format_first_error(e)
        # log validation errors to reveal integration bugs on the client side and to help operators identify which API consumers are sending malformed requests.
        logger.warning(
            "create_check validation error: project=%s error=%r",
            request.project.code,
            error_msg,
        )
        return JsonResponse({"error": error_msg}, status=400)

    created = False
    check = _lookup(request.project, spec)
    if check is None:
        if request.project.num_checks_available() <= 0:
            # log when the check limit has been reached.
            logger.warning(
                "create_check rejected: project=%s has reached check limit",
                request.project.code,
            )
            return HttpResponseForbidden()

        check = Check(project=request.project)
        created = True

    try:
        _update(check, spec, request.v)
    except BadChannelException as e:
        logger.warning(
            "create_check bad channel: project=%s error=%r",
            request.project.code,
            e.message,
        )
        return JsonResponse({"error": e.message}, status=400)

    # log creation of a check successfully
    if created:
        logger.info(
            "Check created: code=%s name=%r project=%s",
            check.code,
            check.name,
            request.project.code,
        )

    return JsonResponse(check.to_dict(v=request.v), status=201 if created else 200)


@csrf_exempt
@cors("GET", "POST")
def checks(request: HttpRequest) -> HttpResponse:
    if request.method == "POST":
        return create_check(request)
    return get_checks(request)


@cors("GET")
@csrf_exempt
@authorize
def channels(request: ApiRequest) -> JsonResponse:
    q = Channel.objects.filter(project=request.project)
    channels = [ch.to_dict() for ch in q]
    return JsonResponse({"channels": channels})


@authorize_read
def get_check(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        # log attempts of a project accessing another project's check.
        logger.warning(
            "get_check forbidden: check=%s belongs to project=%s but request is from project=%s",
            code,
            check.project_id,
            request.project.id,
        )
        return HttpResponseForbidden()

    return JsonResponse(check.to_dict(readonly=request.readonly, v=request.v))


@cors("GET")
@csrf_exempt
@authorize_read
def get_check_by_unique_key(request: ApiRequest, unique_key: str) -> HttpResponse:
    for check in request.project.check_set.all():
        if check.unique_key == unique_key:
            return JsonResponse(check.to_dict(readonly=request.readonly, v=request.v))
    return HttpResponseNotFound()


@authorize
def update_check(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        logger.warning(
            "update_check forbidden: check=%s project mismatch (request project=%s)",
            code,
            request.project.id,
        )
        return HttpResponseForbidden()

    try:
        spec = Spec.model_validate(request.json, strict=True)
    except ValidationError as e:
        error_msg = format_first_error(e)
        logger.warning(
            "update_check validation error: check=%s project=%s error=%r",
            code,
            request.project.code,
            error_msg,
        )
        return JsonResponse({"error": error_msg}, status=400)

    with transaction.atomic():
        check = get_object_or_404(Check.objects.select_for_update(), code=code)
        try:
            _update(check, spec, request.v)
        except BadChannelException as e:
            logger.warning(
                "update_check bad channel: check=%s error=%r", code, e.message
            )
            return JsonResponse({"error": e.message}, status=400)

    # log successful updates to provide an audit trail of configuration changes
    logger.info(
        "Check updated: code=%s project=%s", check.code, request.project.code
    )

    return JsonResponse(check.to_dict(v=request.v))


@authorize
def delete_check(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        logger.warning(
            "delete_check forbidden: check=%s project mismatch (request project=%s)",
            code,
            request.project.id,
        )
        return HttpResponseForbidden()

    with transaction.atomic():
        check = get_object_or_404(Check.objects.select_for_update(), code=code)
        check.delete()

    # log the deletion of a check since it is a destructive action that cannot be reversed.
    logger.info(
        "Check deleted: code=%s name=%r project=%s", code, check.name, request.project.code
    )

    return JsonResponse(check.to_dict(v=request.v))


@csrf_exempt
@cors("POST", "DELETE", "GET")
def single(request: HttpRequest, code: UUID) -> HttpResponse:
    if request.method == "POST":
        return update_check(request, code)
    if request.method == "DELETE":
        return delete_check(request, code)
    return get_check(request, code)


@cors("POST")
@csrf_exempt
@authorize
def pause(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        return HttpResponseForbidden()

    if check.status == "paused":
        return JsonResponse(check.to_dict(v=request.v))

    check.create_flip("paused", mark_as_processed=True)
    check.status = "paused"
    check.last_start = None
    check.alert_after = None
    check.save()
    check.project.update_next_nag_dates()

    # log the pausing of a check since it silences alerts. 
    logger.info("Check paused: code=%s project=%s", check.code, request.project.code)

    return JsonResponse(check.to_dict(v=request.v))


@cors("POST")
@csrf_exempt
@authorize
def resume(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        return HttpResponseForbidden()

    if check.status != "paused":
        # log invalid attempts to resume a non-paused check
        logger.warning(
            "resume rejected: check=%s is not paused (status=%s)",
            check.code,
            check.status,
        )
        return HttpResponse("check is not paused", status=409)

    check.create_flip("new", mark_as_processed=True)
    check.status = "new"
    check.last_start = None
    check.last_ping = None
    check.alert_after = None
    check.save()

    logger.info("Check resumed: code=%s project=%s", check.code, request.project.code)

    return JsonResponse(check.to_dict(v=request.v))


@cors("GET")
@csrf_exempt
@authorize
def pings(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        return HttpResponseForbidden()

    profile = Profile.objects.get(user__project=request.project)
    limit = min(profile.ping_log_limit, 1000)
    pings = list(Ping.objects.filter(owner=check).order_by("-id")[:limit])
    prepare_durations(pings)
    ping_dicts = [p.to_dict(owner_code=check.code, v=request.v) for p in pings]
    return JsonResponse({"pings": ping_dicts})


@cors("GET")
@csrf_exempt
@authorize
def ping_body(request: ApiRequest, code: UUID, n: int) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    if check.project_id != request.project.id:
        return HttpResponseForbidden()

    profile = Profile.objects.get(user__project=request.project)
    threshold = check.n_pings - profile.ping_log_limit
    if n <= threshold:
        raise Http404()

    ping = get_object_or_404(Ping, owner=check, n=n)
    try:
        body = ping.get_body_bytes()
    except Ping.GetBodyError:
        # [IMPROVEMENT 20] Log object storage retrieval errors at ERROR level.
        # ORIGINAL: returned 503 with no log.
        # FIX: A GetBodyError means external object storage (S3/MinIO) is
        # unavailable or the object is missing. This is an infrastructure problem
        # that needs immediate operator attention. ERROR-level ensures alerting.
        logger.error(
            "ping_body: failed to retrieve body from object storage "
            "for check=%s ping_n=%d",
            check.code,
            n,
        )
        return HttpResponse(status=503)

    if not body:
        raise Http404()

    response = HttpResponse(body, content_type="text/plain")
    return response


def flips(request: ApiRequest, check: Check) -> HttpResponse:
    if check.project_id != request.project.id:
        return HttpResponseForbidden()

    form = FlipsFiltersForm(request.GET)
    if not form.is_valid():
        # [IMPROVEMENT 21] Log invalid flip filter parameters.
        # ORIGINAL: returned 400 with no log.
        # FIX: Bad flip filter parameters indicate a client integration bug.
        # Logging the errors helps API consumers understand what they got wrong.
        logger.warning(
            "flips: invalid filter params for check=%s errors=%r",
            check.code,
            form.errors,
        )
        return HttpResponseBadRequest()

    flips = Flip.objects.filter(owner=check).order_by("-id")

    if form.cleaned_data["start"]:
        flips = flips.filter(created__gte=form.cleaned_data["start"])
    if form.cleaned_data["end"]:
        flips = flips.filter(created__lt=form.cleaned_data["end"])
    if form.cleaned_data["seconds"]:
        threshold = now() - td(seconds=form.cleaned_data["seconds"])
        flips = flips.filter(created__gte=threshold)

    return JsonResponse({"flips": [flip.to_dict() for flip in flips]})


@cors("GET")
@csrf_exempt
@authorize_read
def flips_by_uuid(request: ApiRequest, code: UUID) -> HttpResponse:
    check = get_object_or_404(Check, code=code)
    return flips(request, check)


@cors("GET")
@csrf_exempt
@authorize_read
def flips_by_unique_key(request: ApiRequest, unique_key: str) -> HttpResponse:
    for check in request.project.check_set.all():
        if check.unique_key == unique_key:
            return flips(request, check)
    return HttpResponseNotFound()


@cors("GET")
@csrf_exempt
@authorize_read
def badges(request: ApiRequest) -> JsonResponse:
    tags = set(["*"])
    for check in request.project.check_set.all():
        tags.update(check.tags_list())

    key = request.project.badge_key
    badges = {}
    for tag in tags:
        badges[tag] = {
            "svg": get_badge_url(key, tag),
            "svg3": get_badge_url(key, tag, with_late=True),
            "json": get_badge_url(key, tag, fmt="json"),
            "json3": get_badge_url(key, tag, fmt="json", with_late=True),
            "shields": get_badge_url(key, tag, fmt="shields"),
            "shields3": get_badge_url(key, tag, fmt="shields", with_late=True),
        }

    return JsonResponse({"badges": badges})


SHIELDS_COLORS = {"up": "success", "late": "important", "down": "critical"}


def _shields_response(label: str, status: str) -> JsonResponse:
    return JsonResponse(
        {
            "schemaVersion": 1,
            "label": label,
            "message": status,
            "color": SHIELDS_COLORS[status],
        }
    )


@never_cache
@cors("GET")
def badge(
    request: HttpRequest, badge_key: str, signature: str, tag: str, fmt: str
) -> HttpResponse:
    if fmt not in ("svg", "json", "shields"):
        return HttpResponseNotFound()

    with_late = True
    if len(signature) == 10 and signature.endswith("-2"):
        with_late = False

    if not check_signature(badge_key, tag, signature):
        # [IMPROVEMENT 22] Log invalid badge signature attempts.
        # ORIGINAL: returned 404 with no log.
        # FIX: An invalid signature may indicate a tampered or expired URL.
        # Logging at DEBUG level (not WARNING, since this may be common for
        # expired URLs) helps diagnose badge rendering issues.
        logger.debug(
            "badge: invalid signature for badge_key=%s tag=%r", badge_key, tag
        )
        return HttpResponseNotFound()

    q = Check.objects.filter(project__badge_key=badge_key)
    if tag == "*":
        label = settings.MASTER_BADGE_LABEL
    else:
        q = q.filter(tags__contains=tag)
        label = tag

    status, total, grace, down = "up", 0, 0, 0
    for check in q:
        if tag != "*" and tag not in check.tags_list():
            continue
        total += 1
        check_status = check.get_status()
        if check_status == "down":
            down += 1
            status = "down"
            if fmt == "svg":
                break
        elif check_status == "grace":
            grace += 1
            if status == "up" and with_late:
                status = "late"

    if fmt == "shields":
        return _shields_response(label, status)

    if fmt == "json":
        return JsonResponse(
            {"status": status, "total": total, "grace": grace, "down": down}
        )

    svg = get_badge_svg(label, status)
    return HttpResponse(svg, content_type="image/svg+xml")


@never_cache
@cors("GET")
def check_badge(
    request: HttpRequest, states: int, badge_key: UUID, fmt: str
) -> HttpResponse:
    if fmt not in ("svg", "json", "shields"):
        return HttpResponseNotFound()

    check = get_object_or_404(Check, badge_key=badge_key)
    check_status = check.get_status()
    status = "up"
    if check_status == "down":
        status = "down"
    elif check_status == "grace" and states == 3:
        status = "late"

    if fmt == "shields":
        return _shields_response(check.name_then_code(), status)

    if fmt == "json":
        return JsonResponse(
            {
                "status": status,
                "total": 1,
                "grace": 1 if check_status == "grace" else 0,
                "down": 1 if check_status == "down" else 0,
            }
        )

    svg = get_badge_svg(check.name_then_code(), status)
    return HttpResponse(svg, content_type="image/svg+xml")


@csrf_exempt
@require_POST
def notification_status(request: HttpRequest, code: UUID) -> HttpResponse:
    """Handle notification delivery status callbacks."""

    try:
        cutoff = now() - td(hours=1)
        notification = Notification.objects.get(code=code, created__gt=cutoff)
    except Notification.DoesNotExist:
        # [IMPROVEMENT 23] Log expired/missing notification callbacks at DEBUG.
        # ORIGINAL: returned HTTP 200 silently.
        # FIX: Expired callbacks from delivery providers (Twilio, etc.) are
        # normal but worth logging at DEBUG so operators can verify retry storms
        # are not happening.
        logger.debug(
            "notification_status: notification %s not found or older than 1 hour", code
        )
        return HttpResponse()

    error, mark_disabled = None, False

    if request.POST.get("error"):
        error = request.POST["error"][:200]
        mark_disabled = bool(request.POST.get("mark_disabled"))

    if request.POST.get("MessageStatus") in ("failed", "undelivered"):
        status = request.POST["MessageStatus"]
        error = f"Delivery failed (status={status})."

    if request.POST.get("CallStatus") == "failed":
        error = "Delivery failed (status=failed)."

    if error:
        notification.error = error
        notification.save(update_fields=["error"])

        channel_q = Channel.objects.filter(id=notification.channel_id)
        channel_q.update(last_error=error)
        if mark_disabled:
            channel_q.update(disabled=True)

        # [IMPROVEMENT 24] Log notification delivery failures.
        # ORIGINAL: No logging of delivery failures.
        # FIX: A delivery failure means a user did NOT receive an alert. This is
        # a critical event — logging it at WARNING ensures operators and monitoring
        # tools can detect patterns of failed notification channels.
        logger.warning(
            "Notification delivery failed: notification=%s error=%r mark_disabled=%s",
            code,
            error,
            mark_disabled,
        )

    return HttpResponse()


def metrics(request: HttpRequest) -> HttpResponse:
    if not settings.METRICS_KEY:
        return HttpResponseForbidden()

    key = request.headers.get("X-Metrics-Key")
    if key != settings.METRICS_KEY:
        # [IMPROVEMENT 25] Log invalid metrics key usage.
        # ORIGINAL: returned 403 with no log.
        # FIX: The metrics endpoint is sensitive. An invalid key may indicate a
        # misconfigured scraper or a brute-force attempt.
        logger.warning("metrics: invalid X-Metrics-Key from %s", request.META.get("REMOTE_ADDR"))
        return HttpResponseForbidden()

    doc = {
        "ts": int(time.time()),
        "max_ping_id": Ping.objects.values_list("id", flat=True).last(),
        "max_notification_id": Notification.objects.values_list("id", flat=True).last(),
        "num_unprocessed_flips": Flip.objects.filter(processed__isnull=True).count(),
    }

    return JsonResponse(doc)


def status(request: HttpRequest) -> HttpResponse:
    with connection.cursor() as c:
        c.execute("SELECT 1")
        c.fetchone()
    return HttpResponse("OK")


@csrf_exempt
def bounces(request: HttpRequest) -> HttpResponse:
    msg = message_from_bytes(request.body, policy=email.policy.SMTP)
    to_local = msg.get("To", "").split("@")[0]

    try:
        unsigned = unsign_bounce_id(to_local, max_age=3600 * 48)
    except BadSignature:
        # [IMPROVEMENT 26] Log bad bounce signatures at DEBUG level.
        # ORIGINAL: returned HTTP 200 silently.
        # FIX: Bad signatures may occur for expired bounce addresses (normal)
        # or for spoofed emails (abnormal). DEBUG-level logging lets operators
        # investigate if needed without flooding WARNING logs.
        logger.debug(
            "bounces: bad or expired bounce signature for to_local=%r", to_local
        )
        return HttpResponse("OK (bad signature)")

    status, diagnostic = "", ""
    for part in msg.walk():
        if "Status" in part and "Action" in part:
            status = part["Status"]
            diagnostic = part.get("Diagnostic-Code", "")
            if diagnostic.lower().startswith("smtp; "):
                diagnostic = diagnostic[6:]
            break

    permanent = status.startswith("5.")
    transient = status.startswith("4.")
    if not permanent and not transient:
        return HttpResponse("OK (ignored)")

    if unsigned.startswith("n."):
        notification_code = unsigned[2:]
        try:
            cutoff = now() - td(hours=48)
            n = Notification.objects.get(code=notification_code, created__gt=cutoff)
        except Notification.DoesNotExist:
            logger.debug(
                "bounces: notification %s not found for bounce processing",
                notification_code,
            )
            return HttpResponse("OK (notification not found)")

        if diagnostic:
            error = f"Delivery failed ({diagnostic})"[:200]
        else:
            error = f"Delivery failed (SMTP status code: {status})"[:200]

        n.error = error
        n.save(update_fields=["error"])

        channel_q = Channel.objects.filter(id=n.channel_id)
        channel_q.update(last_error=error)

        if permanent:
            channel_q.update(disabled=True)

        # [IMPROVEMENT 27] Log email bounce events.
        # ORIGINAL: No logging on bounce processing.
        # FIX: An email bounce means a user's notification email is bouncing.
        # Logging it at WARNING ensures it surfaces in monitoring dashboards.
        logger.warning(
            "Email bounce processed: notification=%s status=%r permanent=%s error=%r",
            notification_code,
            status,
            permanent,
            error,
        )

    if unsigned.startswith("r.") and permanent:
        username = unsigned[2:]

        try:
            profile = Profile.objects.get(user__username=username)
        except Profile.DoesNotExist:
            logger.debug("bounces: profile not found for username=%r", username)
            return HttpResponse("OK (user not found)")

        profile.reports = "off"
        profile.next_report_date = None
        profile.nag_period = td()
        profile.next_nag_date = None
        profile.save()

        # [IMPROVEMENT 28] Log when a user's reports are disabled due to a bounce.
        # ORIGINAL: No logging when a user's reports get turned off.
        # FIX: This is a significant side-effect — the user will stop receiving
        # monthly reports. Logging it at INFO ensures it is traceable.
        logger.info(
            "Reports disabled due to permanent email bounce: username=%r", username
        )

    return HttpResponse("OK")