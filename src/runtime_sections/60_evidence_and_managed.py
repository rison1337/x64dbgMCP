_ANALYSIS_EVIDENCE_SCHEMA = "x64dbg-mcp-evidence"
_ANALYSIS_EVIDENCE_VERSION = 1
_ANALYSIS_EVIDENCE_MAX_BYTES = 32 * 1024 * 1024
_ANALYSIS_EVIDENCE_MAX_ITEMS = 100_000


def _analysis_error(code: str, message: str, **details: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ok": False,
        "errorCode": str(code or "ANALYSIS_EVIDENCE_ERROR"),
        "error": str(message or "Analysis evidence operation failed"),
    }
    if details:
        result["details"] = details
    return result


def _analysis_module_name_matches(left: Any, right: Any) -> bool:
    def forms(value: Any) -> set[str]:
        text = _repair_text_mojibake(str(value or "").strip()).replace("/", "\\")
        if not text:
            return set()
        base = os.path.basename(text).casefold()
        stem = os.path.splitext(base)[0]
        return {text.casefold(), base, stem}

    return bool(forms(left) & forms(right))


def _analysis_resolve_loaded_module(
    module: str = "", expected_sha256: str = ""
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    payload = GetModuleList()
    modules = payload.get("modules", []) if isinstance(payload, dict) else []
    modules = [dict(item) for item in modules if isinstance(item, dict)]
    if not modules:
        return None, _analysis_error(
            "MODULE_LIST_UNAVAILABLE", "No loaded modules were returned by x64dbg."
        )

    requested = _repair_text_mojibake(str(module or "").strip())
    requested_base = _parse_int(requested, None)
    candidates: List[Dict[str, Any]] = []
    if requested_base is not None:
        candidates = [
            item
            for item in modules
            if (_parse_int(item.get("base"), -1) or -1) == requested_base
        ]
    elif requested:
        requested_path = _normalize_path_identity(requested) if os.path.isabs(requested) else ""
        for item in modules:
            item_path = str(item.get("path") or "")
            if requested_path and _normalize_path_identity(item_path) == requested_path:
                candidates.append(item)
            elif _analysis_module_name_matches(requested, item.get("name")) or _analysis_module_name_matches(
                requested, item_path
            ):
                candidates.append(item)
    else:
        current_base = _parse_int(_get_current_debuggee_module_base(), None)
        if current_base is not None:
            candidates = [
                item
                for item in modules
                if _parse_int(item.get("base"), None) == current_base
            ]
        if not candidates:
            current_path = _repair_text_mojibake(
                str(_get_runtime_value("lastDebuggeeImagePath", "") or "")
            )
            if current_path:
                identity = _normalize_path_identity(current_path)
                candidates = [
                    item
                    for item in modules
                    if _normalize_path_identity(str(item.get("path") or "")) == identity
                ]
        if not candidates:
            candidates = [modules[0]]

    # An evidence hash disambiguates two loaded modules with the same basename.
    expected_hash = str(expected_sha256 or "").strip().upper()
    if len(candidates) > 1 and expected_hash:
        candidates = [
            item
            for item in candidates
            if _image_sha256_cached(str(item.get("path") or "")).upper() == expected_hash
        ]
    unique: Dict[int, Dict[str, Any]] = {}
    for item in candidates:
        base = _parse_int(item.get("base"), None)
        if base is not None:
            unique[int(base)] = item
    candidates = list(unique.values())
    if not candidates:
        return None, _analysis_error(
            "MODULE_NOT_FOUND",
            "The requested module is not loaded in the active debug session.",
            module=requested or None,
        )
    if len(candidates) != 1:
        return None, _analysis_error(
            "AMBIGUOUS_MODULE",
            "More than one loaded module matches; pass an exact path or runtime base.",
            module=requested or None,
            matches=[
                {
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "base": item.get("base"),
                }
                for item in candidates
            ],
        )
    return candidates[0], None


def _analysis_module_context(
    module: str = "", expected_sha256: str = ""
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    loaded, error = _analysis_resolve_loaded_module(module, expected_sha256)
    if error or not loaded:
        return None, error
    path = os.path.abspath(_repair_text_mojibake(str(loaded.get("path") or "").strip()))
    if not path or not os.path.isfile(path):
        return None, _analysis_error(
            "MODULE_FILE_UNAVAILABLE",
            "The loaded module's backing file is unavailable; a stable identity cannot be created.",
            path=path or None,
        )
    try:
        layout = _parse_pe_layout(path)
        stat = os.stat(path)
    except Exception as exc:
        return None, _analysis_error(
            "MODULE_IDENTITY_FAILED", "Failed to parse the loaded module's PE identity.", error=str(exc)
        )
    digest = _image_sha256_cached(path)
    if not digest:
        return None, _analysis_error(
            "MODULE_HASH_FAILED", "Failed to calculate the loaded module SHA-256.", path=path
        )
    runtime_base = _parse_int(loaded.get("base"), None)
    runtime_size = _parse_int(loaded.get("size"), None)
    image_size = int(layout.get("sizeOfImage") or 0)
    if runtime_base is None or runtime_size is None or runtime_size <= 0 or image_size <= 0:
        return None, _analysis_error(
            "INVALID_MODULE_LAYOUT", "The loaded module has an invalid base or image size."
        )
    identity = {
        "name": str(loaded.get("name") or os.path.basename(path)),
        "path": path,
        "sha256": digest.upper(),
        "fileSize": int(stat.st_size),
        "arch": str(layout.get("arch") or ""),
        "machine": str(layout.get("machine") or ""),
        "timeDateStamp": str(layout.get("timeDateStamp") or ""),
        "checksum": str(layout.get("checksum") or ""),
        "preferredImageBase": str(layout.get("imageBase") or ""),
        "runtimeImageBase": f"0x{int(runtime_base):X}",
        "runtimeSize": int(runtime_size),
        "sizeOfImage": image_size,
        "entryPointRva": str(layout.get("entryPointRva") or "0x0"),
    }
    return {
        "module": loaded,
        "path": path,
        "layout": layout,
        "identity": identity,
        "base": int(runtime_base),
        "size": min(int(runtime_size), image_size),
    }, None


def _analysis_collect_paged(
    list_function: Callable[..., Dict[str, Any]], module: str, key: str
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    items: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(1000):
        payload = list_function(module=module, offset=offset, limit=5000)
        if not isinstance(payload, dict) or payload.get("ok") is False:
            return [], _analysis_error(
                "EVIDENCE_ENUM_FAILED",
                f"Failed to enumerate {key}.",
                response=payload,
            )
        page = [dict(item) for item in payload.get(key, []) if isinstance(item, dict)]
        items.extend(page)
        if len(items) > _ANALYSIS_EVIDENCE_MAX_ITEMS:
            return [], _analysis_error(
                "EVIDENCE_TOO_LARGE", f"The {key} collection exceeds the item limit."
            )
        if not payload.get("hasMore"):
            return items, None
        next_offset = _parse_int(payload.get("nextOffset"), None)
        if next_offset is None or next_offset <= offset:
            return [], _analysis_error(
                "INVALID_PAGINATION", f"The bridge returned invalid {key} pagination."
            )
        offset = int(next_offset)
    return [], _analysis_error("INVALID_PAGINATION", f"The {key} pagination did not terminate.")


def _analysis_parse_rva(
    value: Any, image_size: int, field_name: str, allow_image_end: bool = False
) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer RVA")
    parsed = _parse_int(value, None)
    upper = int(image_size) + (1 if allow_image_end else 0)
    if parsed is None or parsed < 0 or parsed >= upper:
        raise ValueError(f"{field_name} is outside the module image")
    return int(parsed)


def _analysis_validate_text(value: Any, field_name: str, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value or not value.strip():
        raise ValueError(f"{field_name} cannot be empty")
    if "\x00" in value:
        raise ValueError(f"{field_name} cannot contain NUL")
    encoded_length = len(value.encode("utf-8"))
    if encoded_length > max_length:
        raise ValueError(f"{field_name} exceeds {max_length} UTF-8 bytes")
    return value


def _analysis_load_document(
    evidence_json: str = "", input_path: str = ""
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    inline = str(evidence_json or "")
    path = _repair_text_mojibake(str(input_path or "").strip())
    if bool(inline.strip()) == bool(path):
        return None, _analysis_error(
            "INVALID_ARGUMENT", "Provide exactly one of evidence_json or input_path."
        )
    try:
        if path:
            resolved = os.path.abspath(path)
            lower = resolved.casefold()
            if lower.startswith("\\\\.\\") or lower.startswith("\\\\?\\globalroot"):
                return None, _analysis_error("UNSAFE_PATH", "Device paths are not accepted.")
            stat = os.stat(resolved)
            if not os.path.isfile(resolved) or stat.st_size > _ANALYSIS_EVIDENCE_MAX_BYTES:
                return None, _analysis_error(
                    "EVIDENCE_TOO_LARGE", "Evidence file is missing or exceeds 32 MiB.", path=resolved
                )
            with open(resolved, "r", encoding="utf-8") as handle:
                document = json.load(handle)
        else:
            if len(inline.encode("utf-8")) > _ANALYSIS_EVIDENCE_MAX_BYTES:
                return None, _analysis_error("EVIDENCE_TOO_LARGE", "Evidence JSON exceeds 32 MiB.")
            document = json.loads(inline)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, _analysis_error("INVALID_JSON", "Failed to read analysis evidence JSON.", error=str(exc))
    if not isinstance(document, dict):
        return None, _analysis_error("INVALID_SCHEMA", "Analysis evidence must be a JSON object.")
    return document, None


def _analysis_validate_document(document: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[Dict[str, Any]] = []
    warnings_list: List[str] = []
    if document.get("schema") != _ANALYSIS_EVIDENCE_SCHEMA:
        errors.append({"path": "schema", "error": f"Expected {_ANALYSIS_EVIDENCE_SCHEMA!r}"})
    if _parse_int(document.get("version"), None) != _ANALYSIS_EVIDENCE_VERSION:
        errors.append({"path": "version", "error": f"Expected version {_ANALYSIS_EVIDENCE_VERSION}"})
    image = document.get("image")
    if not isinstance(image, dict):
        errors.append({"path": "image", "error": "A module identity object is required"})
        image = {}
    image_size = _parse_int(image.get("sizeOfImage"), 0) or 0
    digest = str(image.get("sha256") or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", digest):
        errors.append({"path": "image.sha256", "error": "A 64-digit SHA-256 is required"})
    if str(image.get("arch") or "").lower() not in ("x86", "x64"):
        errors.append({"path": "image.arch", "error": "arch must be x86 or x64"})
    if image_size <= 0 or image_size > 0x1_0000_0000:
        errors.append({"path": "image.sizeOfImage", "error": "Invalid PE image size"})

    evidence = document.get("evidence")
    if not isinstance(evidence, dict):
        errors.append({"path": "evidence", "error": "An evidence object is required"})
        evidence = {}
    normalized: Dict[str, List[Dict[str, Any]]] = {}
    specs = {
        "labels": ("text", 255),
        "comments": ("text", 511),
        "bookmarks": (None, 0),
        "breakpoints": (None, 0),
        "patches": (None, 0),
        "nativeTraceHits": (None, 0),
        "apiCallsites": (None, 0),
    }
    total_items = 0
    for key, (text_field, text_limit) in specs.items():
        raw_items = evidence.get(key, [])
        if not isinstance(raw_items, list):
            errors.append({"path": f"evidence.{key}", "error": "Expected an array"})
            raw_items = []
        total_items += len(raw_items)
        normalized[key] = []
        for index, raw in enumerate(raw_items):
            path = f"evidence.{key}[{index}]"
            if not isinstance(raw, dict):
                errors.append({"path": path, "error": "Expected an object"})
                continue
            try:
                item = dict(raw)
                rva = _analysis_parse_rva(item.get("rva"), image_size, f"{path}.rva")
                item["rva"] = rva
                if text_field:
                    item[text_field] = _analysis_validate_text(
                        item.get(text_field), f"{path}.{text_field}", text_limit
                    )
                if key == "breakpoints":
                    bp_type = str(item.get("type") or "normal").lower()
                    if bp_type not in ("normal", "hardware", "memory", "dll", "exception"):
                        raise ValueError(f"{path}.type is unsupported")
                    item["type"] = bp_type
                elif key == "patches":
                    for byte_name in ("oldByte", "newByte"):
                        byte_value = _parse_int(item.get(byte_name), None)
                        if byte_value is None or not 0 <= byte_value <= 255:
                            raise ValueError(f"{path}.{byte_name} must be a byte")
                        item[byte_name] = int(byte_value)
                elif key == "nativeTraceHits":
                    hits = _parse_int(item.get("hits"), None)
                    if hits is None or hits <= 0:
                        raise ValueError(f"{path}.hits must be positive")
                    item["hits"] = int(hits)
                elif key == "apiCallsites":
                    item["api"] = _analysis_validate_text(item.get("api"), f"{path}.api", 512)
                    count = _parse_int(item.get("count"), 1)
                    if count is None or count <= 0:
                        raise ValueError(f"{path}.count must be positive")
                    item["count"] = int(count)
                if "manual" in item and not isinstance(item.get("manual"), bool):
                    raise ValueError(f"{path}.manual must be a boolean")
                item["manual"] = bool(item.get("manual", True))
                normalized[key].append(item)
            except ValueError as exc:
                errors.append({"path": path, "error": str(exc)})

    raw_functions = evidence.get("functions", [])
    if not isinstance(raw_functions, list):
        errors.append({"path": "evidence.functions", "error": "Expected an array"})
        raw_functions = []
    total_items += len(raw_functions)
    normalized["functions"] = []
    for index, raw in enumerate(raw_functions):
        path = f"evidence.functions[{index}]"
        if not isinstance(raw, dict):
            errors.append({"path": path, "error": "Expected an object"})
            continue
        try:
            item = dict(raw)
            start = _analysis_parse_rva(item.get("rvaStart"), image_size, f"{path}.rvaStart")
            if item.get("rvaEndInclusive") not in (None, ""):
                end = _analysis_parse_rva(
                    item.get("rvaEndInclusive"), image_size, f"{path}.rvaEndInclusive"
                )
            elif item.get("rvaEnd") not in (None, ""):
                end = _analysis_parse_rva(item.get("rvaEnd"), image_size, f"{path}.rvaEnd")
            else:
                exclusive = _analysis_parse_rva(
                    item.get("endRvaExclusive"), image_size, f"{path}.endRvaExclusive", True
                )
                if exclusive <= 0:
                    raise ValueError(f"{path}.endRvaExclusive must be greater than zero")
                end = exclusive - 1
            if end < start:
                raise ValueError(f"{path} has an end before its start")
            instruction_count = _parse_int(item.get("instructionCount"), 0) or 0
            if instruction_count < 0 or instruction_count > 10_000_000:
                raise ValueError(f"{path}.instructionCount is invalid")
            if "manual" in item and not isinstance(item.get("manual"), bool):
                raise ValueError(f"{path}.manual must be a boolean")
            item.update(
                {
                    "rvaStart": start,
                    "rvaEndInclusive": end,
                    "instructionCount": int(instruction_count),
                    "manual": bool(item.get("manual", True)),
                    "endConvention": "inclusive",
                }
            )
            normalized["functions"].append(item)
        except ValueError as exc:
            errors.append({"path": path, "error": str(exc)})

    # An x64dbg database can hold only one label/comment/bookmark/patch at an
    # address. Reject ambiguous input instead of letting JSON order decide which
    # value wins. Exact duplicates are harmless but removed deterministically.
    for key in ("labels", "comments", "bookmarks", "patches"):
        unique_items: List[Dict[str, Any]] = []
        seen: Dict[int, Dict[str, Any]] = {}
        for item in normalized[key]:
            rva = int(item["rva"])
            previous = seen.get(rva)
            if previous is None:
                seen[rva] = item
                unique_items.append(item)
            elif previous != item:
                errors.append(
                    {
                        "path": f"evidence.{key}",
                        "error": f"Conflicting duplicate {key[:-1]} at RVA 0x{rva:X}",
                    }
                )
            else:
                warnings_list.append(f"Removed an exact duplicate {key[:-1]} at RVA 0x{rva:X}.")
        normalized[key] = unique_items
    sorted_functions = sorted(
        normalized["functions"], key=lambda item: (item["rvaStart"], item["rvaEndInclusive"])
    )
    deduped_functions: List[Dict[str, Any]] = []
    for item in sorted_functions:
        if deduped_functions and item == deduped_functions[-1]:
            warnings_list.append(
                f"Removed an exact duplicate function at RVA 0x{item['rvaStart']:X}."
            )
            continue
        if deduped_functions and item["rvaStart"] <= deduped_functions[-1]["rvaEndInclusive"]:
            errors.append(
                {
                    "path": "evidence.functions",
                    "error": (
                        "Imported function ranges overlap at RVA "
                        f"0x{item['rvaStart']:X}"
                    ),
                }
            )
        deduped_functions.append(item)
    normalized["functions"] = deduped_functions

    if total_items > _ANALYSIS_EVIDENCE_MAX_ITEMS:
        errors.append({"path": "evidence", "error": "Evidence exceeds 100000 items"})
    declared_counts = document.get("counts")
    actual_counts = {key: len(value) for key, value in normalized.items()}
    if isinstance(declared_counts, dict):
        mismatches = {
            key: {"declared": declared_counts.get(key), "actual": value}
            for key, value in actual_counts.items()
            if key in declared_counts and _parse_int(declared_counts.get(key), -1) != value
        }
        if mismatches:
            warnings_list.append("Declared evidence counts do not match the arrays; arrays are authoritative.")
    return {
        "ok": not errors,
        "valid": not errors,
        "schema": document.get("schema"),
        "version": document.get("version"),
        "errors": errors,
        "warnings": warnings_list,
        "counts": actual_counts,
        "normalized": normalized,
        "image": dict(image),
    }


def _analysis_write_json(path: str, document: Dict[str, Any], overwrite: bool) -> Dict[str, Any]:
    requested = _repair_text_mojibake(str(path or "").strip())
    if not requested:
        return _analysis_error("INVALID_ARGUMENT", "output_path is required")
    resolved = os.path.abspath(requested)
    lower = resolved.casefold()
    if lower.startswith("\\\\.\\") or lower.startswith("\\\\?\\globalroot"):
        return _analysis_error("UNSAFE_PATH", "Device paths are not accepted.")
    parent = os.path.dirname(resolved)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        return _analysis_error("OUTPUT_DIRECTORY_FAILED", "Could not create output directory.", error=str(exc))
    if os.path.exists(resolved) and not overwrite:
        return _analysis_error(
            "OUTPUT_EXISTS", "Evidence output already exists; set overwrite=true to replace it.", path=resolved
        )
    serialized = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(serialized.encode("utf-8")) > _ANALYSIS_EVIDENCE_MAX_BYTES:
        return _analysis_error("EVIDENCE_TOO_LARGE", "Serialized evidence exceeds 32 MiB.")
    temp_path = ""
    try:
        fd, temp_path = tempfile.mkstemp(prefix=".evidence-", suffix=".tmp", dir=parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temp_path, resolved)
            temp_path = ""
        else:
            # Hard-link publication is atomic and CREATE_NEW-like: it can never
            # replace a file created after the pre-check. Both names refer to the
            # fully fsynced temp content until the temporary link is removed.
            os.link(temp_path, resolved)
            os.remove(temp_path)
            temp_path = ""
        return {
            "ok": True,
            "path": resolved,
            "size": os.path.getsize(resolved),
            "sha256": _image_sha256_cached(resolved),
            "overwritten": bool(overwrite),
        }
    except FileExistsError:
        return _analysis_error("OUTPUT_EXISTS", "Evidence output already exists.", path=resolved)
    except OSError as exc:
        return _analysis_error("OUTPUT_WRITE_FAILED", "Failed to write evidence atomically.", error=str(exc))
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


def _analysis_public_validation(validation: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in validation.items() if key != "normalized"}


def _analysis_export_rva(value: Any, base: int, size: int, field: str) -> int:
    absolute = _parse_int(value, None)
    if absolute is None or absolute < base or absolute >= base + size:
        raise ValueError(f"{field} is outside the selected runtime module")
    return int(absolute - base)


def _analysis_trace_hits(trace_id: str, base: int, size: int) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not str(trace_id or "").strip():
        return [], None
    output: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(1000):
        payload = GetNativeTrace(
            str(trace_id),
            event_offset=0,
            event_limit=0,
            hit_offset=offset,
            hit_limit=5000,
            detail="full",
        )
        if not isinstance(payload, dict) or not payload.get("ok"):
            return [], _analysis_error(
                "TRACE_NOT_FOUND", "Failed to read the requested native trace.", response=payload
            )
        for item in payload.get("hits", []):
            if not isinstance(item, dict):
                continue
            address = _parse_int(item.get("ip"), None)
            hits = _parse_int(item.get("hits"), 0) or 0
            if address is not None and base <= address < base + size and hits > 0:
                output.append({"rva": f"0x{address - base:X}", "hits": int(hits)})
        if len(output) > _ANALYSIS_EVIDENCE_MAX_ITEMS:
            return [], _analysis_error("EVIDENCE_TOO_LARGE", "Trace hit evidence exceeds the item limit.")
        if not payload.get("hitHasMore"):
            return output, None
        returned = int(payload.get("hitReturned") or 0)
        if returned <= 0:
            return [], _analysis_error("INVALID_PAGINATION", "Native trace pagination did not advance.")
        offset += returned
    return [], _analysis_error("INVALID_PAGINATION", "Native trace pagination did not terminate.")


def _analysis_api_callsites(
    trace_id: str, base: int, size: int
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    if not str(trace_id or "").strip():
        return [], None
    aggregate: Dict[Tuple[int, str], int] = {}
    offset = 0
    for _ in range(1000):
        payload = GetApiTraceLog(str(trace_id), offset=offset, limit=5000)
        if not isinstance(payload, dict) or not payload.get("ok"):
            return [], _analysis_error(
                "API_TRACE_NOT_FOUND", "Failed to read the requested API trace.", response=payload
            )
        calls = [item for item in payload.get("calls", []) if isinstance(item, dict)]
        for call in calls:
            address = _parse_int(call.get("returnAddress"), None)
            if address is None or not (base <= address < base + size):
                continue
            api = f"{call.get('module') or ''}!{call.get('func') or ''}".strip("!")
            if not api:
                continue
            key = (int(address - base), api)
            aggregate[key] = aggregate.get(key, 0) + 1
        offset += len(calls)
        total = int(payload.get("total") or offset)
        if offset >= total:
            return [
                {"rva": f"0x{rva:X}", "api": api, "count": count}
                for (rva, api), count in sorted(aggregate.items())
            ], None
        if not calls:
            return [], _analysis_error("INVALID_PAGINATION", "API trace pagination did not advance.")
    return [], _analysis_error("INVALID_PAGINATION", "API trace pagination did not terminate.")


@mcp.tool()
def ValidateAnalysisEvidence(evidence_json: str = "", input_path: str = "") -> dict:
    """Validate portable module-identity + RVA evidence without changing x64dbg."""
    document, error = _analysis_load_document(evidence_json, input_path)
    if error or document is None:
        return error or _analysis_error("INVALID_JSON", "Evidence could not be loaded.")
    return _analysis_public_validation(_analysis_validate_document(document))


@mcp.tool()
def ExportAnalysisEvidence(
    module: str = "",
    output_path: str = "",
    overwrite: bool = False,
    include_breakpoints: bool = True,
    include_patches: bool = True,
    native_trace_id: str = "",
    api_trace_id: str = "",
) -> dict:
    """Export x64dbg analysis as a portable, deterministic module+RVA document.

    Labels, comments, bookmarks and inclusive function ranges are always
    exported. Breakpoints and patches are evidence only and are never applied by
    an import unless their explicit opt-in flags are set.
    """
    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return _analysis_error(
            "BRIDGE_IDENTITY_UNAVAILABLE", "Authoritative bridge identity is unavailable.", response=hello
        )
    hello_payload = hello.get("payload") if isinstance(hello.get("payload"), dict) else {}
    capabilities = hello_payload.get("capabilities") if isinstance(hello_payload, dict) else {}
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("analysisEvidence"), dict):
        return _analysis_error(
            "UNSUPPORTED_CAPABILITY",
            "The active x64dbg plugin does not advertise analysisEvidence v1.",
        )
    context, error = _analysis_module_context(module)
    if error or context is None:
        return error or _analysis_error("MODULE_NOT_FOUND", "Module could not be resolved.")
    identity = dict(context["identity"])
    base = int(context["base"])
    size = int(context["size"])
    module_name = str(identity.get("name") or "")

    label_payload = LabelList()
    if not isinstance(label_payload, dict) or not isinstance(label_payload.get("labels"), list):
        return _analysis_error("EVIDENCE_ENUM_FAILED", "Failed to enumerate labels.", response=label_payload)
    comments, error = _analysis_collect_paged(CommentList, module_name, "comments")
    if error:
        return error
    bookmarks, error = _analysis_collect_paged(BookmarkList, module_name, "bookmarks")
    if error:
        return error
    functions, error = _analysis_collect_paged(FunctionList, module_name, "functions")
    if error:
        return error

    evidence: Dict[str, List[Dict[str, Any]]] = {
        "labels": [],
        "comments": [],
        "bookmarks": [],
        "functions": [],
        "breakpoints": [],
        "patches": [],
        "nativeTraceHits": [],
        "apiCallsites": [],
    }
    try:
        for item in label_payload.get("labels", []):
            if not isinstance(item, dict) or not _analysis_module_name_matches(module_name, item.get("module")):
                continue
            rva = _analysis_parse_rva(item.get("rva"), size, "label.rva")
            evidence["labels"].append(
                {
                    "rva": f"0x{rva:X}",
                    "text": str(item.get("text") or ""),
                    "manual": bool(item.get("manual", True)),
                }
            )
        for item in comments:
            rva = _analysis_parse_rva(item.get("rva"), size, "comment.rva")
            evidence["comments"].append(
                {
                    "rva": f"0x{rva:X}",
                    "text": str(item.get("text") or ""),
                    "manual": bool(item.get("manual", True)),
                }
            )
        for item in bookmarks:
            rva = _analysis_parse_rva(item.get("rva"), size, "bookmark.rva")
            evidence["bookmarks"].append(
                {"rva": f"0x{rva:X}", "manual": bool(item.get("manual", True))}
            )
        for item in functions:
            start = _analysis_parse_rva(item.get("rvaStart"), size, "function.rvaStart")
            end = _analysis_parse_rva(item.get("rvaEnd"), size, "function.rvaEnd")
            if end < start:
                raise ValueError("function end precedes start")
            evidence["functions"].append(
                {
                    "rvaStart": f"0x{start:X}",
                    "rvaEndInclusive": f"0x{end:X}",
                    "endConvention": "inclusive",
                    "manual": bool(item.get("manual", True)),
                    "instructionCount": int(item.get("instructionCount") or 0),
                }
            )
        if include_breakpoints:
            payload = GetBreakpointList("all")
            if not isinstance(payload, dict) or not isinstance(payload.get("breakpoints"), list):
                return _analysis_error(
                    "EVIDENCE_ENUM_FAILED", "Failed to enumerate breakpoints.", response=payload
                )
            for item in payload.get("breakpoints", []):
                if not isinstance(item, dict):
                    continue
                address = _parse_int(item.get("addr"), None)
                if address is None or not (base <= address < base + size):
                    continue
                evidence["breakpoints"].append(
                    {
                        "rva": f"0x{address - base:X}",
                        "type": str(item.get("type") or "normal"),
                        "enabled": bool(item.get("enabled", True)),
                        "singleshoot": bool(item.get("singleshoot", False)),
                        "name": str(item.get("name") or ""),
                        "condition": str(item.get("breakCondition") or ""),
                        "hitCount": int(item.get("hitCount") or 0),
                    }
                )
        if include_patches:
            payload = GetPatchList()
            if not isinstance(payload, dict) or not isinstance(payload.get("patches"), list):
                return _analysis_error(
                    "EVIDENCE_ENUM_FAILED", "Failed to enumerate patches.", response=payload
                )
            for item in payload.get("patches", []):
                if not isinstance(item, dict):
                    continue
                address = _parse_int(item.get("address"), None)
                if address is None or not (base <= address < base + size):
                    continue
                evidence["patches"].append(
                    {
                        "rva": f"0x{address - base:X}",
                        "oldByte": str(item.get("oldByte") or "0x0"),
                        "newByte": str(item.get("newByte") or "0x0"),
                    }
                )
    except (TypeError, ValueError) as exc:
        return _analysis_error("INVALID_BRIDGE_EVIDENCE", "x64dbg returned invalid module evidence.", error=str(exc))

    trace_hits, error = _analysis_trace_hits(native_trace_id, base, size)
    if error:
        return error
    evidence["nativeTraceHits"] = trace_hits
    api_callsites, error = _analysis_api_callsites(api_trace_id, base, size)
    if error:
        return error
    evidence["apiCallsites"] = api_callsites

    for key in ("labels", "comments", "bookmarks", "breakpoints", "patches", "nativeTraceHits", "apiCallsites"):
        evidence[key].sort(key=lambda item: (_parse_int(item.get("rva"), 0) or 0, json.dumps(item, sort_keys=True)))
    evidence["functions"].sort(
        key=lambda item: (
            _parse_int(item.get("rvaStart"), 0) or 0,
            _parse_int(item.get("rvaEndInclusive"), 0) or 0,
        )
    )
    bridge_identity = hello.get("identity") if isinstance(hello.get("identity"), dict) else {}
    build = hello_payload.get("build") if isinstance(hello_payload.get("build"), dict) else {}
    document = {
        "schema": _ANALYSIS_EVIDENCE_SCHEMA,
        "version": _ANALYSIS_EVIDENCE_VERSION,
        "generatedAt": _now_iso(),
        "addressModel": {"kind": "module+rva", "encoding": "hex-string", "functionEnd": "inclusive"},
        "producer": {
            "name": "x64dbgMCP",
            "bridgeBuildId": build.get("id"),
            "bridgeSourceId": build.get("sourceId"),
        },
        "image": identity,
        "session": {
            "bridgeInstanceId": bridge_identity.get("bridgeInstanceId"),
            "sessionId": bridge_identity.get("sessionId"),
            "sessionGeneration": bridge_identity.get("sessionGeneration"),
            "debuggeePid": bridge_identity.get("debuggeePid"),
            "eventSeq": bridge_identity.get("eventSeq"),
            "nativeTraceId": str(native_trace_id or "") or None,
            "apiTraceId": str(api_trace_id or "") or None,
        },
        "evidence": evidence,
        "counts": {key: len(value) for key, value in evidence.items()},
    }
    validation = _analysis_validate_document(document)
    if not validation.get("valid"):
        return _analysis_error(
            "EXPORT_VALIDATION_FAILED",
            "Generated evidence failed its own schema validation.",
            validation=_analysis_public_validation(validation),
        )
    output = None
    if str(output_path or "").strip():
        output = _analysis_write_json(output_path, document, overwrite)
        if not output.get("ok"):
            return {**output, "document": document, "validation": _analysis_public_validation(validation)}
    return {
        "ok": True,
        "document": document,
        "validation": _analysis_public_validation(validation),
        "output": output,
    }


def _analysis_current_annotations(
    module_name: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    label_payload = LabelList()
    if not isinstance(label_payload, dict) or not isinstance(label_payload.get("labels"), list):
        return None, _analysis_error("PREFLIGHT_FAILED", "Failed to enumerate existing labels.")
    comments, error = _analysis_collect_paged(CommentList, module_name, "comments")
    if error:
        return None, error
    bookmarks, error = _analysis_collect_paged(BookmarkList, module_name, "bookmarks")
    if error:
        return None, error
    functions, error = _analysis_collect_paged(FunctionList, module_name, "functions")
    if error:
        return None, error

    def rva_map(items: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
        result: Dict[int, Dict[str, Any]] = {}
        for item in items:
            if not _analysis_module_name_matches(module_name, item.get("module")):
                continue
            rva = _parse_int(item.get("rva"), None)
            if rva is not None:
                result[int(rva)] = dict(item)
        return result

    return {
        "labels": rva_map([dict(item) for item in label_payload.get("labels", []) if isinstance(item, dict)]),
        "comments": rva_map(comments),
        "bookmarks": rva_map(bookmarks),
        "functions": [dict(item) for item in functions],
    }, None


def _analysis_guarded_mutation(
    endpoint: str, data: Dict[str, Any], event_seq: int
) -> Tuple[bool, Any, str]:
    raw = safe_post(
        endpoint,
        data,
        log=False,
        expected_event_seq=int(event_seq),
    )
    payload = _coerce_json_payload(raw)
    if isinstance(payload, dict):
        if payload.get("ok") is False or payload.get("success") is False:
            error = payload.get("error")
            if isinstance(error, dict):
                error = error.get("message") or error.get("code")
            return False, payload, str(error or "The bridge rejected the mutation")
        if payload.get("success") is True or payload.get("ok") is True:
            return True, payload, ""
    text = str(raw or "")
    lowered = text.lower()
    success = "success" in lowered and "error" not in lowered and "failed" not in lowered
    return success, payload if payload is not None else raw, "" if success else text


@mcp.tool()
def ImportAnalysisEvidence(
    evidence_json: str = "",
    input_path: str = "",
    module: str = "",
    dry_run: bool = True,
    allow_hash_mismatch: bool = False,
    overwrite_existing: bool = False,
    apply_labels: bool = True,
    apply_comments: bool = True,
    apply_bookmarks: bool = True,
    apply_functions: bool = True,
    apply_breakpoints: bool = False,
    apply_patches: bool = False,
) -> dict:
    """Plan or apply portable analysis evidence to the active module.

    The default is a read-only dry run.  Hash and architecture mismatches fail
    closed. Breakpoints and patches require separate explicit opt-in flags;
    imported breakpoint commands/log actions are never executed.
    """
    document, error = _analysis_load_document(evidence_json, input_path)
    if error or document is None:
        return error or _analysis_error("INVALID_JSON", "Evidence could not be loaded.")
    validation = _analysis_validate_document(document)
    public_validation = _analysis_public_validation(validation)
    if not validation.get("valid"):
        return _analysis_error(
            "INVALID_EVIDENCE", "Analysis evidence failed validation.", validation=public_validation
        )
    evidence_image = validation.get("image") if isinstance(validation.get("image"), dict) else {}
    expected_hash = str(evidence_image.get("sha256") or "").upper()

    hello = BridgeHello(refresh=True)
    if not isinstance(hello, dict) or not hello.get("ok"):
        return _analysis_error(
            "BRIDGE_IDENTITY_UNAVAILABLE", "Authoritative bridge identity is unavailable.", response=hello
        )
    hello_payload = hello.get("payload") if isinstance(hello.get("payload"), dict) else {}
    capabilities = hello_payload.get("capabilities") if isinstance(hello_payload, dict) else {}
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("analysisEvidence"), dict):
        return _analysis_error(
            "UNSUPPORTED_CAPABILITY", "The active x64dbg plugin does not advertise analysisEvidence v1."
        )
    context, error = _analysis_module_context(
        module, "" if allow_hash_mismatch else expected_hash
    )
    if error or context is None:
        return error or _analysis_error("MODULE_NOT_FOUND", "Module could not be resolved.")
    current_image = dict(context["identity"])
    base = int(context["base"])
    size = int(context["size"])
    module_name = str(current_image.get("name") or "")

    mismatches: List[Dict[str, Any]] = []
    if str(evidence_image.get("arch") or "").lower() != str(current_image.get("arch") or "").lower():
        mismatches.append(
            {"field": "arch", "expected": evidence_image.get("arch"), "current": current_image.get("arch")}
        )
    if str(evidence_image.get("machine") or "").lower() != str(current_image.get("machine") or "").lower():
        mismatches.append(
            {"field": "machine", "expected": evidence_image.get("machine"), "current": current_image.get("machine")}
        )
    if (_parse_int(evidence_image.get("sizeOfImage"), 0) or 0) != int(current_image.get("sizeOfImage") or 0):
        mismatches.append(
            {
                "field": "sizeOfImage",
                "expected": evidence_image.get("sizeOfImage"),
                "current": current_image.get("sizeOfImage"),
            }
        )
    hash_matches = expected_hash == str(current_image.get("sha256") or "").upper()
    if not hash_matches and not allow_hash_mismatch:
        mismatches.append(
            {"field": "sha256", "expected": expected_hash, "current": current_image.get("sha256")}
        )
    if mismatches:
        return _analysis_error(
            "MODULE_IDENTITY_MISMATCH",
            "Evidence belongs to a different module image.",
            mismatches=mismatches,
            allowHashMismatch=bool(allow_hash_mismatch),
            currentImage=current_image,
        )

    current, error = _analysis_current_annotations(module_name)
    if error or current is None:
        return error or _analysis_error("PREFLIGHT_FAILED", "Could not enumerate current annotations.")
    normalized = validation.get("normalized") if isinstance(validation.get("normalized"), dict) else {}
    selected = {
        "labels": bool(apply_labels),
        "comments": bool(apply_comments),
        "bookmarks": bool(apply_bookmarks),
        "functions": bool(apply_functions),
        "breakpoints": bool(apply_breakpoints),
        "patches": bool(apply_patches),
    }
    actions: List[Dict[str, Any]] = []
    noops: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    warnings_list: List[str] = list(validation.get("warnings") or [])

    for kind in ("labels", "comments"):
        if not selected[kind]:
            continue
        existing_map = current[kind]
        for item in normalized.get(kind, []):
            rva = int(item["rva"])
            existing = existing_map.get(rva)
            desired_text = str(item.get("text") or "")
            desired_manual = bool(item.get("manual", True))
            same = bool(
                existing
                and str(existing.get("text") or "") == desired_text
                and bool(existing.get("manual", True)) == desired_manual
            )
            record = {
                "kind": kind[:-1],
                "rva": f"0x{rva:X}",
                "address": f"0x{base + rva:X}",
                "text": desired_text,
                "manual": desired_manual,
            }
            if same:
                noops.append({**record, "reason": "already_equal"})
            elif existing and not overwrite_existing:
                conflicts.append({**record, "reason": "different_existing_value", "existing": existing})
            else:
                actions.append({**record, "operation": "update" if existing else "create"})

    if selected["bookmarks"]:
        existing_map = current["bookmarks"]
        for item in normalized.get("bookmarks", []):
            rva = int(item["rva"])
            desired_manual = bool(item.get("manual", True))
            existing = existing_map.get(rva)
            record = {
                "kind": "bookmark",
                "rva": f"0x{rva:X}",
                "address": f"0x{base + rva:X}",
                "manual": desired_manual,
            }
            if existing and bool(existing.get("manual", True)) == desired_manual:
                noops.append({**record, "reason": "already_equal"})
            elif existing and not overwrite_existing:
                conflicts.append({**record, "reason": "different_existing_value", "existing": existing})
            else:
                actions.append({**record, "operation": "update" if existing else "create"})

    if selected["functions"]:
        existing_functions: List[Tuple[int, int, Dict[str, Any]]] = []
        for item in current["functions"]:
            start = _parse_int(item.get("rvaStart"), None)
            end = _parse_int(item.get("rvaEnd"), None)
            if start is not None and end is not None:
                existing_functions.append((int(start), int(end), item))
        for item in normalized.get("functions", []):
            start = int(item["rvaStart"])
            end = int(item["rvaEndInclusive"])
            exact = next((entry for entry in existing_functions if entry[0] == start and entry[1] == end), None)
            overlap = next(
                (entry for entry in existing_functions if not (end < entry[0] or start > entry[1])), None
            )
            record = {
                "kind": "function",
                "rvaStart": f"0x{start:X}",
                "rvaEndInclusive": f"0x{end:X}",
                "start": f"0x{base + start:X}",
                "end": f"0x{base + end:X}",
                "manual": bool(item.get("manual", True)),
                "instructionCount": int(item.get("instructionCount") or 0),
            }
            if exact:
                noops.append({**record, "reason": "range_already_exists"})
            elif overlap:
                # x64dbg has no safe atomic replace for an overlapping function.
                conflicts.append({**record, "reason": "overlapping_function", "existing": overlap[2]})
            else:
                actions.append({**record, "operation": "create"})

    existing_breakpoints: set[int] = set()
    if selected["breakpoints"]:
        bp_payload = GetBreakpointList("all")
        if not isinstance(bp_payload, dict) or not isinstance(bp_payload.get("breakpoints"), list):
            return _analysis_error("PREFLIGHT_FAILED", "Failed to enumerate current breakpoints.")
        existing_breakpoints = {
            int(address)
            for address in (_parse_int(item.get("addr"), None) for item in bp_payload.get("breakpoints", []) if isinstance(item, dict))
            if address is not None
        }
        for item in normalized.get("breakpoints", []):
            rva = int(item["rva"])
            address = base + rva
            record = {
                "kind": "breakpoint",
                "rva": f"0x{rva:X}",
                "address": f"0x{address:X}",
                "type": str(item.get("type") or "normal"),
            }
            if str(item.get("type") or "normal") != "normal" or not bool(item.get("enabled", True)):
                noops.append({**record, "reason": "only_enabled_software_breakpoints_are_imported"})
                warnings_list.append(
                    f"Skipped {record['type']} or disabled breakpoint at {record['rva']}; only enabled software breakpoints are imported."
                )
            elif address in existing_breakpoints:
                noops.append({**record, "reason": "breakpoint_already_exists"})
            else:
                # Deliberately omit command/log/condition fields from untrusted evidence.
                actions.append({**record, "operation": "create"})

    if selected["patches"]:
        for item in normalized.get("patches", []):
            rva = int(item["rva"])
            address = base + rva
            read = ReadMemory(f"0x{address:X}", 1, ty="hex", max_chars=0)
            current_byte = None
            if isinstance(read, dict) and read.get("ok"):
                try:
                    current_byte = bytes.fromhex(str(read.get("hex") or ""))[0]
                except (ValueError, IndexError):
                    current_byte = None
            if current_byte is None:
                return _analysis_error(
                    "PREFLIGHT_FAILED", "Failed to read a byte before patch import.", address=f"0x{address:X}"
                )
            old_byte = int(item["oldByte"])
            new_byte = int(item["newByte"])
            record = {
                "kind": "patch",
                "rva": f"0x{rva:X}",
                "address": f"0x{address:X}",
                "oldByte": f"0x{old_byte:02X}",
                "newByte": f"0x{new_byte:02X}",
                "currentByte": f"0x{current_byte:02X}",
            }
            if current_byte == new_byte:
                noops.append({**record, "reason": "already_patched"})
            elif current_byte != old_byte and not overwrite_existing:
                conflicts.append({**record, "reason": "original_byte_mismatch"})
            else:
                actions.append({**record, "operation": "update"})

    ignored_counts = {
        key: len(normalized.get(key, []))
        for key in ("labels", "comments", "bookmarks", "functions", "breakpoints", "patches")
        if not selected.get(key, False)
    }
    session_payload = hello_payload.get("session") if isinstance(hello_payload.get("session"), dict) else {}
    bridge_identity = hello.get("identity") if isinstance(hello.get("identity"), dict) else {}
    event_seq = int(
        _parse_int(bridge_identity.get("eventSeq"), _parse_int(session_payload.get("eventSeq"), 0)) or 0
    )
    plan = {
        "module": current_image,
        "evidenceImage": evidence_image,
        "identity": {
            "hashMatches": hash_matches,
            "hashMismatchAllowed": bool(allow_hash_mismatch and not hash_matches),
            "runtimeBase": f"0x{base:X}",
        },
        "selected": selected,
        "actions": actions,
        "noops": noops,
        "conflicts": conflicts,
        "ignoredCounts": ignored_counts,
        "warnings": list(dict.fromkeys(warnings_list)),
        "eventSeq": event_seq,
        "transactional": False,
        "guard": "session identity + event sequence CAS",
    }
    if dry_run:
        return {
            "ok": not conflicts,
            "dryRun": True,
            "canApply": not conflicts,
            "wouldMutate": len(actions),
            "validation": public_validation,
            "plan": plan,
        }
    if conflicts:
        return {
            "ok": False,
            "dryRun": False,
            "errorCode": "IMPORT_CONFLICT",
            "error": "Preflight found conflicts; no mutations were applied.",
            "validation": public_validation,
            "plan": plan,
            "applied": [],
        }
    if not bool(session_payload.get("paused")):
        return {
            "ok": False,
            "dryRun": False,
            "errorCode": "TARGET_NOT_PAUSED",
            "error": "Pause the target before applying analysis evidence.",
            "validation": public_validation,
            "plan": plan,
            "applied": [],
        }
    if event_seq <= 0:
        return {
            "ok": False,
            "dryRun": False,
            "errorCode": "EVENT_IDENTITY_UNAVAILABLE",
            "error": "The bridge did not provide an event sequence for guarded import.",
            "validation": public_validation,
            "plan": plan,
            "applied": [],
        }

    applied: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    for action in actions:
        kind = action["kind"]
        if kind == "label":
            endpoint = "Label/Set"
            data = {"addr": action["address"], "text": action["text"], "manual": str(action["manual"]).lower()}
        elif kind == "comment":
            endpoint = "Comment/Set"
            data = {"addr": action["address"], "text": action["text"], "manual": str(action["manual"]).lower()}
        elif kind == "bookmark":
            endpoint = "Bookmark/Set"
            data = {"addr": action["address"], "manual": str(action["manual"]).lower()}
        elif kind == "function":
            endpoint = "Function/Add"
            data = {
                "start": action["start"],
                "end": action["end"],
                "manual": str(action["manual"]).lower(),
                "instructionCount": str(action["instructionCount"]),
            }
        elif kind == "breakpoint":
            endpoint = "Debug/SetBreakpoint"
            data = {"addr": action["address"]}
        elif kind == "patch":
            endpoint = "Memory/Write"
            data = {"addr": action["address"], "data": f"{_parse_int(action['newByte'], 0) or 0:02X}"}
        else:
            failures.append({"action": action, "error": "Unsupported planned mutation"})
            break
        success, response, message = _analysis_guarded_mutation(endpoint, data, event_seq)
        if not success:
            failures.append({"action": action, "endpoint": endpoint, "error": message, "response": response})
            break
        applied.append({"action": action, "endpoint": endpoint, "response": response})

    verification_failures: List[Dict[str, Any]] = []
    function_ranges: Optional[set[Tuple[int, int]]] = None
    breakpoint_addresses: Optional[set[int]] = None
    for entry in applied:
        action = entry["action"]
        kind = action["kind"]
        if kind == "label":
            result = LabelGet(action["address"])
            verified = bool(result.get("found")) and str(result.get("label") or "") == action["text"]
        elif kind == "comment":
            result = CommentGet(action["address"])
            verified = bool(result.get("found")) and str(result.get("comment") or "") == action["text"]
        elif kind == "bookmark":
            result = BookmarkGet(action["address"])
            verified = bool(result.get("found"))
        elif kind == "function":
            if function_ranges is None:
                function_items, function_error = _analysis_collect_paged(
                    FunctionList, module_name, "functions"
                )
                function_ranges = {
                    (int(start), int(end))
                    for start, end in (
                        (_parse_int(item.get("rvaStart"), None), _parse_int(item.get("rvaEnd"), None))
                        for item in function_items
                        if isinstance(item, dict)
                    )
                    if start is not None and end is not None
                } if not function_error else set()
            verified = (
                (_parse_int(action["rvaStart"], -1), _parse_int(action["rvaEndInclusive"], -1))
                in function_ranges
            )
            result = {"ranges": len(function_ranges)}
        elif kind == "breakpoint":
            if breakpoint_addresses is None:
                payload = GetBreakpointList("all")
                breakpoint_addresses = {
                    int(value)
                    for value in (
                        _parse_int(item.get("addr"), None)
                        for item in payload.get("breakpoints", [])
                        if isinstance(item, dict)
                    )
                    if value is not None
                } if isinstance(payload, dict) else set()
            verified = (_parse_int(action["address"], -1) or -1) in breakpoint_addresses
            result = {"breakpoints": len(breakpoint_addresses)}
        else:
            result = ReadMemory(action["address"], 1, ty="hex", max_chars=0)
            expected = f"{_parse_int(action['newByte'], 0) or 0:02x}"
            verified = bool(result.get("ok")) and str(result.get("hex") or "").lower() == expected
        entry["verified"] = bool(verified)
        if not verified:
            verification_failures.append({"action": action, "response": result})

    ok = not failures and not verification_failures and len(applied) == len(actions)
    return {
        "ok": ok,
        "dryRun": False,
        "validation": public_validation,
        "plan": plan,
        "applied": applied,
        "appliedCount": len(applied),
        "failures": failures,
        "verificationFailures": verification_failures,
        "partial": bool(applied) and not ok,
    }


_RUNTIME_EVIDENCE_SCHEMA = "x64dbg-mcp-runtime-evidence"
_RUNTIME_EVIDENCE_VERSION = 1


def _runtime_load_json_value(value: Any, label: str) -> Tuple[Optional[Any], Optional[Dict[str, Any]]]:
    """Load a bounded JSON value from inline text or a normal local file."""

    raw = str(value or "").strip()
    if not raw:
        return None, None
    try:
        if os.path.isfile(raw):
            resolved = os.path.abspath(raw)
            lowered = resolved.casefold()
            if lowered.startswith("\\\\.\\") or lowered.startswith("\\\\?\\globalroot"):
                return None, _analysis_error("UNSAFE_PATH", f"{label} cannot use a device path.")
            if os.path.getsize(resolved) > _ANALYSIS_EVIDENCE_MAX_BYTES:
                return None, _analysis_error("EVIDENCE_TOO_LARGE", f"{label} exceeds 32 MiB.", path=resolved)
            with open(resolved, "r", encoding="utf-8") as handle:
                return json.load(handle), None
        if len(raw.encode("utf-8")) > _ANALYSIS_EVIDENCE_MAX_BYTES:
            return None, _analysis_error("EVIDENCE_TOO_LARGE", f"{label} exceeds 32 MiB.")
        return json.loads(raw), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, _analysis_error("INVALID_JSON", f"Failed to load {label}.", error=str(exc))


def _runtime_collect_api_calls(trace_id: str, limit: int = 100_000) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Read an API trace with strict forward-only pagination."""

    if not str(trace_id or "").strip():
        return [], None
    calls: List[Dict[str, Any]] = []
    offset = 0
    for _ in range(1000):
        payload = GetApiTraceLog(str(trace_id), offset=offset, limit=min(5000, limit))
        if not isinstance(payload, dict) or not payload.get("ok"):
            return [], _analysis_error("API_TRACE_NOT_FOUND", "Failed to read the requested API trace.", response=payload)
        page = [dict(item) for item in payload.get("calls", []) if isinstance(item, dict)]
        calls.extend(page)
        if len(calls) > limit:
            return [], _analysis_error("EVIDENCE_TOO_LARGE", "API trace evidence exceeds the item limit.")
        total = int(payload.get("total") or len(calls))
        if offset + len(page) >= total:
            return calls, None
        if not page:
            return [], _analysis_error("INVALID_PAGINATION", "API trace pagination did not advance.")
        offset += len(page)
    return [], _analysis_error("INVALID_PAGINATION", "API trace pagination did not terminate.")


def _runtime_normalize_coverage(
    raw: Any, image_sha256: str
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    value = raw
    if isinstance(value, dict) and isinstance(value.get("artifacts"), list):
        values = value.get("artifacts") or []
    elif value in (None, ""):
        values = []
    else:
        values = [value]
    artifacts: List[Dict[str, Any]] = []
    for index, item in enumerate(values):
        artifact, error = _coverage_artifact_input(item, f"coverage[{index}]")
        if error or artifact is None:
            return [], _analysis_error("INVALID_COVERAGE", error or "Coverage artifact is invalid.")
        stable = str(artifact.get("stableIdentity") or "").upper()
        if image_sha256 and image_sha256.upper() not in stable:
            return [], _analysis_error(
                "IDENTITY_MISMATCH",
                "Coverage artifact is bound to a different image SHA-256.",
                expected=image_sha256.upper(),
                actual=stable,
            )
        body = dict(artifact)
        body["artifactSha256"] = _coverage_artifact_digest(artifact)
        artifacts.append(body)
    return artifacts, None


def _runtime_normalize_dumps(
    raw: Any,
) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]]]:
    value = raw
    if isinstance(value, dict) and isinstance(value.get("dumps"), list):
        values = value.get("dumps") or []
    elif value in (None, ""):
        values = []
    else:
        values = [value]
    output: List[Dict[str, Any]] = []
    for index, item in enumerate(values):
        if isinstance(item, str):
            item = {"path": item}
        if not isinstance(item, dict):
            return [], _analysis_error("INVALID_DUMP_ARTIFACT", f"dumps[{index}] must be an object or path.")
        path = str(item.get("path") or "").strip()
        if not path:
            return [], _analysis_error("INVALID_DUMP_ARTIFACT", f"dumps[{index}].path is required.")
        resolved = os.path.abspath(path)
        lowered = resolved.casefold()
        if lowered.startswith("\\\\.\\") or lowered.startswith("\\\\?\\globalroot"):
            return [], _analysis_error("UNSAFE_PATH", "Device paths are not accepted for dump evidence.")
        try:
            stat = os.stat(resolved)
            if not os.path.isfile(resolved) or stat.st_size > _ANALYSIS_EVIDENCE_MAX_BYTES:
                return [], _analysis_error("INVALID_DUMP_ARTIFACT", "Dump is missing or exceeds 32 MiB.", path=resolved)
            digest = hashlib.sha256(Path(resolved).read_bytes()).hexdigest().upper()
        except OSError as exc:
            return [], _analysis_error("INVALID_DUMP_ARTIFACT", "Failed to hash dump artifact.", path=resolved, error=str(exc))
        declared = str(item.get("sha256") or "").strip().upper()
        if declared and declared != digest:
            return [], _analysis_error(
                "ARTIFACT_HASH_MISMATCH", "Dump artifact hash does not match its file.", path=resolved,
                expected=declared, actual=digest,
            )
        output.append({
            "kind": str(item.get("kind") or "dump"),
            "path": resolved,
            "size": int(stat.st_size),
            "sha256": digest,
            "label": str(item.get("label") or ""),
        })
    return output, None


def _runtime_document_from_input(value: Any) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    document, error = _runtime_load_json_value(value, "runtime evidence")
    if error or document is None:
        return None, error or _analysis_error("INVALID_JSON", "Runtime evidence is empty.")
    if not isinstance(document, dict):
        return None, _analysis_error("INVALID_SCHEMA", "Runtime evidence must be a JSON object.")
    if document.get("schema") == _RUNTIME_EVIDENCE_SCHEMA:
        static = document.get("staticEvidence")
        image = document.get("image")
        if not isinstance(static, dict) or not isinstance(image, dict):
            return None, _analysis_error("INVALID_SCHEMA", "Runtime evidence lacks staticEvidence/image.")
        return {
            "schema": _ANALYSIS_EVIDENCE_SCHEMA,
            "version": _ANALYSIS_EVIDENCE_VERSION,
            "image": image,
            "evidence": static,
            "counts": {key: len(value) for key, value in static.items() if isinstance(value, list)},
        }, None
    return document, None


def _runtime_artifact_digest(document: Dict[str, Any]) -> str:
    body = {key: value for key, value in document.items() if key != "artifactSha256"}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest().upper()


@mcp.tool()
def ResolveModuleRva(
    module: str = "",
    address: str = "",
    rva: str = "",
    expected_sha256: str = "",
) -> dict:
    """Resolve one runtime address or RVA to a stable image-SHA-256+RVA key."""

    if bool(str(address or "").strip()) == bool(str(rva or "").strip()):
        return _analysis_error("INVALID_ARGUMENT", "Provide exactly one of address or rva.")
    context, error = _analysis_module_context(module, expected_sha256)
    if error or context is None:
        return error or _analysis_error("MODULE_NOT_FOUND", "Module could not be resolved.")
    image = dict(context["identity"])
    base = int(context["base"])
    size = int(context["size"])
    try:
        if str(rva or "").strip():
            parsed_rva = _analysis_parse_rva(rva, size, "rva")
            absolute = base + parsed_rva
        else:
            absolute = _parse_int(address, None)
            if absolute is None or not (base <= absolute < base + size):
                raise ValueError("address is outside the selected runtime module")
            parsed_rva = absolute - base
    except ValueError as exc:
        return _analysis_error("INVALID_ARGUMENT", str(exc))
    digest = str(image.get("sha256") or "").upper()
    return {
        "ok": True,
        "schema": "runtime-location-v1",
        "image": image,
        "module": image.get("name"),
        "address": f"0x{absolute:X}",
        "rva": f"0x{parsed_rva:X}",
        "stableKey": f"{digest}:0x{parsed_rva:X}",
        "session": GetSessionBinding(),
    }


@mcp.tool()
def ExportRuntimeEvidence(
    module: str = "",
    output_path: str = "",
    overwrite: bool = False,
    native_trace_id: str = "",
    api_trace_id: str = "",
    coverage_artifact_json: str = "",
    comparison_recovery_json: str = "",
    dump_artifacts_json: str = "",
    include_static: bool = True,
) -> dict:
    """Export static annotations plus hash+RVA runtime evidence for IDA."""

    if include_static:
        static_result = ExportAnalysisEvidence(
            module=module,
            include_breakpoints=True,
            include_patches=True,
            native_trace_id=native_trace_id,
            api_trace_id=api_trace_id,
        )
        if not isinstance(static_result, dict) or not static_result.get("ok"):
            return static_result if isinstance(static_result, dict) else _analysis_error(
                "EXPORT_FAILED", "Static evidence export failed."
            )
        static_document = dict(static_result.get("document") or {})
    else:
        hello = BridgeHello(refresh=True)
        if not isinstance(hello, dict) or not hello.get("ok"):
            return _analysis_error(
                "BRIDGE_IDENTITY_UNAVAILABLE",
                "Authoritative bridge identity is unavailable.",
                response=hello,
            )
        context, error = _analysis_module_context(module)
        if error or context is None:
            return error or _analysis_error("MODULE_NOT_FOUND", "Module could not be resolved.")
        identity = dict(context["identity"])
        identity_payload = hello.get("identity") if isinstance(hello, dict) else {}
        static_document = {
            "schema": _ANALYSIS_EVIDENCE_SCHEMA,
            "version": _ANALYSIS_EVIDENCE_VERSION,
            "image": identity,
            "evidence": {},
            "session": identity_payload if isinstance(identity_payload, dict) else {},
        }
    image = dict(static_document.get("image") or {})
    image_sha = str(image.get("sha256") or "").upper()
    coverage_input, error = _runtime_load_json_value(coverage_artifact_json, "coverage artifact")
    if error:
        return error
    coverage, error = _runtime_normalize_coverage(coverage_input, image_sha)
    if error:
        return error
    if native_trace_id and not coverage:
        live = GetBasicBlockCoverage(native_trace_id, limit=5000)
        if not isinstance(live, dict) or not live.get("ok"):
            return _analysis_error("COVERAGE_EXPORT_FAILED", "Failed to read native coverage.", response=live)
        coverage, error = _runtime_normalize_coverage(_coverage_artifact_body(live), image_sha)
        if error:
            return error
    api_calls, error = _runtime_collect_api_calls(api_trace_id)
    if error:
        return error
    recovery, error = _runtime_load_json_value(comparison_recovery_json, "comparison recovery")
    if error:
        return error
    if recovery is None:
        recovery = []
    elif isinstance(recovery, dict) and isinstance(recovery.get("results"), list):
        recovery = recovery["results"]
    elif not isinstance(recovery, list):
        recovery = [recovery]
    dumps_input, error = _runtime_load_json_value(dump_artifacts_json, "dump artifacts")
    if error:
        return error
    dumps, error = _runtime_normalize_dumps(dumps_input)
    if error:
        return error
    bridge_identity = static_document.get("session") if isinstance(static_document.get("session"), dict) else {}
    runtime = {
        "coverageArtifacts": coverage,
        "apiTraces": [{
            "traceId": str(api_trace_id or "") or None,
            "callCount": len(api_calls),
            "calls": api_calls,
        }] if api_trace_id else [],
        "comparisonRecoveries": recovery,
        "dumps": dumps,
    }
    document = {
        "schema": _RUNTIME_EVIDENCE_SCHEMA,
        "version": _RUNTIME_EVIDENCE_VERSION,
        "generatedAt": _now_iso(),
        "addressModel": {"kind": "image-sha256+module+rva", "encoding": "hex-string"},
        "producer": {"name": "x64dbgMCP", "staticSchema": _ANALYSIS_EVIDENCE_SCHEMA},
        "image": image,
        "session": bridge_identity,
        "staticEvidence": static_document.get("evidence") if isinstance(static_document.get("evidence"), dict) else {},
        "runtimeEvidence": runtime,
        "counts": {
            "coverageArtifacts": len(coverage),
            "apiCalls": len(api_calls),
            "comparisonRecoveries": len(recovery),
            "dumps": len(dumps),
        },
    }
    document["artifactSha256"] = _runtime_artifact_digest(document)
    output = None
    if str(output_path or "").strip():
        output = _analysis_write_json(output_path, document, overwrite)
        if not output.get("ok"):
            return {**output, "document": document}
    return {
        "ok": True,
        "schema": _RUNTIME_EVIDENCE_SCHEMA,
        "document": document,
        "artifactSha256": document["artifactSha256"],
        "output": output,
    }


@mcp.tool()
def ImportStaticAnnotations(
    evidence_json: str = "",
    input_path: str = "",
    module: str = "",
    dry_run: bool = True,
    allow_hash_mismatch: bool = False,
    overwrite_existing: bool = False,
) -> dict:
    """Import only static labels/comments/bookmarks/functions from runtime evidence."""

    if bool(str(evidence_json or "").strip()) == bool(str(input_path or "").strip()):
        return _analysis_error("INVALID_ARGUMENT", "Provide exactly one of evidence_json or input_path.")
    document, error = _runtime_document_from_input(evidence_json or input_path)
    if error or document is None:
        return error or _analysis_error("INVALID_JSON", "Static evidence could not be loaded.")
    return ImportAnalysisEvidence(
        evidence_json=json.dumps(document, ensure_ascii=False),
        module=module,
        dry_run=dry_run,
        allow_hash_mismatch=allow_hash_mismatch,
        overwrite_existing=overwrite_existing,
        apply_labels=True,
        apply_comments=True,
        apply_bookmarks=True,
        apply_functions=True,
        apply_breakpoints=False,
        apply_patches=False,
    )


@mcp.tool()
def SyncBreakpoints(
    evidence_json: str = "",
    input_path: str = "",
    module: str = "",
    apply: bool = False,
    allow_hash_mismatch: bool = False,
    overwrite_existing: bool = False,
) -> dict:
    """Dry-run or apply enabled software breakpoints from static/runtime evidence."""

    if bool(str(evidence_json or "").strip()) == bool(str(input_path or "").strip()):
        return _analysis_error("INVALID_ARGUMENT", "Provide exactly one of evidence_json or input_path.")
    document, error = _runtime_document_from_input(evidence_json or input_path)
    if error or document is None:
        return error or _analysis_error("INVALID_JSON", "Breakpoint evidence could not be loaded.")
    result = ImportAnalysisEvidence(
        evidence_json=json.dumps(document, ensure_ascii=False),
        module=module,
        dry_run=not bool(apply),
        allow_hash_mismatch=allow_hash_mismatch,
        overwrite_existing=overwrite_existing,
        apply_labels=False,
        apply_comments=False,
        apply_bookmarks=False,
        apply_functions=False,
        apply_breakpoints=True,
        apply_patches=False,
    )
    if isinstance(result, dict):
        result = dict(result)
        result["schema"] = "breakpoint-sync-v1"
    return result


_MANAGED_EVIDENCE_SCHEMA = "managed-evidence-v1"


def _managed_heap_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return "" if text == "None" else text


def _managed_file_context(path: str = "", module: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    requested_path = _repair_text_mojibake(str(path or "").strip())
    if requested_path and str(module or "").strip():
        return None, _analysis_error("INVALID_ARGUMENT", "Provide path or module, not both.")
    if requested_path:
        lowered = requested_path.replace("/", "\\").casefold()
        if lowered.startswith("\\\\.\\") or lowered.startswith("\\\\?\\globalroot"):
            return None, _analysis_error("UNSAFE_PATH", "Device paths are not accepted.")
        resolved = os.path.abspath(requested_path)
        if not os.path.isfile(resolved):
            return None, _analysis_error("INPUT_NOT_FOUND", "Managed assembly path does not exist.", path=resolved)
        try:
            layout = _parse_pe_layout(resolved)
            stat = os.stat(resolved)
        except Exception as exc:
            return None, _analysis_error("PE_PARSE_FAILED", "Failed to parse the managed PE.", error=str(exc))
        return {
            "path": resolved,
            "layout": layout,
            "base": None,
            "size": int(layout.get("sizeOfImage") or 0),
            "identity": {
                "name": os.path.basename(resolved),
                "path": resolved,
                "sha256": _sha256_file(resolved).upper(),
                "fileSize": int(stat.st_size),
                "arch": str(layout.get("arch") or ""),
                "machine": str(layout.get("machine") or ""),
                "sizeOfImage": int(layout.get("sizeOfImage") or 0),
                "entryPointRva": str(layout.get("entryPointRva") or "0x0"),
            },
        }, None
    context, error = _analysis_module_context(module)
    if error or context is None:
        return None, error or _analysis_error("MODULE_NOT_FOUND", "Managed module could not be resolved.")
    return context, None


def _managed_method_body(pe: Any, row: Any, include_il: bool) -> Dict[str, Any]:
    rva = int(getattr(row, "Rva", 0) or 0)
    result: Dict[str, Any] = {
        "rva": f"0x{rva:X}",
        "hasBody": False,
        "headerKind": None,
        "codeSize": 0,
        "maxStack": None,
        "localVarSigToken": None,
        "ilSha256": None,
        "ilPreviewHex": None,
    }
    if rva <= 0:
        return result
    try:
        header = bytes(pe.get_data(rva, 16) or b"")
        if not header:
            return result
        kind = header[0] & 0x3
        if kind == 0x2:
            header_size = 1
            code_size = header[0] >> 2
            max_stack = 8
            local_token = 0
            header_kind = "tiny"
        elif kind == 0x3 and len(header) >= 12:
            flags_size = int.from_bytes(header[:2], "little")
            header_size = ((flags_size >> 12) & 0xF) * 4
            if header_size < 12 or header_size > 64:
                return result
            max_stack = int.from_bytes(header[2:4], "little")
            code_size = int.from_bytes(header[4:8], "little")
            local_token = int.from_bytes(header[8:12], "little")
            header_kind = "fat"
        else:
            return result
        if code_size < 0 or code_size > 16 * 1024 * 1024:
            return result
        il = bytes(pe.get_data(rva + header_size, code_size) or b"")
        if len(il) != code_size:
            return result
        result.update(
            hasBody=True,
            headerKind=header_kind,
            codeSize=code_size,
            maxStack=max_stack,
            localVarSigToken=f"0x{local_token:08X}" if local_token else None,
            ilSha256=hashlib.sha256(il).hexdigest().upper(),
            ilPreviewHex=il[:64].hex() if include_il else None,
        )
    except Exception:
        pass
    return result


def _managed_probe_component(arch: str) -> Dict[str, Any]:
    normalized = "x86" if str(arch or "").casefold() in ("x86", "x32") else "x64"
    repo_root = Path(__file__).resolve().parents[1]
    explicit = os.getenv(f"X64DBG_MCP_MANAGED_PROBE_{normalized.upper()}", "").strip()
    candidates = [
        explicit,
        str(repo_root / "tools" / "bin" / "managed_probe" / normalized / "x64dbg.ManagedProbe.exe"),
    ]
    executable = next(
        (os.path.abspath(item) for item in candidates if item and os.path.isfile(item)),
        "",
    )
    if not executable:
        return _analysis_error(
            "MANAGED_PROBE_UNAVAILABLE",
            f"The {normalized} managed runtime sidecar is not built.",
            buildScript=str(repo_root / "tools" / "build_managed_probe.ps1"),
            architecture=normalized,
        )
    component_dir = os.path.dirname(executable)
    self_contained = all(
        os.path.isfile(os.path.join(component_dir, name))
        for name in ("hostfxr.dll", "coreclr.dll")
    )
    root_env = f"DOTNET_ROOT_{normalized.upper()}"
    explicit_host = os.getenv(f"X64DBG_MCP_DOTNET_{normalized.upper()}", "").strip()
    program_files_env = "ProgramFiles(x86)" if normalized == "x86" else "ProgramFiles"
    program_files = os.getenv(program_files_env, "").strip()
    path_host = shutil.which("dotnet") if normalized == "x64" else ""
    root_candidates = [
        os.path.dirname(explicit_host) if explicit_host.casefold().endswith("dotnet.exe") else explicit_host,
        os.getenv(root_env, "").strip(),
        os.getenv("DOTNET_ROOT", "").strip() if normalized == "x64" else "",
        os.path.dirname(path_host) if path_host else "",
        os.path.join(program_files, "dotnet") if program_files else "",
    ]
    runtime_root = next(
        (
            os.path.abspath(item)
            for item in root_candidates
            if item
            and os.path.isfile(os.path.join(item, "dotnet.exe"))
            and _detect_pe_arch(os.path.join(item, "dotnet.exe")) in (None, normalized)
        ),
        "",
    )
    if not self_contained and not runtime_root:
        return _analysis_error(
            "MANAGED_RUNTIME_UNAVAILABLE",
            (
                f"The {normalized} managed probe is framework-dependent, but a matching "
                ".NET 8 runtime could not be found. Rebuild the release sidecar as "
                f"self-contained or set {root_env}."
            ),
            architecture=normalized,
            executable=executable,
            runtimeEnvironment=root_env,
            buildScript=str(repo_root / "tools" / "build_managed_probe.ps1"),
        )
    return {
        "ok": True,
        "architecture": normalized,
        "executable": executable,
        "selfContained": self_contained,
        "runtimeRoot": runtime_root or None,
        "runtimeEnvironment": root_env,
    }


def _managed_binding_record(binding_payload: Any) -> Dict[str, Any]:
    if not isinstance(binding_payload, dict):
        return {}
    snapshot = binding_payload.get("binding")
    if not isinstance(snapshot, dict):
        return {}
    record = snapshot.get("binding")
    return dict(record) if isinstance(record, dict) else {}


def _managed_session_key(binding_payload: Any) -> Dict[str, Any]:
    record = _managed_binding_record(binding_payload)
    return {
        "pid": int(record.get("pid") or 0),
        "bridgeInstanceId": str(record.get("bridgeInstanceId") or ""),
        "sessionId": str(record.get("sessionId") or ""),
        "sessionGeneration": int(record.get("sessionGeneration") or 0),
        "imageSha256": str(record.get("imageSha256") or "").upper(),
        "debuggerArch": str(record.get("debuggerArch") or "").casefold(),
    }


def _managed_probe_invoke(
    pid: int,
    arch: str,
    *,
    metadata_token: Optional[int] = None,
    instruction_pointer: Optional[int] = None,
    module: str = "",
    max_threads: int = 256,
    max_frames: int = 256,
    max_modules: int = 4096,
    max_maps: int = 4096,
    timeout_ms: int = 30000,
) -> Dict[str, Any]:
    component = _managed_probe_component(arch)
    if not component.get("ok"):
        return component
    command = [
        str(component["executable"]),
        "--pid",
        str(int(pid)),
        "--max-threads",
        str(max(1, min(int(max_threads), 4096))),
        "--max-frames",
        str(max(1, min(int(max_frames), 4096))),
        "--max-modules",
        str(max(1, min(int(max_modules), 100_000))),
        "--max-maps",
        str(max(1, min(int(max_maps), 100_000))),
    ]
    if metadata_token is not None:
        command.extend(["--token", f"0x{int(metadata_token) & 0xFFFFFFFF:08X}"])
    if instruction_pointer is not None:
        command.extend(["--ip", f"0x{int(instruction_pointer):X}"])
    if str(module or "").strip():
        command.extend(["--module", str(module).strip()])
    environment = os.environ.copy()
    runtime_root = str(component.get("runtimeRoot") or "")
    if runtime_root:
        environment["DOTNET_ROOT"] = runtime_root
        environment[str(component["runtimeEnvironment"])] = runtime_root
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(2.0, min(float(timeout_ms) / 1000.0, 120.0)),
            check=False,
            env=environment,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
    except subprocess.TimeoutExpired as exc:
        return _analysis_error(
            "MANAGED_PROBE_TIMEOUT",
            "The managed runtime sidecar exceeded its bounded deadline.",
            timeoutMs=int(timeout_ms),
            stdout=str(exc.stdout or "")[-2000:],
            stderr=str(exc.stderr or "")[-2000:],
        )
    stdout = str(completed.stdout or "").strip()
    try:
        payload = json.loads(stdout)
    except Exception as exc:
        return _analysis_error(
            "MANAGED_PROBE_INVALID_OUTPUT",
            "The managed runtime sidecar did not return one JSON document.",
            exitCode=int(completed.returncode),
            error=str(exc),
            stdout=stdout[-4000:],
            stderr=str(completed.stderr or "")[-4000:],
        )
    if not isinstance(payload, dict):
        return _analysis_error(
            "MANAGED_PROBE_INVALID_OUTPUT",
            "The managed runtime sidecar returned a non-object JSON value.",
        )
    payload["component"] = {
        "architecture": component.get("architecture"),
        "executable": component.get("executable"),
        "selfContained": component.get("selfContained"),
        "runtimeRoot": component.get("runtimeRoot"),
        "exitCode": int(completed.returncode),
        "elapsedMs": round((time.monotonic() - started) * 1000.0, 2),
        "stderr": str(completed.stderr or "")[-4000:],
    }
    if completed.returncode != 0 or payload.get("ok") is not True:
        payload["ok"] = False
    return payload


@mcp.tool()
def InspectManagedAssembly(
    path: str = "",
    module: str = "",
    include_il: bool = False,
    max_types: int = 2000,
    max_methods: int = 10000,
) -> dict:
    """Inspect CLR metadata, type/method tokens and optional bounded IL bytes."""

    try:
        import dnfile
    except Exception as exc:
        return _analysis_error(
            "DEPENDENCY_UNAVAILABLE",
            "dnfile is required for managed metadata inspection.",
            dependency="dnfile>=0.17.0",
            error=str(exc),
        )
    context, error = _managed_file_context(path, module)
    if error or context is None:
        return error or _analysis_error("INPUT_NOT_FOUND", "Managed assembly could not be resolved.")
    type_limit = max(1, min(int(max_types), 100_000))
    method_limit = max(1, min(int(max_methods), 500_000))
    pe = None
    try:
        pe = dnfile.dnPE(str(context["path"]))
        if not getattr(pe, "net", None):
            return {
                "ok": True,
                "schema": "managed-assembly-inspection-v1",
                "isManaged": False,
                "image": dict(context["identity"]),
                "reason": "CLR_HEADER_NOT_PRESENT",
            }
        net = pe.net
        tables = getattr(net, "mdtables", None)
        if tables is None:
            return _analysis_error("METADATA_UNAVAILABLE", "CLR metadata tables are unavailable.")
        flags = {
            str(name): bool(enabled)
            for name, enabled in list(getattr(net, "Flags", None) or [])
        }
        raw_file = Path(str(context["path"])).read_bytes()
        framework_match = re.search(
            rb"\.NET(?:CoreApp|Framework|Standard),Version=v[0-9.]+",
            raw_file,
        )
        assembly_rows = list(getattr(getattr(tables, "Assembly", None), "rows", None) or [])
        assembly = None
        if assembly_rows:
            row = assembly_rows[0]
            public_key = bytes(getattr(getattr(row, "PublicKey", None), "value", b"") or b"")
            assembly = {
                "name": _managed_heap_text(getattr(row, "Name", "")),
                "version": ".".join(
                    str(int(getattr(row, name, 0) or 0))
                    for name in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
                ),
                "culture": _managed_heap_text(getattr(row, "Culture", "")),
                "publicKeySha256": hashlib.sha256(public_key).hexdigest().upper() if public_key else None,
            }
        references: List[Dict[str, Any]] = []
        for index, row in enumerate(
            list(getattr(getattr(tables, "AssemblyRef", None), "rows", None) or []),
            1,
        ):
            references.append(
                {
                    "token": f"0x{0x23000000 | index:08X}",
                    "name": _managed_heap_text(getattr(row, "Name", "")),
                    "version": ".".join(
                        str(int(getattr(row, name, 0) or 0))
                        for name in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
                    ),
                    "culture": _managed_heap_text(getattr(row, "Culture", "")),
                }
            )
        owner_by_method: Dict[int, str] = {}
        types: List[Dict[str, Any]] = []
        type_rows = list(getattr(getattr(tables, "TypeDef", None), "rows", None) or [])
        for index, row in enumerate(type_rows[:type_limit], 1):
            namespace = _managed_heap_text(getattr(row, "TypeNamespace", ""))
            name = _managed_heap_text(getattr(row, "TypeName", ""))
            full_name = f"{namespace}.{name}".strip(".")
            method_tokens: List[str] = []
            for method_index in list(getattr(row, "MethodList", None) or []):
                row_index = int(getattr(method_index, "row_index", 0) or 0)
                if row_index > 0:
                    owner_by_method[row_index] = full_name
                    method_tokens.append(f"0x{0x06000000 | row_index:08X}")
            types.append(
                {
                    "token": f"0x{0x02000000 | index:08X}",
                    "namespace": namespace,
                    "name": name,
                    "fullName": full_name,
                    "methodTokens": method_tokens,
                }
            )
        methods: List[Dict[str, Any]] = []
        method_rows = list(getattr(getattr(tables, "MethodDef", None), "rows", None) or [])
        for index, row in enumerate(method_rows[:method_limit], 1):
            signature = bytes(getattr(getattr(row, "Signature", None), "value", b"") or b"")
            method = {
                "token": f"0x{0x06000000 | index:08X}",
                "declaringType": owner_by_method.get(index, ""),
                "name": _managed_heap_text(getattr(row, "Name", "")),
                "signatureBlobHex": signature.hex(),
                "flags": [
                    str(name)
                    for name, enabled in list(getattr(row, "Flags", None) or [])
                    if enabled
                ],
                "implementationFlags": [
                    str(name)
                    for name, enabled in list(getattr(row, "ImplFlags", None) or [])
                    if enabled
                ],
                **_managed_method_body(pe, row, bool(include_il)),
            }
            methods.append(method)
        metadata_struct = getattr(getattr(net, "metadata", None), "struct", None)
        metadata_version = bytes(getattr(metadata_struct, "Version", b"") or b"")
        runtime_arch = _dotnet_effective_arch(str(context["path"]))
        return {
            "ok": True,
            "schema": "managed-assembly-inspection-v1",
            "isManaged": True,
            "image": dict(context["identity"]),
            "runtime": {
                "metadataVersion": metadata_version.rstrip(b"\0").decode("ascii", errors="replace"),
                "majorRuntimeVersion": int(getattr(net.struct, "MajorRuntimeVersion", 0) or 0),
                "minorRuntimeVersion": int(getattr(net.struct, "MinorRuntimeVersion", 0) or 0),
                "executionArchitecture": runtime_arch,
                "targetFramework": framework_match.group(0).decode("ascii") if framework_match else None,
                "flags": flags,
            },
            "assembly": assembly,
            "assemblyReferences": references,
            "types": types,
            "methods": methods,
            "counts": {
                "assemblyReferences": len(references),
                "types": len(type_rows),
                "typesReturned": len(types),
                "methods": len(method_rows),
                "methodsReturned": len(methods),
            },
            "truncated": len(type_rows) > len(types) or len(method_rows) > len(methods),
        }
    except Exception as exc:
        return _analysis_error("MANAGED_PARSE_FAILED", "Failed to parse CLR metadata.", error=str(exc))
    finally:
        try:
            if pe is not None:
                pe.close()
        except Exception:
            pass


@mcp.tool()
def ResolveManagedToken(
    token_or_name: str,
    path: str = "",
    module: str = "",
) -> dict:
    """Resolve a MethodDef token/name to IL RVA and the loaded module address."""

    inspection = InspectManagedAssembly(path=path, module=module, include_il=True)
    if not isinstance(inspection, dict) or not inspection.get("ok") or not inspection.get("isManaged"):
        return inspection
    query = str(token_or_name or "").strip()
    token_value = _parse_int(query, None)
    methods = [dict(item) for item in inspection.get("methods", []) if isinstance(item, dict)]
    if token_value is not None:
        matches = [item for item in methods if _parse_int(item.get("token"), None) == token_value]
    else:
        folded = query.casefold()
        matches = [
            item for item in methods
            if str(item.get("name") or "").casefold() == folded
            or f"{item.get('declaringType')}::{item.get('name')}".casefold() == folded
        ]
    if not matches:
        return _analysis_error("METHOD_NOT_FOUND", "No MethodDef matches the token or name.", query=query)
    if len(matches) != 1:
        return _analysis_error(
            "AMBIGUOUS_METHOD", "More than one MethodDef matches; use a metadata token.",
            query=query, matches=[item.get("token") for item in matches],
        )
    method = matches[0]
    il_rva = _parse_int(method.get("rva"), 0) or 0
    runtime_address = None
    if not path:
        context, _error = _managed_file_context("", module)
        if context is not None and context.get("base") is not None and il_rva:
            runtime_address = f"0x{int(context['base']) + il_rva:X}"
    return {
        "ok": True,
        "schema": "managed-method-resolution-v1",
        "image": inspection.get("image"),
        "method": method,
        "ilRva": f"0x{il_rva:X}",
        "ilAddress": runtime_address,
        "jitNativeAddress": None,
        "jitMappingSupported": False,
        "limitation": "IL RVA is metadata/body storage, not a JIT-native code address.",
    }


@mcp.tool()
def GetManagedRuntimeState(module: str = "") -> dict:
    """Report managed image metadata and the loaded CLR/CoreCLR runtime modules."""

    inspection = InspectManagedAssembly(module=module, include_il=False, max_types=1, max_methods=1)
    if not isinstance(inspection, dict) or not inspection.get("ok"):
        return inspection
    payload = GetModuleList()
    modules = [dict(item) for item in payload.get("modules", []) if isinstance(item, dict)] if isinstance(payload, dict) else []
    runtime_names = {"coreclr.dll", "clr.dll", "mscorwks.dll", "mscoree.dll", "clrjit.dll"}
    loaded = [
        item for item in modules
        if os.path.basename(str(item.get("path") or item.get("name") or "")).casefold() in runtime_names
    ]
    names = {
        os.path.basename(str(item.get("path") or item.get("name") or "")).casefold()
        for item in loaded
    }
    runtime_kind = (
        "coreclr" if "coreclr.dll" in names
        else "desktop-clr" if {"clr.dll", "mscorwks.dll"} & names
        else "bootstrap-only" if "mscoree.dll" in names
        else "not-loaded"
    )
    return {
        "ok": True,
        "schema": "managed-runtime-state-v1",
        "isManaged": bool(inspection.get("isManaged")),
        "runtimeKind": runtime_kind,
        "loadedRuntimeModules": loaded,
        "assembly": inspection.get("assembly"),
        "runtime": inspection.get("runtime"),
        "image": inspection.get("image"),
        "session": GetSessionBinding(),
    }


@mcp.tool()
def GetManagedExceptionHistory(
    trace_id: str,
    after_seq: int = 0,
    limit: int = 100,
) -> dict:
    """Return only CLR/CoreCLR exception events from native API trace evidence."""

    evidence = GetNativeApiTraceEvidence(trace_id, after_seq=after_seq, limit=limit)
    if not isinstance(evidence, dict) or not evidence.get("ok"):
        return evidence
    events = [
        dict(item) for item in evidence.get("events", [])
        if isinstance(item, dict) and bool(item.get("managedException"))
    ]
    return {
        "ok": True,
        "schema": "managed-exception-history-v1",
        "traceId": trace_id,
        "events": events,
        "count": len(events),
        "nextAfterSeq": int(evidence.get("nextAfterSeq") or evidence.get("latestSeq") or after_seq),
        "exceptionUnwoundPendingCalls": int(evidence.get("exceptionUnwoundPendingCalls") or 0),
        "droppedEvents": int(evidence.get("droppedEvents") or 0),
    }


@mcp.tool()
def CaptureManagedRuntimeState(
    metadata_token: str = "",
    instruction_pointer: str = "",
    module: str = "",
    pause_if_running: bool = True,
    resume_after: bool = False,
    max_threads: int = 256,
    max_frames: int = 256,
    max_modules: int = 4096,
    max_maps: int = 4096,
    timeout_ms: int = 30000,
) -> dict:
    """Capture CLR/AppDomain/module/thread/stack/JIT state via a passive sidecar.

    The target must be paused for a coherent ClrMD read.  The sidecar never
    claims the debug port and performs no target mutation.  Optional token
    resolution is intentionally scoped to methods present on active managed
    stacks; unavailable pre-JIT methods are reported as not found.
    """

    token_value = None
    if str(metadata_token or "").strip():
        token_value = _parse_int(metadata_token, None)
        if token_value is None or token_value < 0 or token_value > 0xFFFFFFFF:
            return _analysis_error("INVALID_ARGUMENT", "metadata_token is not a 32-bit token.")
    ip_value = None
    if str(instruction_pointer or "").strip():
        ip_value = _parse_int(instruction_pointer, None)
        if ip_value is None or ip_value < 0:
            return _analysis_error("INVALID_ARGUMENT", "instruction_pointer is invalid.")

    state = _build_debug_state(
        include_console=False,
        include_callstack=False,
        max_console_chars=0,
    )
    if not isinstance(state, dict) or not state.get("debugging"):
        return _analysis_error(
            "DEBUG_SESSION_REQUIRED",
            "CaptureManagedRuntimeState requires an active debug session.",
            state=state,
        )
    paused_by_tool = False
    resume_result: Any = None
    if not state.get("paused"):
        if not pause_if_running:
            return _analysis_error(
                "TARGET_NOT_PAUSED",
                "The target must be paused for a coherent managed runtime capture.",
                state=state,
            )
        pause_result = DebugPause()
        state = WaitForPause(
            timeout_ms=min(max(int(timeout_ms), 1000), 10000),
            poll_ms=50,
        )
        if not isinstance(state, dict) or not state.get("paused"):
            return _analysis_error(
                "PAUSE_FAILED",
                "x64dbg did not enter a paused state before managed capture.",
                pause=pause_result,
                state=state,
            )
        paused_by_tool = True

    before = GetSessionBinding()
    before_key = _managed_session_key(before)
    pid = int(before_key.get("pid") or state.get("debuggeePid") or 0)
    if pid <= 0 or not before_key.get("sessionId"):
        return _analysis_error(
            "SESSION_IDENTITY_UNAVAILABLE",
            "Exact bound-session identity is required before managed capture.",
            session=before,
        )
    arch = str(before_key.get("debuggerArch") or "").casefold()
    if arch not in ("x86", "x64"):
        arch = _detect_pe_arch(str(state.get("debuggeePath") or "")) or ""
    try:
        report = _managed_probe_invoke(
            pid,
            arch,
            metadata_token=token_value,
            instruction_pointer=ip_value,
            module=module,
            max_threads=max_threads,
            max_frames=max_frames,
            max_modules=max_modules,
            max_maps=max_maps,
            timeout_ms=timeout_ms,
        )
        after = GetSessionBinding()
        after_key = _managed_session_key(after)
        identity_match = before_key == after_key
        process = report.get("process") if isinstance(report, dict) else {}
        sidecar_pid = int(process.get("pid") or 0) if isinstance(process, dict) else 0
        if not identity_match or sidecar_pid != pid:
            return _analysis_error(
                "SESSION_CHANGED_DURING_CAPTURE",
                "The bound debug session changed while CLR state was being read.",
                before=before_key,
                after=after_key,
                sidecarPid=sidecar_pid,
            )
        result = dict(report) if isinstance(report, dict) else {"ok": False}
        result["pausedByTool"] = paused_by_tool
        result["resumed"] = bool(paused_by_tool and resume_after)
        result["session"] = before_key
        result["imageSha256"] = before_key.get("imageSha256")
        result["identityVerified"] = True
        return result
    finally:
        if paused_by_tool and resume_after:
            resume_result = DebugRun()
            _log_event("managed_capture_resume", result=resume_result)


@mcp.tool()
def ResolveManagedJitMethod(
    metadata_token: str = "",
    instruction_pointer: str = "",
    module: str = "",
    timeout_ms: int = 30000,
) -> dict:
    """Resolve an active managed method to JIT/NGen native ranges and IL maps."""

    if bool(str(metadata_token or "").strip()) == bool(str(instruction_pointer or "").strip()):
        return _analysis_error(
            "INVALID_ARGUMENT",
            "Provide exactly one of metadata_token or instruction_pointer.",
        )
    capture = CaptureManagedRuntimeState(
        metadata_token=metadata_token,
        instruction_pointer=instruction_pointer,
        module=module,
        pause_if_running=True,
        resume_after=False,
        timeout_ms=timeout_ms,
    )
    if not isinstance(capture, dict) or not capture.get("ok"):
        return capture
    resolutions = [
        dict(item)
        for item in capture.get("resolutions", [])
        if isinstance(item, dict)
    ]
    matches: List[Dict[str, Any]] = []
    for resolution in resolutions:
        method = resolution.get("method")
        if isinstance(method, dict):
            matches.append(dict(method))
        matches.extend(
            dict(item)
            for item in resolution.get("methods", [])
            if isinstance(item, dict)
        )
    unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for method in matches:
        unique[
            (
                str(method.get("methodDesc") or ""),
                str(method.get("nativeCode") or ""),
            )
        ] = method
    methods = list(unique.values())
    return {
        "ok": True,
        "schema": "managed-jit-resolution-v1",
        "found": bool(methods),
        "methods": methods,
        "count": len(methods),
        "scope": "active-managed-stack" if metadata_token else "instruction-pointer",
        "query": {
            "metadataToken": metadata_token or None,
            "instructionPointer": instruction_pointer or None,
            "module": module or None,
        },
        "session": capture.get("session"),
        "imageSha256": capture.get("imageSha256"),
        "limitation": (
            None
            if methods
            else "The method is not present on an active managed stack or has not been JIT-compiled."
        ),
    }


@mcp.tool()
def SetManagedMethodBreakpoint(
    metadata_token: str,
    module: str = "",
    name: str = "",
    singleshoot: bool = False,
    timeout_ms: int = 30000,
) -> dict:
    """Set a native x64dbg breakpoint on an already-JIT/NGen managed method."""

    resolution = ResolveManagedJitMethod(
        metadata_token=metadata_token,
        module=module,
        timeout_ms=timeout_ms,
    )
    if not isinstance(resolution, dict) or not resolution.get("ok"):
        return resolution
    methods = [
        item
        for item in resolution.get("methods", [])
        if isinstance(item, dict) and (_parse_int(item.get("nativeCode"), 0) or 0) > 0
    ]
    if not methods:
        return _analysis_error(
            "METHOD_NOT_JITTED",
            "No active JIT/NGen native address exists for this managed token.",
            resolution=resolution,
        )
    if len(methods) != 1:
        return _analysis_error(
            "AMBIGUOUS_MANAGED_METHOD",
            "The token resolves to more than one active native body; narrow the module.",
            methods=methods,
        )
    method = methods[0]
    address = f"0x{int(_parse_int(method.get('nativeCode'), 0) or 0):X}"
    set_result = DebugSetBreakpoint(address)
    configured: List[Any] = []
    breakpoint_name = str(name or "").strip() or (
        f"managed:{method.get('declaringType')}::{method.get('name')}"
    )
    escaped_name = breakpoint_name.replace("\\", "\\\\").replace('"', '\\"')
    configured.append(
        ExecCommand(f'SetBreakpointName {address}, "{escaped_name}"')
    )
    if singleshoot:
        configured.append(ExecCommand(f"SetBreakpointSingleshoot {address}, 1"))
    return {
        "ok": "success" in str(set_result).casefold(),
        "schema": "managed-method-breakpoint-v1",
        "address": address,
        "method": method,
        "name": breakpoint_name,
        "singleshoot": bool(singleshoot),
        "setResult": set_result,
        "configuration": configured,
        "session": resolution.get("session"),
        "ownership": "caller",
        "limitation": "Pre-JIT breakpoint binding requires a CLR debugging backend and is not claimed.",
    }


@mcp.tool()
def ExportManagedRuntimeEvidence(
    output_path: str,
    metadata_token: str = "",
    instruction_pointer: str = "",
    module: str = "",
    overwrite: bool = False,
    timeout_ms: int = 30000,
) -> dict:
    """Atomically export a session-bound CLR/JIT/stack capture."""

    capture = CaptureManagedRuntimeState(
        metadata_token=metadata_token,
        instruction_pointer=instruction_pointer,
        module=module,
        pause_if_running=True,
        resume_after=False,
        timeout_ms=timeout_ms,
    )
    if not isinstance(capture, dict) or not capture.get("ok"):
        return capture
    document = {
        "schema": "managed-runtime-evidence-v1",
        "version": 1,
        "generatedAt": _now_iso(),
        "imageSha256": capture.get("imageSha256"),
        "session": capture.get("session"),
        "capture": capture,
    }
    document["artifactSha256"] = _runtime_artifact_digest(document)
    output = _analysis_write_json(output_path, document, overwrite)
    return {
        "ok": bool(output.get("ok")),
        "schema": document["schema"],
        "artifactSha256": document["artifactSha256"],
        "output": output,
        "document": document,
    }


@mcp.tool()
def ExportManagedAssemblyMetadata(
    output_path: str,
    module: str = "",
    overwrite: bool = False,
    timeout_ms: int = 30000,
) -> dict:
    """Extract a bounded CLR metadata stream from a paused managed module.

    This is intentionally a metadata-stream artifact, not a claim that a
    dynamic assembly has been reconstructed into a runnable PE.  Dynamic and
    non-PE modules are supported when ClrMD exposes a metadata address/length;
    provenance, target identity and an exact SHA-256 are retained.
    """

    capture = CaptureManagedRuntimeState(
        module=module,
        pause_if_running=True,
        resume_after=False,
        timeout_ms=timeout_ms,
    )
    if not isinstance(capture, dict) or not capture.get("ok"):
        return capture
    session = capture.get("session")
    if not isinstance(session, dict) or not session.get("sessionId"):
        return _analysis_error(
            "SESSION_IDENTITY_UNAVAILABLE",
            "Exact bound-session identity is required before metadata extraction.",
        )
    modules: List[Dict[str, Any]] = []
    for runtime in capture.get("runtimes", []):
        if not isinstance(runtime, dict):
            continue
        for domain in runtime.get("appDomains", []):
            if not isinstance(domain, dict):
                continue
            modules.extend(
                dict(item)
                for item in domain.get("modules", [])
                if isinstance(item, dict)
            )
    query = str(module or "").strip().casefold()
    def _managed_module_is_memory_only(item: Dict[str, Any]) -> bool:
        name = str(item.get("name") or "").strip()
        assembly_name = str(item.get("assemblyName") or "").strip()
        return not any(
            os.path.isfile(candidate)
            for candidate in (name, assembly_name)
            if candidate
        )

    candidates = [
        item
        for item in modules
        if bool(item.get("isDynamic"))
        or not bool(item.get("isPeFile"))
        or _managed_module_is_memory_only(item)
    ]
    if query:
        candidates = [
            item
            for item in candidates
            if query in str(item.get("name") or "").casefold()
            or query in str(item.get("assemblyName") or "").casefold()
        ]
    if not candidates:
        return _analysis_error(
            "DYNAMIC_ASSEMBLY_NOT_FOUND",
            "No dynamic or non-PE managed module with metadata was found.",
            module=module or None,
            available=[
                {
                    "name": item.get("name"),
                    "isDynamic": bool(item.get("isDynamic")),
                    "isPeFile": bool(item.get("isPeFile")),
                    "isMemoryOnly": _managed_module_is_memory_only(item),
                    "metadataLength": item.get("metadataLength"),
                }
                for item in modules
            ],
        )
    if len(candidates) != 1:
        return _analysis_error(
            "AMBIGUOUS_DYNAMIC_ASSEMBLY",
            "More than one dynamic/non-PE managed module matches.",
            module=module or None,
            matches=[item.get("name") or item.get("assemblyName") for item in candidates],
        )
    selected = candidates[0]
    metadata_address = _parse_int(selected.get("metadataAddress"), 0) or 0
    metadata_length = _parse_int(selected.get("metadataLength"), 0) or 0
    if metadata_address <= 0 or not (1 <= metadata_length <= 16 * 1024 * 1024):
        return _analysis_error(
            "METADATA_STREAM_UNAVAILABLE",
            "ClrMD did not expose a bounded metadata address/length for this module.",
            module=selected,
        )
    requested = _repair_text_mojibake(str(output_path or "").strip())
    if not requested:
        return _analysis_error("INVALID_ARGUMENT", "output_path is required")
    target = os.path.abspath(requested)
    target_lower = target.casefold()
    if target_lower.startswith("\\\\.\\") or target_lower.startswith("\\\\?\\globalroot"):
        return _analysis_error("UNSAFE_PATH", "Device paths are not accepted.")
    if os.path.exists(target) and not overwrite:
        return _analysis_error("OUTPUT_EXISTS", "Evidence output already exists.", path=target)
    parent = os.path.dirname(target)
    os.makedirs(parent, exist_ok=True)
    temporary = ""
    try:
        fd, temporary = tempfile.mkstemp(prefix=".managed-metadata-", suffix=".bin", dir=parent)
        os.close(fd)
        os.remove(temporary)
        saved = SaveMemoryRegionToFile(
            temporary,
            f"0x{metadata_address:X}",
            metadata_length,
        )
        if not isinstance(saved, dict) or not saved.get("ok") or not os.path.isfile(temporary):
            return _analysis_error(
                "METADATA_READ_FAILED",
                "x64dbg could not save the exposed CLR metadata stream.",
                save=saved,
            )
        raw = Path(temporary).read_bytes()
        if len(raw) != metadata_length:
            return _analysis_error(
                "METADATA_READ_TRUNCATED",
                "The saved metadata stream length differs from ClrMD provenance.",
                expected=metadata_length,
                actual=len(raw),
            )
        after_key = _managed_session_key(GetSessionBinding())
        expected_key = {
            "pid": int(session.get("pid") or 0),
            "bridgeInstanceId": str(session.get("bridgeInstanceId") or ""),
            "sessionId": str(session.get("sessionId") or ""),
            "sessionGeneration": int(session.get("sessionGeneration") or 0),
            "imageSha256": str(session.get("imageSha256") or "").upper(),
            "debuggerArch": str(session.get("debuggerArch") or "").casefold(),
        }
        if after_key != expected_key:
            return _analysis_error(
                "SESSION_CHANGED_DURING_CAPTURE",
                "The debug session changed while metadata was being extracted.",
                before=expected_key,
                after=after_key,
            )
        document = {
            "schema": "managed-assembly-metadata-v1",
            "version": 1,
            "generatedAt": _now_iso(),
            "imageSha256": session.get("imageSha256"),
            "session": session,
            "module": {
                key: selected.get(key)
                for key in (
                    "name",
                    "assemblyName",
                    "appDomain",
                    "imageBase",
                    "size",
                    "isDynamic",
                    "isPeFile",
                    "metadataAddress",
                    "metadataLength",
                )
            },
            "metadata": {
                "length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest().upper(),
                "base64": base64.b64encode(raw).decode("ascii"),
                "formatHint": "CLR metadata root stream (BSJB expected)",
            },
            "limitations": {
                "runnablePe": False,
                "note": "This is a metadata-stream extraction; dynamic IL/native bodies are not rebuilt into a PE.",
            },
        }
        document["module"]["isMemoryOnly"] = _managed_module_is_memory_only(selected)
        document["artifactSha256"] = _runtime_artifact_digest(document)
        output = _analysis_write_json(target, document, overwrite)
        return {
            "ok": bool(output.get("ok")),
            "schema": document["schema"],
            "artifactSha256": document["artifactSha256"],
            "output": output,
            "module": document["module"],
            "metadata": {
                "length": len(raw),
                "sha256": document["metadata"]["sha256"],
            },
        }
    except Exception as exc:
        return _analysis_error("METADATA_EXPORT_FAILED", "Managed metadata extraction failed.", error=str(exc))
    finally:
        if temporary:
            try:
                os.remove(temporary)
            except OSError:
                pass


@mcp.tool()
def ExportManagedEvidence(
    output_path: str = "",
    path: str = "",
    module: str = "",
    overwrite: bool = False,
    include_il: bool = True,
    max_types: int = 2000,
    max_methods: int = 10000,
) -> dict:
    """Export canonical SHA-256-bound CLR metadata and bounded IL evidence."""

    inspection = InspectManagedAssembly(
        path=path,
        module=module,
        include_il=include_il,
        max_types=max_types,
        max_methods=max_methods,
    )
    if not isinstance(inspection, dict) or not inspection.get("ok") or not inspection.get("isManaged"):
        return inspection
    document = {
        "schema": _MANAGED_EVIDENCE_SCHEMA,
        "version": 1,
        "generatedAt": _now_iso(),
        "image": inspection.get("image"),
        "runtime": inspection.get("runtime"),
        "assembly": inspection.get("assembly"),
        "assemblyReferences": inspection.get("assemblyReferences"),
        "types": inspection.get("types"),
        "methods": inspection.get("methods"),
        "counts": inspection.get("counts"),
        "truncated": bool(inspection.get("truncated")),
        "session": GetSessionBinding() if not path else None,
        "limitations": {
            "jitNativeMapping": False,
            "managedLocals": False,
            "managedBreakpoints": False,
            "note": "This artifact covers CLR metadata/IL and exception correlation, not ICorDebug JIT state.",
        },
    }
    document["artifactSha256"] = _runtime_artifact_digest(document)
    output = None
    if str(output_path or "").strip():
        output = _analysis_write_json(output_path, document, overwrite)
        if not output.get("ok"):
            return {**output, "document": document}
    return {
        "ok": True,
        "schema": _MANAGED_EVIDENCE_SCHEMA,
        "document": document,
        "artifactSha256": document["artifactSha256"],
        "output": output,
    }


@mcp.tool()
def EnumHandles() -> dict:
    """
    Enumerate all open handles in the debugged process.
    Returns handle values, types, access rights, names, and type names.
    Useful for analyzing file handles, registry keys, mutexes, events, etc.

    Returns:
        Dictionary with:
        - count: Number of handles
        - handles: List of handle objects with handle (hex), typeNumber,
          grantedAccess (hex), name, and typeName
    """
    result = safe_get("EnumHandles")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except Exception:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


import argparse


def main_cli():
    parser = argparse.ArgumentParser(description="x64dbg MCP CLI wrapper")

    parser.add_argument(
        "tool", help="Tool/function name (e.g. ExecCommand, RegisterGet, MemoryRead)"
    )
    parser.add_argument("args", nargs="*", help="Arguments for the tool")
    parser.add_argument(
        "--x64dbg-url",
        dest="x64dbg_url",
        default=os.getenv("X64DBG_URL"),
        help="x64dbg HTTP server URL",
    )

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Map CLI call → actual MCP tool function
    if opts.tool in globals():
        func = globals()[opts.tool]
        if callable(func):
            try:
                kwargs: Dict[str, Any] = {}
                positional: List[Any] = []
                for arg in opts.args:
                    if "=" in arg:
                        key, value = arg.split("=", 1)
                        kwargs[key] = value
                    else:
                        positional.append(arg)

                if kwargs and not positional:
                    result = _invoke_tool_by_name(opts.tool, kwargs)
                else:
                    sig = inspect.signature(func)
                    type_hints = _resolve_callable_type_hints(func)
                    coerced_args: List[Any] = []
                    parameters = [
                        p
                        for p in sig.parameters.values()
                        if p.kind
                        not in (
                            inspect.Parameter.VAR_POSITIONAL,
                            inspect.Parameter.VAR_KEYWORD,
                        )
                    ]
                    for index, arg in enumerate(positional):
                        if index >= len(parameters):
                            coerced_args.append(arg)
                            continue
                        param = parameters[index]
                        annotation = type_hints.get(param.name, param.annotation)
                        value = _coerce_value_for_annotation(arg, annotation)
                        coerced_args.append(value)
                    result = _invoke_public_callable(opts.tool, func, *coerced_args)
                print(json.dumps(result, indent=2))
            except TypeError as e:
                print(f"Error calling {opts.tool}: {e}")
        else:
            print(f"{opts.tool} is not callable")
    else:
        print(f"Unknown tool: {opts.tool}")


def claude_cli():
    parser = argparse.ArgumentParser(
        description="Chat with Claude using x64dbg MCP tools"
    )
    parser.add_argument(
        "prompt",
        nargs=argparse.REMAINDER,
        help="Initial user prompt. If empty, read from stdin",
    )
    parser.add_argument(
        "--model",
        dest="model",
        default=os.getenv("ANTHROPIC_MODEL", "claude-opus-4-8"),
        help="Claude model",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=os.getenv("ANTHROPIC_API_KEY"),
        help="Anthropic API key",
    )
    parser.add_argument(
        "--system",
        dest="system",
        default="You can control x64dbg via MCP tools.",
        help="System prompt",
    )
    parser.add_argument(
        "--max-steps",
        dest="max_steps",
        type=int,
        default=100,
        help="Max tool-use iterations",
    )
    parser.add_argument(
        "--x64dbg-url",
        dest="x64dbg_url",
        default=os.getenv("X64DBG_URL"),
        help="x64dbg HTTP server URL",
    )
    parser.add_argument(
        "--no-tools",
        dest="no_tools",
        action="store_true",
        help="Disable tool-use (text-only)",
    )

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Resolve prompt
    user_prompt = " ".join(opts.prompt).strip()
    if not user_prompt:
        user_prompt = sys.stdin.read().strip()
    if not user_prompt:
        print("No prompt provided.")
        return

    try:
        import anthropic
    except Exception as e:
        print("Anthropic SDK not installed. Run: pip install anthropic")
        print(str(e))
        return

    if not opts.api_key:
        print("Missing Anthropic API key. Set ANTHROPIC_API_KEY or pass --api-key.")
        return

    client = anthropic.Anthropic(api_key=opts.api_key)

    tools_spec: List[Dict[str, Any]] = []
    if not opts.no_tools:
        tools_spec = [
            {
                "name": "mcp_list_tools",
                "description": "List available MCP tool functions and their parameters.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "mcp_call_tool",
                "description": "Invoke an MCP tool by name with arguments.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"},
                    },
                    "required": ["tool"],
                },
            },
        ]

    messages: List[Dict[str, Any]] = [{"role": "user", "content": user_prompt}]

    step = 0
    while True:
        step += 1
        response = client.messages.create(
            model=opts.model,
            system=opts.system,
            messages=messages,
            tools=tools_spec if not opts.no_tools else None,
            max_tokens=1024,
        )

        # Print any assistant text
        assistant_text_chunks: List[str] = []
        tool_uses: List[Dict[str, Any]] = []
        for block in response.content:
            b = _block_to_dict(block)
            if b.get("type") == "text":
                assistant_text_chunks.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_uses.append(b)

        if assistant_text_chunks:
            print("\n".join(assistant_text_chunks))

        if not tool_uses or opts.no_tools:
            break

        # Prepare tool results as a new user message
        tool_result_blocks: List[Dict[str, Any]] = []
        for tu in tool_uses:
            name = tu.get("name")
            tu_id = tu.get("id")
            input_obj = tu.get("input", {}) or {}
            result: Any
            if name == "mcp_list_tools":
                result = {"tools": _list_tools_description()}
            elif name == "mcp_call_tool":
                tool_name = input_obj.get("tool")
                args = input_obj.get("args", {}) or {}
                result = _invoke_tool_by_name(tool_name, args)
            else:
                result = {"error": f"Unknown tool: {name}"}

            # Ensure serializable content (string)
            try:
                result_text = json.dumps(result)
            except Exception:
                result_text = str(result)

            tool_result_blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu_id,
                    "content": result_text,
                }
            )

        # Normalize assistant content to plain dicts
        assistant_blocks = [_block_to_dict(b) for b in response.content]
        messages.append({"role": "assistant", "content": assistant_blocks})
        messages.append({"role": "user", "content": tool_result_blocks})

        if step >= opts.max_steps:
            break


_EXT_TOOLS_STATUS: Dict[str, Any] = {"loaded": False, "error": None}
