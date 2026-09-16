def _load_ext_tools() -> None:
    try:
        import importlib.util as _iu

        _ext_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "ext_tools.py"
        )
        if not os.path.exists(_ext_path):
            _EXT_TOOLS_STATUS.update(loaded=False, error="ext_tools.py not found next to x64dbg.py")
            return
        spec = _iu.spec_from_file_location("x64dbg_ext_tools", _ext_path)
        if spec is None or spec.loader is None:
            _EXT_TOOLS_STATUS.update(loaded=False, error="Failed to build import spec for ext_tools.py")
            return
        mod = _iu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        register = getattr(mod, "register", None)
        if callable(register):
            register(mcp, globals())
            _EXT_TOOLS_STATUS.update(loaded=True, error=None)
        else:
            _EXT_TOOLS_STATUS.update(loaded=False, error="ext_tools.py exposes no register() function")
    except Exception as _ext_err:  # pragma: no cover - best-effort
        _EXT_TOOLS_STATUS.update(loaded=False, error=str(_ext_err))
        try:
            print(f"[ext_tools] load failed: {_ext_err}", file=sys.stderr)
        except Exception:
            pass


_load_ext_tools()


# Install the result contract only after every optional module has registered its
# tools, so extension routes receive exactly the same envelope as
# core routes. Direct Python calls remain available as the compatibility shim.
_install_public_result_envelopes()


_TOOL_PROFILE_STATUS: Dict[str, Any] = {
    "loaded": False,
    "requested": str(os.getenv("X64DBG_MCP_TOOL_PROFILE") or "full").strip().lower(),
    "active": "full",
    "error": None,
}
_TOOL_CATALOG: Dict[str, Any] = {}


def _apply_tool_profiles() -> None:
    """Attach schema-v2 metadata after every optional tool module is loaded."""

    global _TOOL_CATALOG
    import importlib.util as _iu

    profile_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "tool_profiles.py"
    )
    spec = _iu.spec_from_file_location("x64dbg_tool_profiles", profile_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Failed to load tool_profiles.py")
    profile_module = sys.modules.get("x64dbg_tool_profiles")
    if profile_module is None:
        profile_module = _iu.module_from_spec(spec)
        # dataclasses resolves postponed annotations through sys.modules while
        # the class decorator runs, so publish the module before exec_module.
        sys.modules["x64dbg_tool_profiles"] = profile_module
        try:
            spec.loader.exec_module(profile_module)
        except Exception:
            sys.modules.pop("x64dbg_tool_profiles", None)
            raise
    requested = str(_TOOL_PROFILE_STATUS.get("requested") or "full")
    known_profiles = tuple(getattr(profile_module, "PROFILE_NAMES", ("full",)))
    active = requested if requested in known_profiles else "full"
    invalid_error = None
    if active != requested:
        invalid_error = (
            f"Unknown X64DBG_MCP_TOOL_PROFILE={requested!r}; using compatibility profile 'full'"
        )
    catalog = profile_module.apply_tool_metadata(
        mcp, _get_mcp_tools_registry(), active_profile=active
    )
    if active != "full":
        manager = mcp._tool_manager
        unfiltered_list_tools = manager.list_tools

        def _profiled_list_tools():
            return profile_module.filter_mcp_tools(
                unfiltered_list_tools(), catalog, active
            )

        manager.list_tools = _profiled_list_tools
    _TOOL_CATALOG = catalog
    _TOOL_PROFILE_STATUS.update(
        loaded=True,
        active=active,
        error=invalid_error,
        schemaVersion=int(catalog.get("schemaVersion") or 0),
        visibleCount=len(catalog.get("visibleTools") or []),
        totalCount=int(catalog.get("count") or 0),
    )


_apply_tool_profiles()


if __name__ == "__main__":
    # Support multiple modes:
    #  - "serve" or "--serve": run MCP server
    #  - "claude" subcommand: run Claude Messages chat loop
    #  - default: tool invocation CLI
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--serve", "serve"):
            _become_primary_server_instance()
            _start_server_lock_watchdog()
            mcp.run()
        elif sys.argv[1] == "claude":
            # Shift off the subcommand and re-dispatch
            sys.argv.pop(1)
            claude_cli()
        else:
            main_cli()
    else:
        _become_primary_server_instance()
        _start_server_lock_watchdog()
        mcp.run()
