import atexit
import ctypes
import importlib.util
import logging
import os
import signal
import subprocess
import sys
import threading
import warnings
from pathlib import Path
from typing import BinaryIO, Optional


BROKER_CHILD_ENV = "X64DBG_STDIO_BROKER_CHILD"


def _configure_runtime() -> None:
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONWARNINGS", "ignore")
    if not sys.warnoptions:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
    try:
        logging.basicConfig(level=logging.ERROR, force=True)
    except TypeError:
        logging.basicConfig(level=logging.ERROR)
    logging.getLogger().setLevel(logging.ERROR)
    for logger_name in (
        "mcp",
        "mcp.server",
        "mcp.server.fastmcp",
        "mcp.server.fastmcp.server",
        "mcp.server.lowlevel.server",
        "FastMCP",
    ):
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.ERROR)
        logger.propagate = True
    # stderr is a separate MCP transport channel and must stay observable.
    # Hiding it made import/contract failures look like opaque startup timeouts
    # and also leaked a devnull stream until interpreter shutdown.


def _signal_to_keyboard_interrupt(signum, frame):  # type: ignore[no-untyped-def]
    raise KeyboardInterrupt


def _install_signal_handlers() -> None:
    for signal_name in ("SIGINT", "SIGBREAK"):
        sig = getattr(signal, signal_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _signal_to_keyboard_interrupt)
        except Exception:
            continue


def _load_server_module():
    module_path = Path(__file__).with_name("x64dbg.py")
    spec = importlib.util.spec_from_file_location("x64dbg_mcp_server", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load x64dbg server module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_embedded_server() -> int:
    _install_signal_handlers()
    module = _load_server_module()
    try:
        module.mcp.run()
    except KeyboardInterrupt:
        return 0
    return 0


def _child_creation_flags() -> int:
    flags = 0
    for name in ("CREATE_NEW_PROCESS_GROUP", "CREATE_NO_WINDOW"):
        flags |= int(getattr(subprocess, name, 0))
    return flags


def _safe_close(stream: Optional[BinaryIO]) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except Exception:
        pass


def _pump_stream(
    reader: BinaryIO,
    writer: BinaryIO,
    *,
    close_writer: bool,
    stop_event: Optional[threading.Event] = None,
    eof_grace_seconds: float = 0.0,
) -> None:
    reader_read1 = getattr(reader, "read1", None)
    reader_fileno = getattr(reader, "fileno", None)
    file_descriptor: Optional[int] = None
    if callable(reader_fileno):
        try:
            file_descriptor = int(reader_fileno())
        except (OSError, TypeError, ValueError):
            file_descriptor = None
    try:
        while stop_event is None or not stop_event.is_set():
            chunk = b""
            # Prefer the raw descriptor.  BufferedReader.read1() owns an
            # internal lock while blocked; abandoning such a daemon thread at
            # CPython shutdown triggers _enter_buffered_busy and, on Windows,
            # an application-error dialog.  os.read() is also cancellable with
            # CancelSynchronousIo below.
            if file_descriptor is not None:
                try:
                    chunk = os.read(file_descriptor, 65536)
                except OSError:
                    chunk = b""
            elif callable(reader_read1):
                chunk = reader_read1(65536)
            else:
                chunk = reader.read(4096)
            if not chunk:
                # A test harness (and some MCP hosts during a quick restart)
                # may write several JSON-RPC frames and close its pipe
                # immediately.  Keep the child pipe open for one short grace
                # window so the embedded async server can dispatch every
                # already-forwarded frame before observing EOF.
                if close_writer and eof_grace_seconds > 0:
                    if stop_event is None:
                        threading.Event().wait(eof_grace_seconds)
                    else:
                        stop_event.wait(eof_grace_seconds)
                break
            writer.write(chunk)
            writer.flush()
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        if close_writer:
            _safe_close(writer)
        else:
            try:
                writer.flush()
            except Exception:
                pass


def _cancel_synchronous_io(thread: threading.Thread) -> bool:
    """Cancel a Windows pipe/console read owned by ``thread``.

    The broker must be able to leave when its child exits even while the MCP
    host keeps stdin open.  Returning False is harmless: the caller has a
    bounded hard-exit fallback after all child resources have been released.
    """

    if os.name != "nt" or thread.native_id is None or not thread.is_alive():
        return not thread.is_alive()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_thread = kernel32.OpenThread
    open_thread.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
    open_thread.restype = ctypes.c_void_p
    cancel_io = kernel32.CancelSynchronousIo
    cancel_io.argtypes = (ctypes.c_void_p,)
    cancel_io.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int
    # CancelSynchronousIo requires THREAD_TERMINATE access.
    handle = open_thread(0x0001, 0, int(thread.native_id))
    if not handle:
        return False
    try:
        ctypes.set_last_error(0)
        if cancel_io(handle):
            return True
        # ERROR_NOT_FOUND means the thread had no pending synchronous I/O and
        # is normally already between the read and its exit check.
        return ctypes.get_last_error() == 1168
    finally:
        close_handle(handle)


def _spawn_isolated_child() -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env[BROKER_CHILD_ENV] = "1"
    env.setdefault("PYTHONUNBUFFERED", "1")
    kwargs = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        # Inherit the broker's stderr.  MCP reserves stdout for protocol
        # frames; stderr is the correct diagnostic channel.
        "stderr": None,
        "bufsize": 0,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = _child_creation_flags()
    return subprocess.Popen(
        [sys.executable, "-u", str(Path(__file__))],
        **kwargs,
    )


def _run_broker(*, hard_exit_on_stuck_pump: bool = True) -> int:
    child = _spawn_isolated_child()
    stop_event = threading.Event()

    def _cleanup() -> None:
        if child.poll() is not None:
            return
        try:
            child.terminate()
            child.wait(timeout=2)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass

    atexit.register(_cleanup)

    parent_stdin = getattr(sys.stdin, "buffer", sys.stdin)
    parent_stdout = getattr(sys.stdout, "buffer", sys.stdout)

    stdin_thread = threading.Thread(
        target=_pump_stream,
        args=(parent_stdin, child.stdin),
        kwargs={
            "close_writer": True,
            "stop_event": stop_event,
            "eof_grace_seconds": 0.1,
        },
        daemon=True,
        name="x64dbg-stdin-forwarder",
    )
    stdout_thread = threading.Thread(
        target=_pump_stream,
        args=(child.stdout, parent_stdout),
        # The child has a finite stdout pipe.  Let this pump drain through EOF;
        # cancelling it at process exit could discard the final MCP response.
        kwargs={"close_writer": False},
        daemon=True,
        name="x64dbg-stdout-forwarder",
    )
    stdin_thread.start()
    stdout_thread.start()

    try:
        return_code = child.wait()
    except KeyboardInterrupt:
        _cleanup()
        return_code = 0
    finally:
        stop_event.set()
        _cancel_synchronous_io(stdin_thread)
        stdin_thread.join(timeout=2.0)
        stdout_thread.join(timeout=2.0)
        if stdout_thread.is_alive():
            _safe_close(child.stdout)
            stdout_thread.join(timeout=1.0)
        try:
            atexit.unregister(_cleanup)
        except Exception:
            pass

    code = int(return_code or 0)
    if stdin_thread.is_alive() or stdout_thread.is_alive():
        # Never enter CPython finalization with a live stdio pump.  This path is
        # only reached after the child has exited and its resources were closed.
        # os._exit avoids both a hang and the _enter_buffered_busy crash dialog.
        if hard_exit_on_stuck_pump:
            try:
                parent_stdout.flush()
            except Exception:
                pass
            os._exit(code if code >= 0 else 1)
    return code


def main() -> int:
    _configure_runtime()
    if os.getenv(BROKER_CHILD_ENV) == "1":
        return _run_embedded_server()
    return _run_broker()


if __name__ == "__main__":
    raise SystemExit(main())
