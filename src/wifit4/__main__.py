"""Entry point for ``python -m wifit4`` and the ``wifit4`` console script."""


async def _smoke() -> None:
    """Headless self-test: prove the PyInstaller bundle is intact, then exit. Used by CI to
    catch bundling breaks the unit-test import-smoke can't.

    Three checks:
      1. The bundled libusb shared lib is where ``libusb_package.get_library_path()`` looks
         (``libusb_package/libusb-1.0.*``) and actually loads. A onefile build can misplace it,
         which breaks USB enumeration with "No backend available". We deliberately do NOT
         ``libusb_init``/enumerate here: CI runners have no USB subsystem (no ``/dev/bus/usb``),
         so init legitimately fails there. That's a runtime-env concern, not a packaging break.
      2. ``App.run_test()`` mounts every screen headless (no TTY), pulling the widget .tcss and
         logo assets that a broken ``collect_all`` would silently drop.
      3. ``supported_ids()`` is non-empty: the pkgutil chip-discovery walk only enumerates
         drivers PyInstaller actually collected, so an empty map means the bundle shipped with
         no drivers and the app would launch but show zero interfaces.
    """
    import ctypes
    import os

    from libusb_package import get_library_path

    lib = get_library_path()
    if not (lib and os.path.isfile(str(lib))):
        raise RuntimeError(f"bundled libusb not found via libusb_package: {lib!r}")
    ctypes.CDLL(str(lib))  # must load from the bundle (deps resolved), not just exist on disk

    from wifit4.ui.app import WifiteApp

    app = WifiteApp(cli_log_level="unset")
    async with app.run_test() as pilot:
        await pilot.pause()

    # Chip discovery actually finds drivers. supported_ids() walks wifit4.chips via pkgutil; if
    # PyInstaller didn't collect the dynamically-imported chip packages the map is empty and the
    # app launches fine but shows zero interfaces. That is the break this check exists to catch.
    from wifit4.device.manager import supported_ids

    if not supported_ids():
        raise RuntimeError("chip discovery found no driver packages (PyInstaller bundling break)")


def main() -> None:
    """Parse CLI args, then run the headless smoke test or launch the TUI."""
    import argparse

    from wifit4 import __version__

    parser = argparse.ArgumentParser(prog="wifit4", description="USB Wireless Auditor")
    parser.add_argument("--version", action="version", version=f"wifit4 {__version__}")
    parser.add_argument("--smoke", action="store_true", help="TEST ONLY: Run headless, render, exit 0")
    parser.add_argument("--quiet", action="store_true", help="Do not emit any logs")
    parser.add_argument("--debug", action="store_true", help="Emit verbose debug logs")
    parser.add_argument("--trace", action="store_true", help="Emit very verbose trace logs")

    # ── New wifit4 upgrade flags ────────────────────────────────────────────
    subparsers = parser.add_subparsers(dest="command")

    # mesh daemon mode
    mesh_p = subparsers.add_parser("daemon", help="Headless mesh node REST daemon")
    mesh_p.add_argument("--host", default="0.0.0.0")
    mesh_p.add_argument("--port", type=int, default=8765)

    # enterprise attack
    ent_p = subparsers.add_parser("enterprise", help="Rogue RADIUS 802.1X capture")
    ent_p.add_argument("--ssid",      required=True, help="Target corporate SSID to clone")
    ent_p.add_argument("--iface",     required=True, help="Wireless interface for fake AP")
    ent_p.add_argument("--channel",   type=int, default=6)
    ent_p.add_argument("--out",       default="enterprise_captures.txt", help="Output file")

    # cloud crack
    crack_p = subparsers.add_parser("crack", help="Submit .hc22000 to cloud webhook")
    crack_p.add_argument("--file",    required=True, help=".hc22000 capture file path")
    crack_p.add_argument("--webhook", required=True, help="Webhook base URL")
    crack_p.add_argument("--ssid",    default="unknown")
    crack_p.add_argument("--bssid",   default="00:00:00:00:00:00")

    args = parser.parse_args()

    # ── Dispatch subcommands ────────────────────────────────────────────────
    if getattr(args, "command", None) == "daemon":
        from wifit4.mesh.daemon import MeshDaemon
        node = MeshDaemon()
        node.serve(host=args.host, port=args.port)
        return

    if getattr(args, "command", None) == "enterprise":
        import asyncio
        from wifit4.attacks.enterprise import RogueRadiusServer
        from pathlib import Path
        out_path = Path(args.out)
        def _save(crackable):
            line = crackable.to_hashcat_5500()
            print(f"[+] CAPTURED: {line}")
            with open(out_path, "a") as f:
                f.write(line + "\n")
        server = RogueRadiusServer(on_capture=_save)
        conf_path = server.write_hostapd_config(args.ssid, args.iface, args.channel)
        print(f"[*] Rogue RADIUS on 127.0.0.1:1812")
        print(f"[*] hostapd config written to: {conf_path}")
        print(f"[*] Run: sudo hostapd {conf_path}")
        asyncio.run(server.start())
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            server.stop()
        return

    if getattr(args, "command", None) == "crack":
        import asyncio
        from pathlib import Path
        from wifit4.crack.cloud_crack import CloudCrackUploader, CrackJob
        job = CrackJob(ssid=args.ssid, bssid=args.bssid, hc22000_path=Path(args.file))
        def _on_result(r):
            print(f"[+] CRACKED: {r.job.ssid} → {r.psk}")
        uploader = CloudCrackUploader(webhook_url=args.webhook, on_result=_on_result)
        async def _run():
            await uploader.submit(job)
            await asyncio.sleep(3600)  # wait up to 1h
        asyncio.run(_run())
        return

    if args.smoke:
        import asyncio

        # 60s ceiling so a hung mount fails CI instead of stalling the runner.
        asyncio.run(asyncio.wait_for(_smoke(), timeout=60))
        return

    # Lazy import for WEP cracker ProcessPoolExecutor case
    from wifit4.ui.app import WifiteApp

    cli_log_level = None
    if args.debug:
        cli_log_level = "debug"
    if args.trace:
        cli_log_level = "trace"
    if args.quiet:
        cli_log_level = "quiet"

    WifiteApp(cli_log_level=cli_log_level).run()


if __name__ == "__main__":
    # Frozen (PyInstaller) builds use the `spawn` start method, so each
    # ProcessPoolExecutor worker (the WEP cracker) re-execs this exe. freeze_support()
    # makes that re-exec run the worker bootstrap and exit, instead of launching a
    # second TUI. It is a no-op for normal `python -m wifit4` / console-script runs.
    import multiprocessing

    multiprocessing.freeze_support()
    main()
