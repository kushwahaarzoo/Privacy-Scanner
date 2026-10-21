
FINGERPRINT_INIT_SCRIPT = r"""
(() => {
    if (window.__privacyScannerInstalled) return;

    Object.defineProperty(window, "__privacyScannerInstalled", {
        value: true,
        configurable: false
    });

    const events = [];

    Object.defineProperty(window, "__privacyScannerSignals", {
        value: events,
        configurable: false
    });

    function record(api, detail = "") {
        try {
            events.push({
                api: api,
                detail: String(detail).slice(0, 120),
                time: Date.now()
            });

            // Prevent an unbounded instrumentation buffer.
            if (events.length > 500) {
                events.shift();
            }
        } catch (_) {}
    }

    function wrapMethod(prototype, methodName, apiName) {
        if (!prototype) return;

        const original = prototype[methodName];

        if (typeof original !== "function") return;

        try {
            prototype[methodName] = function (...args) {
                record(apiName, methodName);

                return Reflect.apply(original, this, args);
            };
        } catch (_) {}
    }

    // Canvas readout/export APIs.
    if (window.CanvasRenderingContext2D) {
        wrapMethod(
            CanvasRenderingContext2D.prototype,
            "getImageData",
            "canvas"
        );
    }

    if (window.HTMLCanvasElement) {
        wrapMethod(
            HTMLCanvasElement.prototype,
            "toDataURL",
            "canvas"
        );

        wrapMethod(
            HTMLCanvasElement.prototype,
            "toBlob",
            "canvas"
        );
    }

    // WebGL methods commonly used in rendering probes.
    for (const type of [
        window.WebGLRenderingContext,
        window.WebGL2RenderingContext
    ]) {
        if (!type) continue;

        wrapMethod(type.prototype, "getParameter", "webgl");
        wrapMethod(type.prototype, "readPixels", "webgl");
        wrapMethod(type.prototype, "getExtension", "webgl");
        wrapMethod(type.prototype, "getSupportedExtensions", "webgl");
    }

    // Audio processing API signals.
    for (const type of [
        window.AudioContext,
        window.webkitAudioContext
    ]) {
        if (!type) continue;

        wrapMethod(type.prototype, "createAnalyser", "audio");
        wrapMethod(type.prototype, "createOscillator", "audio");
        wrapMethod(type.prototype, "createDynamicsCompressor", "audio");
        wrapMethod(type.prototype, "createBuffer", "audio");
    }

    if (window.AnalyserNode) {
        wrapMethod(AnalyserNode.prototype, "getFloatFrequencyData", "audio");
        wrapMethod(AnalyserNode.prototype, "getByteFrequencyData", "audio");
        wrapMethod(AnalyserNode.prototype, "getFloatTimeDomainData", "audio");
        wrapMethod(AnalyserNode.prototype, "getByteTimeDomainData", "audio");
    }

    // Font enumeration/checking signal.
    if (document.fonts && document.fonts.check) {
        wrapMethod(
            Object.getPrototypeOf(document.fonts),
            "check",
            "font_check"
        );
    }

    // Record access to selected browser-identifying properties.
    // These getters return the original values unchanged.
    function observeGetter(prototype, propertyName, apiName) {
        if (!prototype) return;

        let owner = prototype;

        while (owner) {
            const descriptor = Object.getOwnPropertyDescriptor(
                owner,
                propertyName
            );

            if (descriptor) {
                if (!descriptor.get || !descriptor.configurable) return;

                try {
                    Object.defineProperty(owner, propertyName, {
                        ...descriptor,
                        get: function () {
                            record(apiName, propertyName);
                            return Reflect.apply(descriptor.get, this, []);
                        }
                    });
                } catch (_) {}

                return;
            }

            owner = Object.getPrototypeOf(owner);
        }
    }

    for (const property of [
        "hardwareConcurrency",
        "deviceMemory",
        "platform",
        "maxTouchPoints"
    ]) {
        observeGetter(
            Navigator.prototype,
            property,
            "navigator_property"
        );
    }

    for (const property of [
        "width",
        "height",
        "colorDepth",
        "pixelDepth"
    ]) {
        observeGetter(
            Screen.prototype,
            property,
            "screen_property"
        );
    }
})();
"""


def collect_fingerprinting_signals(page) -> dict:
    """
    Read instrumentation events from accessible page frames.

    Cross-origin frames are normally accessible to Playwright's
    frame evaluation, but detached or navigated frames may fail.
    """
    events = []
    frames_checked = 0
    frames_failed = 0

    for frame in page.frames:
        try:
            frame_events = frame.evaluate(
                "() => window.__privacyScannerSignals || []"
            )

            frames_checked += 1

            for event in frame_events:
                events.append({
                    "api": event.get("api", "unknown"),
                    "detail": event.get("detail", ""),
                    "frame_url": frame.url,
                })

        except Exception:
            frames_failed += 1

    counts = {}

    for event in events:
        api = event["api"]
        counts[api] = counts.get(api, 0) + 1

    findings = []

    descriptions = {
        "canvas": (
            "Canvas readout or export API calls were observed. "
            "These can be used for fingerprinting but also for "
            "legitimate graphics functionality."
        ),
        "webgl": (
            "WebGL information or pixel-reading API calls were "
            "observed. These may contribute to graphics fingerprinting."
        ),
        "audio": (
            "Audio processing API calls were observed. Some "
            "fingerprinting techniques use audio processing."
        ),
        "font_check": (
            "Font availability checks were observed. Such checks "
            "can contribute to device identification."
        ),
        "navigator_property": (
            "Selected navigator properties were read. These can "
            "reveal browser or device characteristics."
        ),
        "screen_property": (
            "Selected screen properties were read. These may "
            "contribute to browser fingerprinting."
        ),
    }

    for api, count in sorted(counts.items()):
        findings.append({
            "code": f"API_SIGNAL_{api.upper()}",
            "category": api,
            "observed_calls": count,
            "severity": "review",
            "message": descriptions.get(
                api,
                "A monitored browser API was used."
            ),
            "evidence": [
                event for event in events
                if event["api"] == api
            ][:20],
        })

    return {
        "instrumentation": "selected_api_wrappers_v1",
        "events_observed": len(events),
        "api_call_counts": counts,
        "findings": findings,
        "frames_checked": frames_checked,
        "frames_failed": frames_failed,
        "limitations": [
            "Only selected APIs are instrumented.",
            "Sites can detect or bypass instrumentation.",
            "Calls may have legitimate uses unrelated to tracking.",
            "Native APIs, workers, and uninstrumented frames may be missed.",
            "This detector does not establish that a stable identifier was generated.",
        ],
    }
