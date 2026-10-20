if (!globalThis.__authsyncScannerInstalled) {
    globalThis.__authsyncScannerInstalled = true;
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === "AUTHSYNC_SELECT_QR") selectAndScan(message.screenshot);
        if (message.type === "AUTHSYNC_CANCEL_QR") globalThis.__authsyncCancelScanner?.();
    });
}

async function selectAndScan(screenshot) {
    globalThis.__authsyncCancelScanner?.();
    const overlay = document.createElement("div");
    overlay.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;display:block;cursor:crosshair;background:#07111f2e;touch-action:none;user-select:none;";
    const shadow = overlay.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
        * { box-sizing: border-box; }
        .hint {
            position: fixed; top: 20px; left: 50%; transform: translateX(-50%);
            padding: 10px 16px; border: 1px solid #ffffff24; border-radius: 999px;
            background: #101828e8; color: white; font: 600 14px/1.25 system-ui, sans-serif;
            box-shadow: 0 8px 30px #0008; opacity: 0; transition: opacity .16s ease;
        }
        .hint.visible { opacity: 1; }
        .tutorial {
            position: fixed; top: 50%; left: 50%; width: min(360px, calc(100vw - 32px));
            transform: translate(-50%, -50%); padding: 18px; border: 1px solid #ffffff70;
            border-radius: 20px; background: linear-gradient(145deg, #17243a52, #0c14245c);
            color: white; box-shadow: 0 18px 50px #0005; font-family: system-ui, sans-serif;
            text-align: center; pointer-events: none; transition: opacity .16s ease, transform .16s ease;
        }
        .tutorial.hide { opacity: 0; transform: translate(-50%, -47%) scale(.97); }
        .preview {
            position: relative; height: 170px; overflow: hidden; border-radius: 14px;
            border: 1px solid #ffffff75;
            background: linear-gradient(#edf2f866 0 0) 20px 24px / 155px 8px no-repeat,
                        linear-gradient(#dfe7f15c 0 0) 20px 43px / 105px 6px no-repeat,
                        linear-gradient(#dfe7f15c 0 0) 20px 58px / 130px 6px no-repeat,
                        linear-gradient(135deg, #f8fafc45, #dce6f23d);
        }
        .qr {
            position: absolute; right: 34px; top: 32px; width: 104px; height: 104px;
            padding: 8px; border: 1px solid #ffffff9c; border-radius: 6px;
            background: #ffffff52; box-shadow: 0 5px 18px #23354d25;
        }
        .qr svg { width: 100%; height: 100%; display: block; opacity: .68; }
        .demo-selection {
            position: absolute; border: 3px dashed #477cff; border-radius: 8px;
            background: #477cff18; box-shadow: 0 0 0 2px #fff9, 0 8px 24px #315ba733;
            animation: authsync-demo-selection 2.5s cubic-bezier(.45,0,.2,1) infinite;
        }
        .cursor {
            position: absolute; width: 25px; height: 31px; filter: drop-shadow(0 3px 3px #0005);
            animation: authsync-demo-cursor 2.5s cubic-bezier(.45,0,.2,1) infinite;
        }
        .title { margin: 16px 0 4px; font-size: 17px; font-weight: 700; letter-spacing: -.01em; text-shadow: 0 2px 5px #000c; }
        .subtitle { margin: 0; color: #eef4ff; font-size: 13px; text-shadow: 0 2px 5px #000c; }
        kbd { padding: 2px 6px; border: 1px solid #ffffff3d; border-radius: 5px; background: #ffffff12; font: inherit; }
        .selection {
            position: fixed; display: none; border: 2px solid #78a0ff; border-radius: 4px;
            background: #7c9cff22; box-shadow: 0 0 0 9999px #07111fa8, 0 0 0 1px #fff8 inset;
        }
        @keyframes authsync-demo-selection {
            0%, 16% { left: 186px; top: 30px; width: 5px; height: 5px; opacity: 0; }
            24% { opacity: 1; }
            70%, 88% { left: 179px; top: 24px; width: 120px; height: 120px; opacity: 1; }
            100% { left: 179px; top: 24px; width: 120px; height: 120px; opacity: 0; }
        }
        @keyframes authsync-demo-cursor {
            0%, 16% { left: 179px; top: 22px; opacity: 0; }
            24% { left: 179px; top: 22px; opacity: 1; }
            70%, 88% { left: 291px; top: 136px; opacity: 1; }
            100% { left: 291px; top: 136px; opacity: 0; }
        }
        @media (prefers-reduced-motion: reduce) {
            .demo-selection { left: 179px; top: 24px; width: 120px; height: 120px; animation: none; }
            .cursor { left: 291px; top: 136px; animation: none; }
        }
    `;
    const hint = document.createElement("div");
    hint.className = "hint";
    hint.textContent = "Release to scan · Esc to cancel";
    const tutorial = document.createElement("div");
    tutorial.className = "tutorial";
    tutorial.innerHTML = `
        <div class="preview" aria-hidden="true">
            <div class="qr">
                <svg viewBox="0 0 21 21" shape-rendering="crispEdges">
                    <path fill="#152238" d="M1 1h7v7H1zm2 2v3h3V3zM13 1h7v7h-7zm2 2v3h3V3zM1 13h7v7H1zm2 2v3h3v-3zM10 2h2v2h-2zM9 5h3v2H9zM10 9h2v3h-2zM13 9h2v2h-2zM16 9h4v2h-4zM9 13h3v2H9zM13 12h2v4h-2zM16 13h2v2h-2zM19 12h1v4h-1zM9 17h2v3H9zM12 18h3v2h-3zM16 17h4v3h-2v-1h-2z"/>
                </svg>
            </div>
            <div class="demo-selection"></div>
            <svg class="cursor" viewBox="0 0 26 34" aria-hidden="true">
                <path d="M2 2v25l7-6 5 11 5-2-5-11h9z" fill="#fff" stroke="#142033" stroke-width="2" stroke-linejoin="round"/>
            </svg>
        </div>
        <p class="title">Drag to select the QR code</p>
        <p class="subtitle">Draw a box around the complete code · <kbd>Esc</kbd> cancels</p>`;
    const selection = document.createElement("div");
    selection.className = "selection";
    shadow.append(style, hint, tutorial, selection);
    document.documentElement.append(overlay);
    globalThis.__authsyncScannerOverlay = overlay;
    let start;

    const cancel = () => {
        overlay.remove();
        if (globalThis.__authsyncScannerOverlay === overlay) globalThis.__authsyncScannerOverlay = null;
        if (globalThis.__authsyncCancelScanner === cancel) globalThis.__authsyncCancelScanner = null;
        window.removeEventListener("keydown", onKey);
    };
    globalThis.__authsyncCancelScanner = cancel;
    const onKey = (event) => { if (event.key === "Escape") cancel(); };
    window.addEventListener("keydown", onKey);
    overlay.addEventListener("pointerdown", (event) => {
        tutorial.classList.add("hide");
        hint.classList.add("visible");
        start = { x: event.clientX, y: event.clientY };
        selection.style.display = "block";
        selection.style.left = `${start.x}px`; selection.style.top = `${start.y}px`;
        selection.style.width = "0"; selection.style.height = "0";
        overlay.setPointerCapture(event.pointerId);
    });
    overlay.addEventListener("pointermove", (event) => {
        if (!start) return;
        const rect = normalizedRect(start.x, start.y, event.clientX, event.clientY);
        Object.assign(selection.style, { left: `${rect.x}px`, top: `${rect.y}px`, width: `${rect.width}px`, height: `${rect.height}px` });
    });
    overlay.addEventListener("pointercancel", cancel);
    overlay.addEventListener("pointerup", async (event) => {
        if (!start) return;
        const rect = normalizedRect(start.x, start.y, event.clientX, event.clientY);
        cancel();
        if (rect.width < 20 || rect.height < 20) return;
        try {
            const image = await loadImage(screenshot);
            const scaleX = image.naturalWidth / innerWidth;
            const scaleY = image.naturalHeight / innerHeight;
            const canvas = new OffscreenCanvas(Math.round(rect.width * scaleX), Math.round(rect.height * scaleY));
            canvas.getContext("2d").drawImage(image, rect.x * scaleX, rect.y * scaleY, rect.width * scaleX, rect.height * scaleY, 0, 0, canvas.width, canvas.height);
            const otpAuthUri = await detectTotpQr(canvas);
            if (!otpAuthUri) throw new Error("No TOTP QR code was found in that selection.");
            const result = await chrome.runtime.sendMessage({ type: "ADD_OTP_URI", otpAuthUri });
            if (!result || typeof result.ok !== "boolean") {
                throw new Error("The extension background service is unavailable. Reload Lockstep from chrome://extensions and try again.");
            }
            if (!result.ok) throw new Error(result.error);
            alert("Authenticator added to Lockstep.");
        } catch (error) { alert(`Lockstep: ${error.message}`); }
    });
}

async function detectTotpQr(canvas) {
    if (typeof globalThis.jsQR !== "function") {
        throw new Error("The bundled QR decoder could not be loaded.");
    }
    const context = canvas.getContext("2d", { willReadFrequently: true });
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const decoded = globalThis.jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    return decoded?.data?.startsWith("otpauth://totp/") ? decoded.data : null;
}

function normalizedRect(x1, y1, x2, y2) {
    return { x: Math.min(x1, x2), y: Math.min(y1, y2), width: Math.abs(x2 - x1), height: Math.abs(y2 - y1) };
}

function loadImage(source) {
    return new Promise((resolve, reject) => {
        const image = new Image();
        image.onload = () => resolve(image);
        image.onerror = () => reject(new Error("Could not read the captured tab."));
        image.src = source;
    });
}

