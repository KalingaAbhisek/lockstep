/* Authenticated SSE invalidation channel. Payloads contain no vault data or credentials.
   With shareKey, the tabs of one browser share a single connection: the tab holding the Web Lock named shareKey
   listens and forwards "change"/"session" to the other tabs over a BroadcastChannel of the same name; when it
   closes, the next tab takes the lock and connects (the server's first event then covers the gap). This keeps
   the API's per-account connection limit free for the other client. */
(() => {
    function watch({connect, onChange, onSession, shareKey}) {
        const controller = new AbortController(), signal = controller.signal;
        const channel = shareKey && globalThis.BroadcastChannel && globalThis.navigator?.locks ? new BroadcastChannel(shareKey) : null;
        const publish = kind => { try { channel?.postMessage(kind); } catch { /* the channel was closed */ } };
        const sessionEnded = () => { controller.abort(); void Promise.resolve().then(onSession).catch(()=>{}); };
        let dirty = false, updating = false;
        const pause = millis => new Promise(resolve => {
            if (signal.aborted) return resolve();
            const finish = () => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
            const timer = setTimeout(finish, millis); signal.addEventListener("abort", finish, {once:true});
        });
        async function invalidate() {
            dirty = true;
            if (updating) return;
            updating = true;
            try {
                while (dirty && !signal.aborted) {
                    dirty = false;
                    try { await onChange(); }
                    catch (error) {
                        if (["SESSION_CHANGED", "VIEW_CHANGED", "VAULT_LOCKED"].includes(error?.code)) continue;
                        dirty = true; await pause(Math.max(500, error?.retryAfterMillis || 0));
                    }
                }
            } finally { updating = false; }
        }
        if (channel) {
            channel.onmessage = ({data}) => {
                if (signal.aborted) return;
                if (data === "session") { if (onSession) sessionEnded(); else void invalidate(); }
                else if (data === "change") void invalidate();
            };
            signal.addEventListener("abort", () => channel.close(), {once:true});
        }
        const listen = async () => {
            let failures = 0;
            while (!signal.aborted) {
                let reader, retryAfter = 0;
                const started = Date.now();
                try {
                    const response = await connect(signal);
                    const retry = response.headers.get("Retry-After");
                    if (retry) {
                        const delay = Number.isFinite(Number(retry)) ? Number(retry)*1000 : Date.parse(retry)-Date.now();
                        retryAfter = Number.isFinite(delay) ? Math.max(0,delay) : 0;
                    }
                    if (!response.ok) {
                        if (response.status === 401 || response.status === 403) { publish("change"); void invalidate(); }
                        if (response.status === 404 || response.status === 405) retryAfter = 300000;
                        await response.body?.cancel();
                        throw new Error("Live connection unavailable");
                    }
                    if (!response.headers.get("Content-Type")?.startsWith("text/event-stream") || !response.body) {
                        await response.body?.cancel(); throw new Error("Invalid live response");
                    }
                    reader = response.body.getReader();
                    const decoder = new TextDecoder(); let buffer = "";
                    while (!signal.aborted) {
                        const {done, value} = await reader.read();
                        if (done) break;
                        buffer = (buffer + decoder.decode(value, {stream:true})).replace(/\r\n/g, "\n");
                        if (buffer.length > 16384) throw new Error("Live message too large");
                        let end;
                        while ((end=buffer.indexOf("\n\n")) !== -1) {
                            const event = buffer.slice(0,end); buffer=buffer.slice(end+2);
                            if (/^event:\s*session\s*$/m.test(event)) {
                                publish("session");
                                if (onSession) sessionEnded(); else void invalidate();
                            } else if (/^event:\s*change\s*$/m.test(event)) { publish("change"); void invalidate(); }
                        }
                    }
                } catch (error) { retryAfter = Math.max(retryAfter, error?.retryAfterMillis || 0); }
                finally { if (reader) { await reader.cancel().catch(()=>{}); reader.releaseLock(); } }
                if (signal.aborted) break;
                failures = Date.now()-started > 30000 ? 0 : Math.min(failures+1, 6);
                await pause(Math.max(retryAfter, Math.min(30000, 500*2**failures))*(1+Math.random()*.2));
            }
        };
        // Without shareKey (or Web Locks), this page connects itself. Otherwise it waits for its turn; the request
        // is withdrawn when the watch stops, and a lock it holds is released once listen() returns.
        const finished = channel
            ? navigator.locks.request(shareKey, {signal}, () => signal.aborted ? undefined : listen()).catch(() => {})
            : listen();
        return {stop:()=>controller.abort(), finished};
    }
    globalThis.LockstepLiveChanges = Object.freeze({watch});
})();
