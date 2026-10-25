// The server's vault is replaced outside Lockstep (data deleted, a new vault created with the same Google
// account), while device B still holds the older vault with a higher revision. B must not stay stuck:
// (1) when B still has accounts the server lacks, it asks; cancelling keeps them, accepting switches;
// (2) when B would lose nothing, it switches by itself (here during a rotation) and the rotation succeeds.
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = () => { const iat = Math.floor(Date.now() / 1000); return `${b64({ alg: "RS256" })}.${b64({ sub: "user-1", name: "T", email: "t@example.com", iat, exp: iat + 3600 })}.sig`; };
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P = "first-passphrase-1";
const names = (page) => page.$$eval("#entries .entry:not(.entry-skel) .issuer", n => n.map(x => x.textContent));
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 30000 });

async function device(browser) {
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  const page = await context.newPage();
  page.errors = []; page.on("pageerror", e => page.errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), jwt());
  return page;
}
async function setUp(page, issuer) {
  await page.waitForSelector("#lock-dialog[open]", { timeout: 15000 });
  await page.fill("#lock-passcode", P); await page.fill("#lock-confirm", P); await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  if (issuer) {
    await page.click("#open-add"); await page.click("#open-manual");
    await page.fill("#manual-issuer", issuer); await page.fill("#manual-account", "a@x.com"); await page.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
    await page.click("#manual-form button[type=submit]"); await waitCount(page, 1); await page.waitForTimeout(1500);
  }
}
async function unlock(page) {
  await page.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await page.fill("#unlock-passcode", P); await page.click("#unlock-form button[type=submit]");
}
async function rotate(page) {
  await page.evaluate(t => { state.token = t; document.getElementById("toast").textContent = ""; }, jwt());
  await page.click("#open-settings"); await page.click("#settings-key-rotate");
  await page.waitForSelector("#confirm-dialog[open]"); await page.fill("#confirm-passkey", P); await page.click("#confirm-accept");
  await page.waitForFunction(() => /rotated|changed|could not|refused|older vault|differ/i.test(document.getElementById("toast").textContent), null, { timeout: 30000 })
    .catch(async (e) => { console.log("stuck:", await page.evaluate(() => JSON.stringify({ toast: document.getElementById("toast").textContent, dialogs: [...document.querySelectorAll("dialog[open]")].map(d => d.id + ":" + d.textContent.replace(/\s+/g, " ").slice(0, 200)), locked: !document.getElementById("locked").classList.contains("hidden"), signedIn: !document.getElementById("signed-in").classList.contains("hidden") }))); throw e; });
  return (await page.textContent("#toast")).trim();
}
// Device A starts over after the server's data was deleted: it sees no account and sets up a new vault.
async function recreate(a, issuer) {
  await control("wipeVault=1");
  await a.reload(); await a.waitForTimeout(800);
  await a.evaluate(t => onGoogleCredential({ credential: t }), jwt()).catch(() => {}); await a.waitForTimeout(1500);
  await setUp(a, issuer);
}

(async () => {
  const browser = await chromium.launch();
  // Case 1: B keeps an account the replaced vault does not have.
  await control("reset=1");
  let a = await device(browser); await setUp(a, "Alpha");
  let b = await device(browser); await unlock(b); await waitCount(b, 1);
  log("B rotation before the wipe:", await rotate(b));          // B's revision moves to 2
  await recreate(a, "Bravo");
  let st = await control("");
  log("server vault replaced: revision", st.revision, "| accounts", JSON.stringify(st.entries));
  await b.click("#lock-now"); await unlock(b);
  await b.waitForSelector("#confirm-dialog[open]", { timeout: 20000 });
  const question = (await b.textContent("#confirm-message")).trim();
  log("B is asked:", question.slice(0, 140) + "…");
  check(/1 account/.test(question), "B was not told about the account only it has");
  await b.click("#confirm-cancel");
  await b.waitForTimeout(1500);
  log("B kept its older vault:", JSON.stringify(await names(b)), "|", (await b.textContent("#toast")).trim().slice(0, 60));
  check((await names(b)).includes("Alpha"), "cancelling did not keep the older vault's account");
  await b.click("#lock-now"); await unlock(b);
  await b.waitForSelector("#confirm-dialog[open]", { timeout: 20000 });
  await b.click("#confirm-accept");
  await waitCount(b, 1); await b.waitForTimeout(1500);
  log("B switched to the server's vault:", JSON.stringify(await names(b)));
  check(JSON.stringify(await names(b)) === JSON.stringify(["Bravo"]), "accepting did not switch B to the server's vault");
  const rotated = await rotate(b);
  log("B rotation afterwards:", rotated);
  check(/rotated to version 2/.test(rotated), `B could not rotate after switching: ${rotated}`);
  await a.context().close(); await b.context().close();

  // Case 2: B has nothing the replaced vault lacks; its rotation switches by itself and succeeds.
  await control("reset=1");
  a = await device(browser); await setUp(a, null);
  b = await device(browser); await unlock(b); await b.waitForSelector("#signed-in:not(.hidden)", { timeout: 20000 });
  log("B rotation before the wipe:", await rotate(b));
  await recreate(a, "Charlie");
  const result = await rotate(b);
  st = await control("");
  log("B rotation with the replaced vault:", result, "| server key version", st.keyVersion);
  check(/rotated to version 2/.test(result), `B's rotation was refused: ${result}`);
  await waitCount(b, 1);
  log("B shows:", JSON.stringify(await names(b)));
  check(JSON.stringify(await names(b)) === JSON.stringify(["Charlie"]), "B does not show the server's accounts");
  const errors = [...a.errors, ...b.errors];
  check(errors.length === 0, `page errors: ${errors}`);
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
