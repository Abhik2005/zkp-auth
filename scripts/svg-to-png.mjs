/**
 * Convert cover.svg → cover.png using puppeteer (headless Chrome).
 * Run: node scripts/svg-to-png.mjs
 */
import puppeteer from "puppeteer";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dir = dirname(fileURLToPath(import.meta.url));
const svgPath = resolve(__dir, "../cover.svg");
const pngPath = resolve(__dir, "../cover.png");

const browser = await puppeteer.launch({ headless: "new" });
const page = await browser.newPage();

await page.setViewport({ width: 1000, height: 420, deviceScaleFactor: 2 });
await page.goto(pathToFileURL(svgPath).href, { waitUntil: "networkidle0" });

await page.screenshot({
  path: pngPath,
  clip: { x: 0, y: 0, width: 1000, height: 420 },
  omitBackground: false,
});

await browser.close();
console.log(`✓ Saved: ${pngPath}`);
