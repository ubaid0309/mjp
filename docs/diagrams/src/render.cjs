// Renders every SVG in docs/diagrams to a 3x PNG: node docs/diagrams/src/render.cjs [names...]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
(async () => {
  const dir = path.resolve(__dirname, '..');
  const only = process.argv.slice(2);
  const browser = await chromium.launch();
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.svg'))) {
    if (only.length && !only.some((o) => f.startsWith(o))) continue;
    const svg = fs.readFileSync(path.join(dir, f), 'utf8');
    const m = /viewBox="0 0 ([\d.]+) ([\d.]+)"/.exec(svg);
    const [w, h] = m ? [Math.ceil(+m[1]), Math.ceil(+m[2])] : [1600, 1000];
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 3 });
    await page.setContent(`<html><body style="margin:0;background:#fff">${svg}</body></html>`);
    await page.locator('svg').first().screenshot({ path: path.join(dir, f.replace('.svg', '.png')) });
    await page.close();
    console.log('rendered', f);
  }
  await browser.close();
})();
