// XSS-test av programvinduet (src/AISkanner/ui/index.html): hvert tekstfelt programmet sender til vinduet får
// HTML/skript som innhold. Testen feiler hvis noe av det kjøres eller blir HTML, eller hvis teksten ikke vises.
// Kjøres i CI (jobben «sikkerhet»): node tests/xss/xss.js src/AISkanner/ui/index.html
const { chromium } = require('playwright');
const P = (k) => `<img src=x onerror="window.__x=(window.__x||[]).concat('${k}')"><b class=XSS>${k}</b>"'>`;
(async () => {
  const b = await chromium.launch(); const pg = await b.newPage();
  const errs = []; pg.on('pageerror', e => errs.push(e.message));
  await pg.addInitScript(() => {
    const ls = []; window.__sendt = [];
    window.chrome = { webview: { addEventListener: (t, f) => ls.push(f), postMessage: m => window.__sendt.push(m) } };
    window.__motta = d => ls.forEach(f => f({ data: d }));
  });
  await pg.goto('file://' + require('path').resolve(process.argv[2]));
  const funn = [0, 1, 2, 3].map(i => ({ id: i, risiko: ['rod', 'gul', 'gronn', 'ukjent'][i], gruppe: ['lokal', 'nettleser', 'skjult', 'lokal'][i],
    forst: P('forst'), sist: P('sist'), naa: true, navn: P('navn'), kortnavn: P('kortnavn'), versjon: P('versjon'), oppslag: [P('oppslag')],
    versjonKilde: P('versjonKilde'), status: P('status'), tilstander: [P('tilstand')], treffsikkerhet: P('treff'), spor: [P('spor')], godkjenning: P('godkj'),
    punkt: P('punkt'), lokasjon: P('lokasjon'), type: P('type'), grunn: P('grunn'), rammeverk: { kort: P('rkort'), alle: [{ kode: P('rkode'), navn: P('rnavn'), kilde: P('rkilde'), url: 'javascript:alert(1)' }] },
    kommerFra: P('kommerFra'), selskap: P('selskap'), kommerFraFarlig: true, senderTil: [{ land: P('land'), kode: P('kode'), farlig: true, sett: true }],
    ingenLand: P('ingenLand'), lokalt: false, kort: P('kort'), folgbar: true, merk: [P('merk')], steder: [P('sted'), 'C:\\x\\' + P('sti')],
    trafikk: [{ adresse: P('adresse'), tjeneste: P('tjeneste'), landKode: P('lk'), cdn: P('cdn'), ip: [{ ip: P('ip'), kode: P('ik'), cdn: P('icdn'), eier: P('eier'), land: P('iland'), farlig: true }],
      tilLand: P('tilLand'), land: P('tland'), farlig: true, antall: 3, kilde: [P('kilde')], proto: [P('proto')], prosesser: [{ pid: 4, fil: P('fil') }], data: P('data') }] }));
  const info = { sekunder: 3, dataMalt: true, maleSekunder: 5, sendtTekst: P('sendt'), nvd: P('nvd'), enhet: P('enhet'),
    sjekker: [{ navn: P('sjnavn'), tekst: P('sjtekst'), niva: 'feil', linjer: [P('sjlinje')] }], kjort: P('kjort'), admin: true, fullt: true, bruker: P('bruker'),
    kjortAv: P('kjortAv'), brukerFeil: P('brukerFeil'), revisjon: P('revisjon'), revisjonFeil: false, lytter: false, lytteSekunder: 20,
    telling: { totalt: 4, modeller: 1, nettsteder: 1, utvidelser: 1, apper: 1, innebygd: 0, spor: 0 } };
  await pg.evaluate(([f, i]) => window.__motta({ type: 'resultat', funn: f, info: i }), [funn, info]);
  await pg.waitForTimeout(500);
  for (let i = 0; i < 4; i++) {
    await pg.evaluate(i => { try { apneArk(alle[i]); } catch (e) { window.__e = (window.__e || []).concat(String(e)); } }, i);
    await pg.waitForTimeout(150);
    for (const t of await pg.$$('#detalj [data-fane]')) { try { await t.click({ timeout: 500 }); await pg.waitForTimeout(100); } catch (e) {} }
  }
  await pg.evaluate(p => {
    const S = window.__motta;
    S({ type: 'fremdrift', mapper: 1, sekunder: 1, fullt: true, steg: [{ navn: p, s: 1, n: 1 }] });
    S({ type: 'feil', tekst: p });
  }, P('melding'));
  await pg.waitForTimeout(300);
  const x = await pg.evaluate(() => [window.__x || [], document.querySelectorAll('b.XSS').length, window.__e || [], (document.body.textContent.match(/kortnavn|sjtekst|grunn|tland|fil</g)||[]).length]);
  console.log('Skript kjørt:', JSON.stringify([...new Set(x[0])]), '| HTML laget:', x[1], '| feil:', JSON.stringify(x[2].concat(errs)), '| vist som tekst:', x[3]);
  await b.close();
  if (x[0].length || x[1] || x[2].length || errs.length || x[3] < 20) { console.log('XSS-TEST FEILET'); process.exit(1); }
  console.log('XSS-TEST OK');
})();
