// Prueft die Zeichenlogik von internal/web/static/app.js gegen eine DOM-Attrappe:
// Achsenrichtung, dynamische Y-Achse, Zeitachse, leere Messreihen.
//
// Nicht Teil der Go-Suite und nicht im Image-Build - dafuer waere ein Node-Toolchain im
// Dockerfile noetig, fuer rund hundert Zeilen View-Code. Stattdessen: `make check-chart`,
// das hier in einem node-Container laeuft. Wer an der Grafik etwas aendert, sollte es
// ausfuehren und danach einmal in den Browser schauen.
const fs = require('fs');
const src = fs.readFileSync(require('path').join(__dirname, '..', 'internal/web/static/app.js'), 'utf8');

const nodes = {};
function fakeEl(id) {
  return {
    id, textContent: '', className: '', attrs: {}, style: {}, children: [], colSpan: 0,
    disabled: false, value: '',
    setAttribute(k, v) { this.attrs[k] = v; },
    appendChild(c) { this.children.push(c); },
    replaceChildren(...c) { this.children = c; },
    querySelector() { return fakeEl('q'); },
  };
}
global.document = {
  getElementById: (id) => (nodes[id] = nodes[id] || fakeEl(id)),
  createElement: (tag) => fakeEl(tag),
  querySelector: (sel) => (nodes[sel] = nodes[sel] || fakeEl(sel)),
  addEventListener() {}, hidden: false,
};
global.setInterval = () => 0;
global.fetch = () => new Promise(() => {});

const exposed = src.replace(/\n\}\)\(\);\s*$/,
  '\n  module.exports = { area, mbits, minutes, niceMaxMbit, tickLabel, renderChart, renderClients, apply };\n})();\n');
eval(exposed);
const { area, mbits, minutes, niceMaxMbit, tickLabel, renderChart, renderClients, apply } = module.exports;

let fails = 0;
const check = (name, cond, extra) => cond
  ? console.log('  ok   ' + name)
  : (console.log('  FAIL ' + name + (extra !== undefined ? ' -> ' + extra : '')), fails++);

const MBIT = 125000; // Byte/s je Mbit/s
const series = (n, up, down, t0) => Array.from({length: n}, (_, i) => ({
  t: new Date((t0 || Date.now()) - (n - 1 - i) * 5000).toISOString(),
  up: typeof up === 'function' ? up(i) : up,
  down: typeof down === 'function' ? down(i) : down,
  flows: 4,
}));
const yTicks = () => nodes['chart-y'].children.map(c => c.textContent);
const yTops = () => nodes['chart-y'].children.map(c => c.style.top);
const xTicks = () => nodes['chart-x'].children.map(c => c.textContent);

console.log('== Y-Achse: runde Obergrenzen');
check('nichts -> 0,25 Mbit/s Boden', niceMaxMbit(0) === 0.25, niceMaxMbit(0));
check('winzig -> Boden', niceMaxMbit(0.05 * MBIT) === 0.25, niceMaxMbit(0.05 * MBIT));
check('1,1 -> 2', niceMaxMbit(1.1 * MBIT) === 2, niceMaxMbit(1.1 * MBIT));
check('38 -> 40', niceMaxMbit(38 * MBIT) === 40, niceMaxMbit(38 * MBIT));
check('45 -> 50', niceMaxMbit(45 * MBIT) === 50, niceMaxMbit(45 * MBIT));
check('exakt 50 bleibt 50', niceMaxMbit(50 * MBIT) === 50, niceMaxMbit(50 * MBIT));
check('120 -> 200', niceMaxMbit(120 * MBIT) === 200, niceMaxMbit(120 * MBIT));
check('950 -> 1000', niceMaxMbit(950 * MBIT) === 1000, niceMaxMbit(950 * MBIT));

console.log('== Tick-Beschriftung');
check('12.5 statt 13', tickLabel(12.5) === '12.5', tickLabel(12.5));
check('ganze Zahl ohne Nullen', tickLabel(100) === '100', tickLabel(100));
check('0.25', tickLabel(0.25) === '0.25', tickLabel(0.25));
check('0', tickLabel(0) === '0', tickLabel(0));

console.log('== Y-Achse rendern (Spitze 40 Mbit/s runter)');
renderChart({intervalSeconds: 5, accounted: true, peakUp: 2 * MBIT, peakDown: 40 * MBIT,
             samples: series(60, 1.5 * MBIT, i => (30 + i / 6) * MBIT)});
check('fuenf Ticks', yTicks().length === 5, JSON.stringify(yTicks()));
check('oben die Obergrenze', yTicks()[0] === '40', yTicks()[0]);
check('unten Null', yTicks()[4] === '0', yTicks()[4]);
check('Viertel dazwischen', JSON.stringify(yTicks()) === JSON.stringify(['40','30','20','10','0']), JSON.stringify(yTicks()));
check('Positionen 0..100 %', JSON.stringify(yTops()) === JSON.stringify(['0%','25%','50%','75%','100%']), JSON.stringify(yTops()));

console.log('== Y-Achse ist dynamisch');
renderChart({intervalSeconds: 5, peakUp: 0.4 * MBIT, peakDown: 0.9 * MBIT, samples: series(20, 0.3 * MBIT, 0.8 * MBIT)});
check('kleine Last -> Achse bis 1', yTicks()[0] === '1', yTicks()[0]);
renderChart({intervalSeconds: 5, peakUp: 8 * MBIT, peakDown: 380 * MBIT, samples: series(20, 5 * MBIT, 300 * MBIT)});
check('grosse Last -> Achse bis 400', yTicks()[0] === '400', yTicks()[0]);
check('Viertel mitskaliert', yTicks()[2] === '200', yTicks()[2]);
renderChart({intervalSeconds: 5, peakUp: 0, peakDown: 0, samples: series(20, 0, 0)});
check('zurueck auf den Boden', yTicks()[0] === '0.25', yTicks()[0]);

console.log('== Kurve passt zur Achse');
// Spitze 40 -> Achse 40: der Hoechstwert muss die obere Kante beruehren.
renderChart({intervalSeconds: 5, peakUp: 0, peakDown: 40 * MBIT,
             samples: [{t: new Date(Date.now() - 5000).toISOString(), up: 0, down: 0},
                       {t: new Date().toISOString(), up: 0, down: 40 * MBIT}]});
const ys = nodes['chart-down'].attrs.d.match(/L \d+\.\d+ (\d+\.\d+)/g).map(m => parseFloat(m.split(' ')[2]));
check('Spitze beruehrt obere Kante', Math.abs(ys[1] - 2) < 0.01, String(ys[1]));
check('Null liegt unten', Math.abs(ys[0] - 140) < 0.01, String(ys[0]));
// Achse 50 bei Spitze 45: 45/50 der Hoehe.
renderChart({intervalSeconds: 5, peakUp: 0, peakDown: 45 * MBIT,
             samples: [{t: new Date(Date.now() - 5000).toISOString(), up: 0, down: 0},
                       {t: new Date().toISOString(), up: 0, down: 45 * MBIT}]});
const ys2 = nodes['chart-down'].attrs.d.match(/L \d+\.\d+ (\d+\.\d+)/g).map(m => parseFloat(m.split(' ')[2]));
check('Spitze bei 45/50 der Hoehe', Math.abs(ys2[1] - (140 - 0.9 * 138)) < 0.2, String(ys2[1]));

console.log('== X-Achse');
renderChart({intervalSeconds: 5, peakDown: MBIT, peakUp: 0, samples: series(60, 0, MBIT)});
check('vier Zeit-Ticks', xTicks().length === 4, JSON.stringify(xTicks()));
check('links die Spanne', xTicks()[0] === 'vor 5 min', xTicks()[0]);
check('rechts jetzt', xTicks()[3] === 'jetzt', xTicks()[3]);
check('Mitte dazwischen', xTicks()[1] === 'vor 3 min' && xTicks()[2] === 'vor 2 min', JSON.stringify(xTicks()));
renderChart({intervalSeconds: 5, peakDown: MBIT, peakUp: 0, samples: series(6, 0, MBIT)});
check('kurze Reihe in Sekunden', xTicks()[0] === 'vor 25 s', xTicks()[0]);
renderChart({intervalSeconds: 5, peakDown: 0, peakUp: 0, samples: []});
check('leere Reihe: keine Zeit-Ticks', xTicks().length === 0, JSON.stringify(xTicks()));
check('leere Reihe: Y-Achse trotzdem da', yTicks().length === 5, JSON.stringify(yTicks()));
check('leere Reihe: Hinweis', /sammelt Daten/.test(nodes['chart-scale'].textContent), nodes['chart-scale'].textContent);

console.log('== Barrierefreiheit und Randfaelle');
renderChart({intervalSeconds: 5, peakUp: 2 * MBIT, peakDown: 40 * MBIT, samples: series(10, MBIT, 30 * MBIT)});
check('aria-label nennt Werte und Achse', /runter 30.0 Mbit\/s.*bis 40 Mbit/.test(nodes['chart'].attrs['aria-label']),
      nodes['chart'].attrs['aria-label']);
check('keine NaN im Pfad', !/NaN/.test(nodes['chart-down'].attrs.d));
renderChart({});
check('Status ohne metrics-Feld stuerzt nicht ab', yTicks().length === 5);
apply({enabled: true, target: '10.10.10.5', tableLoaded: true, activeFlows: 3, now: new Date().toISOString(),
       metrics: {intervalSeconds: 5, accounted: true, peakUp: MBIT, peakDown: 10 * MBIT, samples: series(30, MBIT, 8 * MBIT),
                 clients: [{ip: '203.0.113.9', active: true, flows: 5, bytesUp: 1680000, bytesDown: 987654321,
                            sessions: 2, lastSeen: new Date().toISOString()}]},
       checks: [], counters: [], events: []});
check('apply() laeuft komplett durch', nodes['pill'].textContent === 'Weiterleitung AN', nodes['pill'].textContent);
check('Client-Tabelle gefuellt', nodes['clients'].children.length === 1);

console.log(fails === 0 ? '\nALLES GRUEN' : `\n${fails} FEHLER`);
process.exit(fails === 0 ? 0 : 1);
