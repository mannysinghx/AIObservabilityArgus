// Governance Effectiveness Score calculator.
// G = 100 * C * (V^0.15 * O^0.20 * K^0.25 * E^0.15 * R^0.15 * I^0.10) * (1 - P)
// Self-contained, no network calls — every number stays in the browser.
(function () {
  "use strict";

  // Elasticity weight used only for the "what to do next" ranking below: how
  // much a 1% relative improvement in this factor moves G. C and P are linear
  // terms (weight 1); V/O/K/E/R/I are the formula's own exponents.
  var FACTORS = [
    { key: "C", name: "Coverage", letter: "C", weight: 1.00, default: 90,
      desc: "How much of your critical systems, data, vendors, processes, and AI use cases are inside governance.",
      action: "Inventory unmonitored systems, vendors, and AI use cases, and bring the highest-risk ones into scope first." },
    { key: "V", name: "Visibility", letter: "V", weight: 0.15, default: 80,
      desc: "Can you see important access, actions, changes, and decisions?",
      action: "Instrument logging and monitoring for access, changes, and decisions in the areas with the least visibility today." },
    { key: "O", name: "Ownership", letter: "O", weight: 0.20, default: 75,
      desc: "Does every important risk, control, exception, and decision have a named owner?",
      action: "Assign one named, accountable owner to every open risk, control, exception, and decision — no shared or vacant ownership." },
    { key: "K", name: "Key Control Reliability", letter: "K", weight: 0.25, default: 70,
      desc: "Do your most important controls work when they are tested?",
      action: "Retest your most important controls. Any control that fails gets a fix owner and a retest date, not another audit note." },
    { key: "E", name: "Evidence", letter: "E", weight: 0.15, default: 85,
      desc: "Can you prove your controls and governance processes are actually working?",
      action: "Automate evidence capture for your top controls so proof exists on demand instead of a manual scramble before an audit." },
    { key: "R", name: "Response", letter: "R", weight: 0.15, default: 60,
      desc: "Are serious issues contained and resolved within the required time?",
      action: "Set and enforce resolution-time SLAs for serious issues, and track time-to-contain and time-to-resolve as core metrics." },
    { key: "I", name: "Improvement", letter: "I", weight: 0.10, default: 50,
      desc: "Are you preventing repeated failures, or simply recording them again?",
      action: "Root-cause repeated failures instead of re-logging them, then retest the control after the fix to confirm it holds." }
  ];
  var PENALTY = { key: "P", name: "Critical Exposure Penalty", letter: "P", weight: 1.00, default: 10,
    desc: "How much overdue and unaccepted risk currently sits above your approved risk level.",
    action: "Close or formally accept every expired risk exception, prioritized by severity and age, until none sit above your approved level." };

  var NEUTRAL = { C: 75, V: 75, O: 75, K: 75, E: 75, R: 75, I: 75, P: 10 };

  var slidersEl = document.getElementById("sliders");
  var scoreBigEl = document.getElementById("scoreBig");
  var scoreBandEl = document.getElementById("scoreBand");
  var scoreNoteEl = document.getElementById("scoreNote");
  var formulaLiveEl = document.getElementById("formulaLive");
  var prioritiesEl = document.getElementById("priorities");
  var bandScaleEl = document.getElementById("bandScale");

  var inputs = {}; // key -> <input>
  var valueEls = {}; // key -> value label span

  function buildRows() {
    var all = FACTORS.concat([PENALTY]);
    var html = "";
    all.forEach(function (f) {
      var isPenalty = f.key === "P";
      html +=
        '<div class="slider-row' + (isPenalty ? " penalty" : "") + '">' +
          '<div class="sr-head">' +
            '<div class="sr-name"><span class="letter">' + f.letter + '</span>' + f.name + '</div>' +
            '<div class="sr-val tnum" id="val-' + f.key + '">' + f.default + '%</div>' +
          '</div>' +
          '<div class="sr-desc">' + f.desc + '</div>' +
          '<input type="range" min="0" max="100" step="1" value="' + f.default + '" id="in-' + f.key + '" ' +
            'aria-label="' + f.name + ' percent">' +
        '</div>';
    });
    slidersEl.innerHTML = html;
    all.forEach(function (f) {
      inputs[f.key] = document.getElementById("in-" + f.key);
      valueEls[f.key] = document.getElementById("val-" + f.key);
      inputs[f.key].addEventListener("input", onChange);
    });
  }

  function currentValues() {
    var v = {};
    FACTORS.concat([PENALTY]).forEach(function (f) {
      v[f.key] = Number(inputs[f.key].value);
    });
    return v;
  }

  function setValues(v) {
    FACTORS.concat([PENALTY]).forEach(function (f) {
      inputs[f.key].value = String(v[f.key]);
    });
    render();
  }

  function updateTrackFill(key, pct) {
    inputs[key].style.setProperty("--pct", pct + "%");
  }

  function computeScore(v) {
    var C = v.C / 100, V = v.V / 100, O = v.O / 100, K = v.K / 100,
        E = v.E / 100, R = v.R / 100, I = v.I / 100, P = v.P / 100;
    var weighted = Math.pow(V, 0.15) * Math.pow(O, 0.20) * Math.pow(K, 0.25) *
                   Math.pow(E, 0.15) * Math.pow(R, 0.15) * Math.pow(I, 0.10);
    var G = 100 * C * weighted * (1 - P);
    return { G: G, weighted: weighted };
  }

  function bandFor(score) {
    if (score >= 80) return { key: "strong", label: "Strong — supported by evidence" };
    if (score >= 65) return { key: "working", label: "Working — important gaps remain" };
    if (score >= 50) return { key: "weak", label: "Weak — corrective action required" };
    return { key: "serious", label: "Serious unmanaged exposure" };
  }

  function fmt(n, d) {
    return n.toFixed(d == null ? 2 : d).replace(/\.00$/, "");
  }

  function renderFormulaLive(v, result) {
    var frac = function (k) { return (v[k] / 100).toFixed(2); };
    formulaLiveEl.innerHTML =
      "G = 100 × " + frac("C") +
      " × (" + frac("V") + "<sup>0.15</sup> × " + frac("O") + "<sup>0.20</sup> × " +
      frac("K") + "<sup>0.25</sup> × " + frac("E") + "<sup>0.15</sup> × " +
      frac("R") + "<sup>0.15</sup> × " + frac("I") + "<sup>0.10</sup>)" +
      " × (1 − " + frac("P") + ")<br>" +
      "&nbsp;&nbsp;= 100 × " + frac("C") + " × " + fmt(result.weighted, 3) +
      " × " + fmt(1 - v.P / 100, 2) +
      " = <b>" + fmt(result.G, 1) + "</b>";
  }

  function weightNote(f) {
    if (f.key === "C" || f.key === "P") return "Linear term — moves the score directly, point for point.";
    if (f.weight >= 0.25) return "Carries a 0.25 exponent — the single most heavily weighted factor in the formula.";
    if (f.weight >= 0.20) return "Carries a 0.20 exponent — one of the more heavily weighted factors.";
    if (f.weight >= 0.15) return "Carries a 0.15 exponent in the formula.";
    return "Carries a 0.10 exponent — the lightest-weighted factor.";
  }

  function renderPriorities(v) {
    // Weakest raw score first — this is what the worked example itself calls
    // out ("the biggest weaknesses are Response and Improvement"), not the
    // factor whose improvement would move G the most. The formula's weight on
    // each factor is still shown per card as supporting context.
    var ranked = FACTORS.concat([PENALTY]).map(function (f) {
      var badness = f.key === "P" ? v.P : (100 - v[f.key]);
      return { f: f, badness: badness, value: v[f.key] };
    }).sort(function (a, b) {
      if (b.badness !== a.badness) return b.badness - a.badness;
      return b.f.weight - a.f.weight; // tie-break: more heavily weighted factor first
    });

    var top = ranked.filter(function (r) { return r.badness > 0.5; }).slice(0, 3);

    if (top.length === 0) {
      prioritiesEl.innerHTML = '<div class="card pri-empty">Every factor is at 100 and the exposure penalty is at 0 — there is no bigger opportunity left to rank. Keep proving it with evidence.</div>';
      return;
    }

    prioritiesEl.innerHTML = top.map(function (r, i) {
      var valueLabel = r.f.key === "P" ? (r.value + "% penalty") : (r.value + "%");
      return (
        '<div class="card pri-card">' +
          '<div class="pri-rank">' + (i + 1) + '</div>' +
          '<h4>' + r.f.name + '</h4>' +
          '<div class="pv">Currently ' + valueLabel + '</div>' +
          '<p>' + r.f.action + '</p>' +
          '<p class="pri-weight">' + weightNote(r.f) + '</p>' +
        '</div>'
      );
    }).join("");
  }

  function render() {
    var v = currentValues();
    FACTORS.concat([PENALTY]).forEach(function (f) {
      valueEls[f.key].textContent = v[f.key] + "%";
      updateTrackFill(f.key, v[f.key]);
    });

    var result = computeScore(v);
    var band = bandFor(result.G);

    scoreBigEl.textContent = fmt(result.G, 0);
    scoreBandEl.textContent = band.label;
    scoreBandEl.className = "score-band " + band.key;

    if (v.P >= 15) {
      scoreNoteEl.textContent = "Your Critical Exposure Penalty alone is removing " + v.P + "% of what your score would otherwise be.";
    } else {
      scoreNoteEl.textContent = "";
    }

    renderFormulaLive(v, result);
    renderPriorities(v);

    Array.prototype.forEach.call(bandScaleEl.querySelectorAll(".band-row"), function (row) {
      row.classList.toggle("active", row.getAttribute("data-band") === band.key);
    });
  }

  function onChange() { render(); }

  document.getElementById("btnExample").addEventListener("click", function () {
    var example = {};
    FACTORS.concat([PENALTY]).forEach(function (f) { example[f.key] = f.default; });
    setValues(example);
  });
  document.getElementById("btnNeutral").addEventListener("click", function () {
    setValues(NEUTRAL);
  });

  buildRows();
  render();
})();
