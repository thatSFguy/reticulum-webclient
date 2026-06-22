// js/micron.js — micron markup → HTML renderer for NomadNet pages.
//
// Micron is NomadNet's page format. Grammar mirrors upstream
// nomadnet/ui/textui/MicronParser.py:
//   #            comment line (whole line ignored)
//   >, >>, >>>   section depth / headings; < resets depth to 0
//   `=           on its own line, toggles literal (raw) mode
//   -x / --      horizontal divider (repeat char x, default U+2500)
//   backtick controls: `_ underline  `! bold  `* italic
//     `Fxxx / `FTxxxxxx foreground  `f reset fg
//     `Bxxx / `BTxxxxxx background  `b reset bg
//     `` (two backticks) reset all   `c `l `r align  `a reset align
//     `:name anchor   `t… table (rendered as plain text)   `{ partial (literal)
//   [label`target] / [target] / [label`target`fields]  links
//   \            escapes the next backtick or backslash
//
// Output is an HTML string. Links become
//   <a class="mu-link" data-target="…" data-fields="…">label</a>
// which app.js wires for navigation. All text is HTML-escaped.

'use strict';

export function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const NAME_CHAR = /[A-Za-z0-9_\-]/;
const HEX3 = /^[0-9a-fA-F]{3}$/;
const HEX6 = /^[0-9a-fA-F]{6}$/;

function freshState() {
  return { bold: false, italic: false, underline: false, fg: null, bg: null };
}

function openSpan(st) {
  const cls = [];
  if (st.bold) cls.push('mu-b');
  if (st.italic) cls.push('mu-i');
  if (st.underline) cls.push('mu-u');
  const styles = [];
  if (st.fg) styles.push(`color:${st.fg}`);
  if (st.bg) styles.push(`background:${st.bg}`);
  if (cls.length === 0 && styles.length === 0) return null;
  let s = '<span';
  if (cls.length) s += ` class="${cls.join(' ')}"`;
  if (styles.length) s += ` style="${styles.join(';')}"`;
  return s + '>';
}

// Render one micron input-field widget to an HTML control. `content` is
// the text between '<' and the first backtick ([flags|]name); `data` is
// the text between that backtick and '>' (initial value, or label for a
// checkbox/radio). Mirrors nomadnet MicronParser field parsing so the
// emitted control carries the field name app.js needs at submit time.
function renderField(content, data) {
  let flags = '', name = content, value = '', prechecked = false;
  if (content.includes('|')) {
    const c = content.split('|');
    flags = c[0];
    name = c[1] || '';
    if (c.length > 2) value = c[2];
    if (c.length > 3 && c[3] === '*') prechecked = true;
  }
  let type = 'field', masked = false, width = 24;
  if (flags.includes('^')) { type = 'radio'; flags = flags.replace(/\^/g, ''); }
  else if (flags.includes('?')) { type = 'checkbox'; flags = flags.replace(/\?/g, ''); }
  else if (flags.includes('!')) { masked = true; flags = flags.replace(/!/g, ''); }
  if (flags.length) { const w = parseInt(flags, 10); if (!isNaN(w)) width = Math.min(w, 256); }

  const nameEsc = escapeHtml(name);
  if (type === 'checkbox' || type === 'radio') {
    const val = value || data;   // value falls back to the label text
    const group = type === 'radio' ? ` name="mu-radio-${nameEsc}"` : '';
    return `<label class="mu-${type}"><input type="${type}" class="mu-field-input"` +
           ` data-field-name="${nameEsc}" data-field-value="${escapeHtml(val)}"${group}` +
           `${prechecked ? ' checked' : ''}><span>${escapeHtml(data)}</span></label>`;
  }
  return `<input class="mu-field-input mu-field-text" type="${masked ? 'password' : 'text'}"` +
         ` data-field-name="${nameEsc}" value="${escapeHtml(data)}" size="${width}">`;
}

// Render a single content line's inline markup. Returns { html, align }.
function renderInline(line) {
  const st = freshState();
  let align = null;
  let out = '';
  let buf = '';

  const flush = () => {
    if (buf.length === 0) return;
    const open = openSpan(st);
    out += open ? open + escapeHtml(buf) + '</span>' : escapeHtml(buf);
    buf = '';
  };

  let i = 0;
  const n = line.length;
  while (i < n) {
    const ch = line[i];

    if (ch === '\\') {
      // Escape the next char literally.
      if (i + 1 < n) { buf += line[i + 1]; i += 2; } else { buf += '\\'; i++; }
      continue;
    }

    if (ch === '[') {
      // Link: scan to matching ']'.
      const end = line.indexOf(']', i + 1);
      if (end > i) {
        flush();
        const inner = line.slice(i + 1, end);
        const parts = inner.split('`');
        let label, target, fields = '';
        if (parts.length === 1) { label = parts[0]; target = parts[0]; }
        else { label = parts[0]; target = parts[1]; fields = parts[2] || ''; }
        out += `<a href="#" class="mu-link" data-target="${escapeHtml(target)}"` +
               (fields ? ` data-fields="${escapeHtml(fields)}"` : '') +
               `>${escapeHtml(label)}</a>`;
        i = end + 1;
        continue;
      }
      buf += ch; i++; continue;
    }

    if (ch === '<') {
      // Input field widget: <[flags|]name`value> (NomadNet MicronParser).
      // Requires a backtick before the closing '>' — otherwise it is a
      // literal '<'. flags may carry ^ (radio), ? (checkbox), ! (masked)
      // and a numeric width; value is the initial text (field) or label
      // (checkbox/radio). See SPEC §11.6.2.
      const fb = line.indexOf('`', i + 1);
      const fe = line.indexOf('>', i + 1);
      if (fb > i && fe > fb) {
        flush();
        out += renderField(line.slice(i + 1, fb), line.slice(fb + 1, fe));
        i = fe + 1;
        continue;
      }
      buf += ch; i++; continue;
    }

    if (ch === '`') {
      const c = line[i + 1];
      if (c === undefined) { buf += '`'; i++; continue; }

      if (c === '`') { flush(); Object.assign(st, freshState()); i += 2; continue; }
      if (c === '_') { flush(); st.underline = !st.underline; i += 2; continue; }
      if (c === '!') { flush(); st.bold = !st.bold; i += 2; continue; }
      if (c === '*') { flush(); st.italic = !st.italic; i += 2; continue; }
      if (c === 'f') { flush(); st.fg = null; i += 2; continue; }
      if (c === 'b') { flush(); st.bg = null; i += 2; continue; }
      if (c === 'c' || c === 'l' || c === 'r') { align = c; i += 2; continue; }
      if (c === 'a') { align = null; i += 2; continue; }

      if (c === 'F' || c === 'B') {
        let color = null, adv = 0;
        if (line[i + 2] === 'T' && HEX6.test(line.substr(i + 3, 6))) {
          color = '#' + line.substr(i + 3, 6); adv = 9;
        } else if (HEX3.test(line.substr(i + 2, 3))) {
          color = '#' + line.substr(i + 2, 3); adv = 5;
        }
        if (color) {
          flush();
          if (c === 'F') st.fg = color; else st.bg = color;
          i += adv; continue;
        }
        buf += '`'; i++; continue;  // malformed — literal backtick
      }

      if (c === ':') {
        // Anchor declaration `:name (consumed; emits an id target).
        let j = i + 2, name = '';
        while (j < n && NAME_CHAR.test(line[j])) { name += line[j]; j++; }
        flush();
        if (name) out += `<span id="${escapeHtml(name)}"></span>`;
        i = j; continue;
      }

      if (c === 't') {
        // Table control (`t, `tl100, `tc, `tr) — consume; render cells as text.
        let j = i + 2;
        if (line[j] === 'l' || line[j] === 'c' || line[j] === 'r') j++;
        while (j < n && /[0-9]/.test(line[j])) j++;
        i = j; continue;
      }

      if (c === '{') {
        // Partial/include — not supported; show a literal marker.
        const close = line.indexOf('}', i + 2);
        const inner = close > i ? line.slice(i + 2, close) : '';
        flush();
        out += `<span class="mu-partial">[partial: ${escapeHtml(inner.split('`')[0])}]</span>`;
        i = close > i ? close + 1 : i + 2; continue;
      }

      // Unknown control — drop the backtick, keep the char.
      i += 1; continue;
    }

    buf += ch; i++;
  }
  flush();
  return { html: out, align };
}

// Render a full micron document to HTML. Returns an HTML string.
export function renderMicron(text) {
  const lines = String(text).replace(/\r\n?/g, '\n').split('\n');
  let html = '';
  let literal = false;
  let depth = 0;
  let tableMode = false;
  let tableBuf = [];
  let tableAlign = null;

  for (const raw of lines) {
    const line = raw;

    // Literal-mode toggle / passthrough.
    if (line === '`=') { literal = !literal; continue; }
    if (literal) {
      const unescaped = line.replace(/^\\`=/, '`=');
      html += `<div class="mu-literal">${escapeHtml(unescaped) || '&nbsp;'}</div>`;
      continue;
    }

    // Table toggle (`t[align][maxwidth]). The first marker opens table
    // mode and buffers following lines; the second renders the buffered
    // markdown-style rows and closes it (nomadnet MicronParser).
    if (line.startsWith('`t')) {
      if (tableMode) {
        html += renderTable(tableBuf, tableAlign);
        tableMode = false; tableBuf = []; tableAlign = null;
      } else {
        tableMode = true; tableBuf = [];
        const a = line[2];
        tableAlign = (a === 'l' || a === 'c' || a === 'r') ? a : null;
      }
      continue;
    }
    if (tableMode) { tableBuf.push(line); continue; }

    if (line.length === 0) { html += '<div class="mu-line">&nbsp;</div>'; continue; }
    if (line[0] === '#') continue;  // comment

    // Section depth.
    if (line[0] === '<') { depth = 0; const { html: h } = renderInline(line.slice(1)); html += `<div class="mu-line">${h || '&nbsp;'}</div>`; continue; }
    if (line[0] === '>') {
      let d = 0;
      while (line[d] === '>') d++;
      depth = d;
      const level = Math.min(d, 3);
      const { html: h } = renderInline(line.slice(d).replace(/^\s+/, ''));
      html += `<div class="mu-h mu-h${level}">${h || '&nbsp;'}</div>`;
      continue;
    }

    // Divider.
    if (line[0] === '-') {
      const ch = line.length > 1 ? line[1] : '─';
      html += `<hr class="mu-hr" data-char="${escapeHtml(ch)}">`;
      continue;
    }

    const { html: h, align } = renderInline(line);
    const alignClass = align === 'c' ? ' mu-center' : align === 'r' ? ' mu-right' : '';
    html += `<div class="mu-line${alignClass}">${h || '&nbsp;'}</div>`;
  }

  // Unterminated table (no closing `t) — render what we buffered.
  if (tableMode && tableBuf.length) html += renderTable(tableBuf, tableAlign);

  return html;
}

// Split a markdown table row into trimmed cells, honoring backslash-
// escaped pipes and stripping the outer pipes (RNS MarkdownToMicron
// _parse_table_row).
function parseTableRow(line) {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|')) s = s.slice(0, -1);
  const cells = [];
  let cur = '', esc = false;
  for (const ch of s) {
    if (esc) { cur += ch; esc = false; }
    else if (ch === '\\') { esc = true; }
    else if (ch === '|') { cells.push(cur.trim()); cur = ''; }
    else cur += ch;
  }
  cells.push(cur.trim());
  return cells;
}

// True if every cell is a markdown alignment marker (---, :--, :-:, --:).
function isSeparatorRow(cells) {
  return cells.length > 0 && cells.every(c => /^:?-+:?$/.test(c.replace(/\s/g, '')));
}

function cellAlign(c) {
  const t = c.replace(/\s/g, '');
  const l = t.startsWith(':'), r = t.endsWith(':');
  return (l && r) ? 'center' : r ? 'right' : 'left';
}

// Render buffered markdown table rows to an HTML <table>. Row 0 is the
// header; if row 1 is an alignment separator it sets per-column alignment
// and is skipped; remaining rows are data. Cell text is rendered through
// the inline pass so links/styling inside cells work.
function renderTable(rows, tableAlign) {
  if (!rows.length) return '';
  const header = parseTableRow(rows[0]);
  let aligns = [];
  let dataStart = 1;
  if (rows.length >= 2 && isSeparatorRow(parseTableRow(rows[1]))) {
    aligns = parseTableRow(rows[1]).map(cellAlign);
    dataStart = 2;
  }
  const cols = header.length;
  const alignAttr = (i) => aligns[i] ? ` style="text-align:${aligns[i]}"` : '';
  const tableCls = tableAlign === 'c' ? ' mu-table-center' : tableAlign === 'r' ? ' mu-table-right' : '';

  let h = `<table class="mu-table${tableCls}"><thead><tr>`;
  for (let i = 0; i < cols; i++) h += `<th${alignAttr(i)}>${renderInline(header[i]).html}</th>`;
  h += '</tr></thead><tbody>';
  for (let r = dataStart; r < rows.length; r++) {
    const cells = parseTableRow(rows[r]);
    h += '<tr>';
    for (let i = 0; i < cols; i++) h += `<td${alignAttr(i)}>${renderInline(cells[i] || '').html}</td>`;
    h += '</tr>';
  }
  return h + '</tbody></table>';
}

export default renderMicron;
