/**
 * "Markdown for Agents" response conversion.
 *
 * Converts a rendered HTML document into a token-efficient Markdown representation without any
 * third-party HTML parser so the module stays dependency-free and safe on untrusted markup.
 */

import type { Response } from 'express';

export const MAX_MARKDOWN_HTML_BYTES = 6 * 1024 * 1024;

export interface MarkdownConversionResult {
  converted: boolean;
  markdown: string;
  byteLength: number;
  reason?: 'too_large' | 'empty';
}

function decodeEntities(text: string): string {
  const named: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
    ndash: '–',
    mdash: '—',
    hellip: '…',
    rsquo: '’',
    lsquo: '‘',
    ldquo: '“',
    rdquo: '”',
    copy: '©',
    reg: '®',
    trade: '™',
  };
  return text
    .replace(/&(#x[0-9a-f]+|#\d+|[a-zA-Z]+);/gi, (whole, entity: string) => {
      if (entity.startsWith('#x') || entity.startsWith('#X')) {
        const code = Number.parseInt(entity.slice(2), 16);
        return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
      }
      if (entity.startsWith('#')) {
        const code = Number.parseInt(entity.slice(1), 10);
        return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
      }
      return named[entity.toLowerCase()] ?? whole;
    })
    .replace(/&#(\d+);/g, (_whole, decimal: string) => String.fromCodePoint(Number.parseInt(decimal, 10)));
}

function stripBlocks(html: string): string {
  let result = html;
  const tags = ['script', 'style', 'noscript', 'svg', 'iframe', 'nav', 'header', 'footer', 'aside', 'form'];
  // Repeat so nested blocks (e.g. a <nav> inside a <header>) are removed completely.
  for (let pass = 0; pass < 4; pass += 1) {
    for (const tag of tags) {
      result = result.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}\\s*>`, 'gi'), ' ');
      result = result.replace(new RegExp(`<${tag}\\b[^>]*\\/>`, 'gi'), ' ');
    }
  }
  result = result.replace(/<!--[\s\S]*?-->/g, ' ');
  return result;
}

function extractJsonLd(html: string): { body: string; nodes: unknown[] } {
  const nodes: unknown[] = [];
  const body = html.replace(
    /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script\s*>/gi,
    (_whole, raw: string) => {
      try {
        const parsed = JSON.parse(raw.trim()) as unknown;
        if (Array.isArray(parsed)) nodes.push(...parsed);
        else if (parsed !== null && typeof parsed === 'object') nodes.push(parsed);
      } catch {
        // Malformed JSON-LD is discarded rather than leaking script contents.
      }
      return ' ';
    }
  );
  return { body, nodes };
}

function htmlToMarkdown(html: string): string {
  let text = html;

  // Block-level structure first, so inline passes also work inside headings/list items.
  text = text.replace(/<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1\s*>/gi, (_whole, level: string, inner: string) => {
    const hashes = '#'.repeat(Number.parseInt(level, 10));
    return `\n\n${hashes} ${inner.replace(/\s+/g, ' ').trim()}\n\n`;
  });
  text = text.replace(/<p\b[^>]*>/gi, '\n\n').replace(/<\/p\s*>/gi, '\n\n');
  text = text.replace(/<div\b[^>]*>/gi, '\n').replace(/<\/div\s*>/gi, '\n');
  text = text.replace(/<section\b[^>]*>/gi, '\n').replace(/<\/section\s*>/gi, '\n');
  text = text.replace(/<article\b[^>]*>/gi, '\n').replace(/<\/article\s*>/gi, '\n');
  text = text.replace(/<main\b[^>]*>/gi, '\n').replace(/<\/main\s*>/gi, '\n');
  text = text.replace(/<br\s*\/?>/gi, '  \n');
  text = text.replace(/<hr\b[^>]*\/?>/gi, '\n\n---\n\n');

  text = text.replace(/<ul\b[^>]*>/gi, '\n').replace(/<\/ul\s*>/gi, '\n');
  text = text.replace(/<ol\b[^>]*>/gi, '\n').replace(/<\/ol\s*>/gi, '\n');
  text = text.replace(/<li\b[^>]*>([\s\S]*?)<\/li\s*>/gi, (_whole, inner: string) => {
    const clean = inner.replace(/\s+/g, ' ').trim();
    return clean ? `- ${clean}\n` : '';
  });

  text = text.replace(/<blockquote\b[^>]*>([\s\S]*?)<\/blockquote\s*>/gi, (_whole, inner: string) => {
    const quoted = inner
      .replace(/<[^>]+>/g, ' ')
      .split(/\n+/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => `> ${line}`)
      .join('\n');
    return `\n\n${quoted}\n\n`;
  });

  text = text.replace(/<pre\b[^>]*>([\s\S]*?)<\/pre\s*>/gi, (_whole, inner: string) => {
    const code = decodeEntities(inner.replace(/<[^>]+>/g, '')).trim();
    return `\n\n\`\`\`\n${code}\n\`\`\`\n\n`;
  });
  text = text.replace(/<code\b[^>]*>([\s\S]*?)<\/code\s*>/gi, (_whole, inner: string) => `\`${inner.trim()}\``);

  text = text.replace(/<img\b[^>]*>/gi, (whole) => {
    const src = /\bsrc\s*=\s*["']([^"']*)["']/i.exec(whole)?.[1] ?? '';
    const alt = /\balt\s*=\s*["']([^"']*)["']/i.exec(whole)?.[1] ?? '';
    if (!src) return '';
    return `![${alt}](${src})`;
  });
  text = text.replace(
    /<a\b[^>]*href\s*=\s*["']([^"']*)["'][^>]*>([\s\S]*?)<\/a\s*>/gi,
    (_whole, href: string, inner: string) => {
      const label = decodeEntities(inner.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
      return label ? `[${label}](${href})` : `[${href}](${href})`;
    }
  );

  text = text.replace(/<(strong|b)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi, '**$2**');
  text = text.replace(/<(em|i)\b[^>]*>([\s\S]*?)<\/\1\s*>/gi, '*$2*');
  text = text.replace(/<del\b[^>]*>([\s\S]*?)<\/del\s*>/gi, '~~$1~~');

  // Lightweight table support: rows become pipe-delimited lines, first row is the header.
  text = text.replace(/<table\b[^>]*>([\s\S]*?)<\/table\s*>/gi, (_whole, inner: string) => {
    const rows = [...inner.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr\s*>/gi)].map((row) =>
      [...row[1].matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]\s*>/gi)].map((cell) =>
        decodeEntities(cell[1].replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim()
      )
    );
    if (!rows.length) return '\n';
    const width = Math.max(...rows.map((row) => row.length));
    const format = (row: string[]): string =>
      `| ${[...row, ...new Array<string>(width - row.length).fill('')].join(' | ')} |`;
    const lines = [format(rows[0]), `| ${new Array<string>(width).fill('---').join(' | ')} |`];
    for (const row of rows.slice(1)) lines.push(format(row));
    return `\n\n${lines.join('\n')}\n\n`;
  });

  text = text.replace(/<\/?[a-zA-Z][^>]*>/g, '');
  text = decodeEntities(text);
  text = text.replace(/\r\n?/g, '\n');
  text = text
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/g, ''))
    .join('\n');
  text = text.replace(/\n{3,}/g, '\n\n').replace(/[ \t]{2,}/g, ' ').trim();
  return text;
}

/** Reads a <meta name="..." content="..."> / <meta property="..." ...> tag in either attribute order. */
function extractMetaContent(html: string, attribute: 'name' | 'property', key: string): string | null {
  const tagPattern = /<meta\b[^>]*>/gi;
  const attrPattern = new RegExp(`${attribute}\\s*=\\s*(["'])(.*?)\\1`, 'i');
  let match: RegExpExecArray | null;
  while ((match = tagPattern.exec(html)) !== null) {
    const tag = match[0];
    const attr = attrPattern.exec(tag);
    if (!attr || attr[2].trim().toLowerCase() !== key.toLowerCase()) continue;
    const content = /\bcontent\s*=\s*(["'])(.*?)\1/i.exec(tag);
    if (content) return decodeEntities(content[2]).trim();
  }
  return null;
}

/** Converts rendered HTML into Markdown suitable for `Accept: text/markdown` clients. */
function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

export function convertHtmlToAgentMarkdown(htmlBuffer: Buffer | string): MarkdownConversionResult {
  const source = typeof htmlBuffer === 'string' ? htmlBuffer : String(htmlBuffer);
  const inputBytes = utf8ByteLength(source);
  if (inputBytes > MAX_MARKDOWN_HTML_BYTES) {
    return { converted: false, markdown: '', byteLength: inputBytes, reason: 'too_large' };
  }

  let body = source;
  let frontmatter = '';
  const frontmatterMatch = /^\uFEFF?---\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(body);
  if (frontmatterMatch) {
    frontmatter = `---\n${frontmatterMatch[1].trim()}\n---\n\n`;
    body = body.slice(frontmatterMatch[0].length);
  } else {
    // Cloudflare Markdown for Agents: synthesise YAML frontmatter from meta tags, with
    // standard <meta name> taking priority over Open Graph <meta property> fallbacks.
    const title = extractMetaContent(source, 'name', 'title') ?? extractMetaContent(source, 'property', 'og:title');
    const description =
      extractMetaContent(source, 'name', 'description') ?? extractMetaContent(source, 'property', 'og:description');
    const image = extractMetaContent(source, 'property', 'og:image');
    const yaml: string[] = [];
    const yamlValue = (value: string): string => `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
    if (title) yaml.push(`title: ${yamlValue(title)}`);
    if (description) yaml.push(`description: ${yamlValue(description)}`);
    if (image) yaml.push(`image: ${yamlValue(image)}`);
    if (yaml.length) frontmatter = `---\n${yaml.join('\n')}\n---\n\n`;
  }

  const { body: withoutJsonLd, nodes } = extractJsonLd(body);
  body = stripBlocks(withoutJsonLd);
  const markdown = htmlToMarkdown(body);
  if (!markdown && !nodes.length) {
    return { converted: false, markdown: '', byteLength: 0, reason: 'empty' };
  }

  let output = `${frontmatter}${markdown}`;
  if (nodes.length) {
    output += `\n\n\`\`\`json\n${JSON.stringify(nodes, null, 2)}\n\`\`\`\n`;
  }
  output = `${output.trim()}\n`;
  return { converted: true, markdown: output, byteLength: utf8ByteLength(output) };
}

/** Applies the Markdown-for-Agents response headers without destroying existing metadata. */
export function applyMarkdownResponseHeaders(res: Response, defaultContentSignal: string): void {
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');

  const vary = res.getHeader('Vary');
  const varyText = Array.isArray(vary) ? vary.join(', ') : vary == null ? '' : String(vary);
  if (!/(?:^|,)\s*accept\s*(?:,|$)/i.test(varyText)) {
    res.setHeader('Vary', varyText ? `${varyText}, Accept` : 'Accept');
  }

  if (!res.getHeader('Content-Signal')) res.setHeader('Content-Signal', defaultContentSignal);

  for (const header of [
    'Content-Length',
    'Content-Encoding',
    'Content-Range',
    'Transfer-Encoding',
    'ETag',
    'Last-Modified',
  ]) {
    res.removeHeader(header);
  }
}
