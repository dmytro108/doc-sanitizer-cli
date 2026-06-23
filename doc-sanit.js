// doc-sanit.js
const { OpenRedaction } = require("openredaction");
const {
  readFileSync,
  writeFileSync,
  mkdirSync,
  statSync,
  readdirSync,
  lstatSync,
} = require("fs");
const path = require("path");

const baseWhitelist = [
  "AWS",
  "etc",
  "systemctl",
  "daemon",
  "localhost",
  "README",
  "md",
  "yaml",
  "yml",
  "service",
];

const envWhitelist = (process.env.DOC_SANIT_WHITELIST || "")
  .split(",")
  .map((item) => item.trim())
  .filter(Boolean);

// Tune defaults for technical docs where broad social/name patterns are noisy.
const redactor = new OpenRedaction({
  includeNames: false,
  includeAddresses: false,
  confidenceThreshold: 0.6,
  enableFalsePositiveFilter: true,
  falsePositiveThreshold: 0.5,
  whitelist: [...new Set([...baseWhitelist, ...envWhitelist])],
});

function decodeText(raw) {
  // Detect BOM and decode accordingly, otherwise assume UTF-8
  if (raw[0] === 0xff && raw[1] === 0xfe) {
    // UTF-16 LE
    return raw.slice(2).toString("utf16le");
  }
  if (raw[0] === 0xfe && raw[1] === 0xff) {
    // UTF-16 BE
    return raw.slice(2).swap16().toString("utf16le");
  }
  if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    // UTF-8 BOM
    return raw.slice(3).toString("utf-8");
  }
  return raw.toString("utf-8");
}

function collectFilesRecursively(rootDir) {
  const files = [];
  const entries = readdirSync(rootDir, { withFileTypes: true });

  entries.forEach((entry) => {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isSymbolicLink()) {
      return;
    }
    if (entry.isDirectory()) {
      files.push(...collectFilesRecursively(fullPath));
      return;
    }
    if (entry.isFile()) {
      files.push(fullPath);
    }
  });

  return files;
}

function getTokenBounds(text, start, end) {
  let left = start;
  let right = end;

  while (left > 0 && /[0-9.]/.test(text[left - 1])) {
    left -= 1;
  }
  while (right < text.length && /[0-9.]/.test(text[right])) {
    right += 1;
  }

  return [left, right];
}

function isIPv4Token(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    if (part.length > 1 && part.startsWith("0")) {
      return false;
    }
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isDetectionInsideIPv4(text, detection) {
  const [start, end] = detection.position || [];
  if (typeof start !== "number" || typeof end !== "number") {
    return false;
  }

  const [left, right] = getTokenBounds(text, start, end);
  const token = text.slice(left, right);
  return isIPv4Token(token);
}

function ipv4Placeholder(ip) {
  let hash = 0;
  for (const ch of ip) {
    hash = (hash * 31 + ch.charCodeAt(0)) % 10000;
  }
  return `[IPV4_${String(hash).padStart(4, "0")}]`;
}

function redactIpv4Addresses(text) {
  const ipv4Regex = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;
  const seen = new Map();
  let replacementCount = 0;

  const redactedText = text.replace(ipv4Regex, (ip) => {
    if (!seen.has(ip)) {
      seen.set(ip, ipv4Placeholder(ip));
    }
    replacementCount += 1;
    return seen.get(ip);
  });

  return { redactedText, replacementCount };
}

function getLineBounds(text, index) {
  const lineStart = text.lastIndexOf("\n", Math.max(0, index - 1)) + 1;
  const nextNewline = text.indexOf("\n", index);
  const lineEnd = nextNewline === -1 ? text.length : nextNewline;
  return [lineStart, lineEnd];
}

function isStructuredKeyDetection(text, detection) {
  const [start, end] = detection.position || [];
  if (typeof start !== "number" || typeof end !== "number") {
    return false;
  }

  const [lineStart, lineEnd] = getLineBounds(text, start);
  const line = text.slice(lineStart, lineEnd);
  const localStart = start - lineStart;
  const localEnd = end - lineStart;

  const keyMatch = line.match(
    /^(\s*)(-\s*)?("[^"\r\n]+"|'[^'\r\n]+'|[A-Za-z0-9_.-]+)\s*:/,
  );
  if (!keyMatch) {
    return false;
  }

  const keyStart = (keyMatch[1] || "").length + (keyMatch[2] || "").length;
  const keyEnd = keyStart + keyMatch[3].length;

  return localStart >= keyStart && localEnd <= keyEnd;
}

function shouldKeepDetection(detection, text) {
  if (
    detection.type === "TRAINING_CERT_ID" &&
    !/\d/.test(String(detection.value || ""))
  ) {
    return false;
  }

  if (isStructuredKeyDetection(text, detection)) {
    return false;
  }

  if (detection.type.startsWith("PHONE") && isDetectionInsideIPv4(text, detection)) {
    return false;
  }

  if (detection.type !== "INSTAGRAM_USERNAME") {
    return true;
  }

  const start = detection.position?.[0] ?? -1;
  if (start <= 0) {
    return detection.value.startsWith("@");
  }

  const prevChar = text[start - 1];
  return detection.value.startsWith("@") || prevChar === "@";
}

function applyDetections(text, detections) {
  if (detections.length === 0) {
    return text;
  }

  const sorted = [...detections].sort(
    (a, b) => (a.position?.[0] ?? 0) - (b.position?.[0] ?? 0),
  );

  let cursor = 0;
  let output = "";

  for (const detection of sorted) {
    const [start, end] = detection.position || [];
    if (
      typeof start !== "number" ||
      typeof end !== "number" ||
      start < cursor ||
      start > text.length ||
      end > text.length
    ) {
      continue;
    }

    output += text.slice(cursor, start);
    output += detection.placeholder;
    cursor = end;
  }

  output += text.slice(cursor);
  return output;
}

function redactSecretAssignments(text) {
  const secretKeyPattern =
    "(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|refresh[_-]?token)";
  const assignmentRegex = new RegExp(
    `\\b[a-z0-9_.-]*${secretKeyPattern}[a-z0-9_.-]*\\b\\s*[:=]\\s*(?:([\"'])([^\"'\\r\\n]{8,})\\1|([^\\s#\\r\\n]{8,}))`,
    "gi",
  );

  let replacementCount = 0;
  const redactedText = text.replace(
    assignmentRegex,
    (fullMatch, quote, quotedValue, unquotedValue) => {
      const separatorMatch = fullMatch.match(/^(.+?[:=]\s*)/);
      if (!separatorMatch) {
        return fullMatch;
      }

      const prefix = separatorMatch[1];
      const value = quotedValue || unquotedValue || "";
      if (/^\[[A-Z_]+(?:_\d+)?\]$/.test(value)) {
        return fullMatch;
      }

      replacementCount += 1;
      if (quote) {
        return `${prefix}${quote}[SECRET_VALUE]${quote}`;
      }

      return `${prefix}[SECRET_VALUE]`;
    },
  );

  return { redactedText, replacementCount };
}

function isLikelyBase64Secret(value) {
  if (value.length < 24 || value.length % 4 !== 0) {
    return false;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return false;
  }

  const normalizedInput = value.replace(/=+$/, "");
  let decoded;
  try {
    decoded = Buffer.from(value, "base64");
  } catch {
    return false;
  }
  if (!decoded || decoded.length < 12) {
    return false;
  }

  const roundtrip = decoded.toString("base64").replace(/=+$/, "");
  if (roundtrip !== normalizedInput) {
    return false;
  }

  return /[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value);
}

function redactBase64Secrets(text) {
  const quotedPattern = /(["'])([A-Za-z0-9+/]{24,}={0,2})\1/g;
  const tokenPattern = /(^|[\s:=,\[{(])([A-Za-z0-9+/]{24,}={0,2})(?=$|[\s,\]}):])/g;
  let replacementCount = 0;

  let redactedText = text.replace(quotedPattern, (fullMatch, quote, candidate) => {
    if (!isLikelyBase64Secret(candidate)) {
      return fullMatch;
    }
    replacementCount += 1;
    return `${quote}[BASE64_SECRET]${quote}`;
  });

  redactedText = redactedText.replace(tokenPattern, (fullMatch, prefix, candidate) => {
    if (!isLikelyBase64Secret(candidate)) {
      return fullMatch;
    }
    replacementCount += 1;
    return `${prefix}[BASE64_SECRET]`;
  });

  return { redactedText, replacementCount };
}

async function sanitizeFile(inputPath, outputPath) {
  let raw;
  try {
    raw = readFileSync(inputPath);
  } catch (err) {
    throw new Error(`Error reading file ${inputPath}: ${err.message}`);
  }

  const text = decodeText(raw);
  const result = await redactor.detect(text);
  const filteredDetections = result.detections.filter((detection) =>
    shouldKeepDetection(detection, text),
  );
  const initialRedactedText = applyDetections(text, filteredDetections);
  const { redactedText: withSecretRedaction, replacementCount: secretCount } =
    redactSecretAssignments(initialRedactedText);
  const { redactedText: withBase64Redaction, replacementCount: base64Count } =
    redactBase64Secrets(withSecretRedaction);
  const { redactedText, replacementCount: ipv4Count } =
    redactIpv4Addresses(withBase64Redaction);
  const totalDetections =
    filteredDetections.length + secretCount + base64Count + ipv4Count;

  try {
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, redactedText, "utf-8");
  } catch (err) {
    throw new Error(`Error writing file ${outputPath}: ${err.message}`);
  }

  console.log(`✓ Redacted: ${inputPath} -> ${outputPath}`);
  console.log(`  Found ${totalDetections} sensitive entities`);
}

function isSubPath(parentPath, childPath) {
  const parent = path.resolve(parentPath);
  const child = path.resolve(childPath);
  return child === parent || child.startsWith(parent + path.sep);
}

async function main() {
  // Получаем параметры из командной строки
  const inputPath = process.argv[2];
  const outputPath = process.argv[3];

  if (!inputPath || !outputPath) {
    console.error("Usage: node doc-sanit.js <input_path> <output_path>");
    console.error("Example file: node doc-sanit.js input.txt output.txt");
    console.error("Example dir:  node doc-sanit.js ./input_dir ./output_dir");
    process.exit(1);
  }

  if (path.resolve(inputPath) === path.resolve(outputPath)) {
    console.error("Error: input and output paths must be different");
    process.exit(1);
  }

  let inputStats;
  try {
    inputStats = statSync(inputPath);
  } catch (err) {
    console.error(`Error accessing input path: ${err.message}`);
    process.exit(1);
  }

  if (inputStats.isFile()) {
    try {
      await sanitizeFile(inputPath, outputPath);
    } catch (err) {
      console.error(err.message);
      process.exit(1);
    }
    return;
  }

  if (!inputStats.isDirectory()) {
    console.error("Error: input path must be a file or directory");
    process.exit(1);
  }

  if (isSubPath(inputPath, outputPath)) {
    console.error("Error: output directory cannot be inside input directory");
    process.exit(1);
  }

  const files = collectFilesRecursively(inputPath);
  let failedCount = 0;

  for (const file of files) {
    const relative = path.relative(inputPath, file);
    const outFile = path.join(outputPath, relative);
    try {
      await sanitizeFile(file, outFile);
    } catch (err) {
      failedCount += 1;
      console.error(err.message);
    }
  }

  console.log("");
  console.log(`Done. Processed ${files.length} file(s). Failed: ${failedCount}.`);

  if (failedCount > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(`Error during redaction: ${err.message}`);
  process.exit(1);
});
