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

const redactor = new OpenRedaction();

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

async function sanitizeFile(inputPath, outputPath) {
  let raw;
  try {
    raw = readFileSync(inputPath);
  } catch (err) {
    throw new Error(`Error reading file ${inputPath}: ${err.message}`);
  }

  const text = decodeText(raw);
  const result = await redactor.detect(text);

  try {
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, result.redacted, "utf-8");
  } catch (err) {
    throw new Error(`Error writing file ${outputPath}: ${err.message}`);
  }

  console.log(`✓ Redacted: ${inputPath} -> ${outputPath}`);
  console.log(`  Found ${result.detections.length} sensitive entities`);
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
