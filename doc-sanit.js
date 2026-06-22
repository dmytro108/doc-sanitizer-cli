// doc-sanit.js
const { OpenRedaction } = require("openredaction");
const { readFileSync, writeFileSync } = require("fs");
const path = require("path");

const redactor = new OpenRedaction();

// Получаем параметры из командной строки
const inputFile = process.argv[2];
const outputFile = process.argv[3];

if (!inputFile || !outputFile) {
  console.error("Usage: node doc-sanit.js <input_file> <output_file>");
  console.error("Example: node doc-sanit.js input.txt output.txt");
  process.exit(1);
}

if (path.resolve(inputFile) === path.resolve(outputFile)) {
  console.error("Error: input and output files must be different");
  process.exit(1);
}

// Читаем текст из файла
let text;
try {
  const raw = readFileSync(inputFile);
  // Detect BOM and decode accordingly, otherwise assume UTF-8
  if (raw[0] === 0xff && raw[1] === 0xfe) {
    // UTF-16 LE
    text = raw.slice(2).toString("utf16le");
  } else if (raw[0] === 0xfe && raw[1] === 0xff) {
    // UTF-16 BE
    text = raw.slice(2).swap16().toString("utf16le");
  } else if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf) {
    // UTF-8 BOM
    text = raw.slice(3).toString("utf-8");
  } else {
    text = raw.toString("utf-8");
  }
} catch (err) {
  console.error(`Error reading file: ${err.message}`);
  process.exit(1);
}

// Детектируем и удаляем PII
redactor.detect(text).then((result) => {
  // Пишем очищенный текст
  try {
    writeFileSync(outputFile, result.redacted, "utf-8");
  } catch (err) {
    console.error(`Error writing file: ${err.message}`);
    process.exit(1);
  }
  console.log(`✓ Redacted: ${inputFile} → ${outputFile}`);
  console.log(`  Found ${result.detections.length} sensitive entities`);

  // Показываем найденные сущности (для отладки)
  if (result.detections.length > 0) {
    console.error("  Detected:");
    result.detections.forEach((entity) => {
      console.error(
        `    - ${entity.type}: "${entity.value}" → "${entity.placeholder}"`,
      );
    });
  }
}).catch((err) => {
  console.error(`Error during redaction: ${err.message}`);
  process.exit(1);
});
