const blockSizeBytes = 64;
const wordSizeBytes = 4;

function sha1(message) {
  const stream = padMessage(bytes(message));

  // SHA1 checksum is a sequence of 5 words. The algorithm starts
  // with 5 predefined words and then updates them using bits from the
  // input blocks.
  let hash = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  for (const block of blocks(stream)) {
    hash = digest(block, hash);
  }
  return hash.map(n => n.toString(16));
}

// Produces list of bytes from the given input.
function* bytes(input) {
  if (typeof input == "string") {
    for (const c of input.split("")) {
      yield c.charCodeAt(0);
    }
    return;
  }
  throw new Error("unsupported input type: " + typeof input);
}

// Parses the bytes list into a list of 16-word blocks.
function* blocks(stream) {
  let buf = [];
  for (const byte of stream) {
    buf.push(byte);
    if (buf.length == blockSizeBytes) {
      yield words(buf);
      buf = [];
    }
  }
  if (buf.length != 0) {
    throw new Error("incomplete block at the end of stream");
  }
}

// Pads the message to ensure that the total length is a multiple of 64 bytes.
// | message | eof | zeros | length |
function* padMessage(message) {
  let length = 0;
  for (const byte of message) {
    length++;
    yield byte;
  }
  // 'eof' byte is a bit '1' followed by seven zero bits.
  yield 128;
  yield* addZeros(length);
  yield* addLength(length);
}

function* addZeros(length) {
  // add 'z' zero bytes.
  //
  // The number of zeros 'z' is such that the whole stream (including the 8-byte
  // length marker at the end) has the length that is a multiple of 64 bytes.
  //
  // length + 1 + z + 8 = 64n
  // 64n >= length + 1 + 8

  const n = Math.ceil((length + 9) / blockSizeBytes);
  const z = blockSizeBytes * n - 9 - length;
  for (let i = 0; i < z; i++) {
    yield 0;
  }
}

function* addLength(length) {
  // 'length' is a 64-bit encoding of length of the message in bits.
  const seq = distribute(length * 8)
    .concat(Array(8).fill(0))
    .slice(0, 8)
    .reverse();
  for (const byte of seq) {
    yield byte;
  }
}

// Returns length representation as a sequence of bytes,
// least significant byte first.
function distribute(length) {
  if (length < 0) throw new Error("negative length");
  if (length == 0) return [];
  return [length % 256].concat(distribute(Math.floor(length / 256)));
}

// Groups a bytes stream into a words stream.
function words(stream) {
  if (stream.length == 0) return [];
  if (stream.length < wordSizeBytes) {
    throw new Error("incomplete word");
  }
  const word = stream
    .slice(0, wordSizeBytes)
    .reduce((s, byte) => s * 256 + byte, 0);
  return [word].concat(words(stream.slice(wordSizeBytes)));
}

function digest(block, sum) {
  if (block.length != blockSizeBytes / wordSizeBytes) {
    throw new Error("incorrect block size: " + block.length);
  }
  const W = [];
  for (let t = 0; t < 16; t++) {
    W[t] = block[t];
  }
  for (let t = 16; t < 80; t++) {
    W[t] = ROTL(1, uint32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]));
    checkUint32(W[t]);
  }

  let [a, b, c, d, e] = sum;

  for (let t = 0; t < 80; t++) {
    const T = uint32(ROTL(5, a) + f(t, b, c, d) + e + K(t) + W[t]);
    e = d;
    d = c;
    c = ROTL(30, b);
    b = a;
    a = T;
    checkUint32(c);
  }
  return addVec(sum, [a, b, c, d, e]);
}

function addVec(xs, ys) {
  if (xs.length == 0) return [];
  const [x, ...restx] = xs;
  const [y, ...resty] = ys;
  return [uint32(x + y), ...addVec(restx, resty)];
}

function uint32(v) {
  const max = 0xffffffff + 1;
  if (v < 0) {
    return uint32(v + max);
  }
  return v % max;
}

function checkUint32(value) {
  if (!isUint32(value)) throw new Error("not uint32: " + value);
}
function isUint32(x) {
  return x >= 0 && x <= 0xffffffff;
}

// Logical functions f[i].
function f(t, B, C, D) {
  checkUint32(B);
  checkUint32(C);
  checkUint32(D);
  if (t < 0 || t > 79) throw new Error("invalid f[i] number: " + t);

  if (t < 20) return uint32((B & C) | (~B & D));
  if (t < 40) return uint32(B ^ C ^ D);
  if (t < 60) return uint32((B & C) | (B & D) | (C & D));
  return uint32(B ^ C ^ D);
}

// Constants K[i].
function K(t) {
  if (t < 0 || t > 79) throw new Error("invalid K[i] number: " + t);
  if (t < 20) return 0x5a827999;
  if (t < 40) return 0x6ed9eba1;
  if (t < 60) return 0x8f1bbcdc;
  return 0xca62c1d6;
}

// Rotate-left function
function ROTL(times, value) {
  if (!isUint32(value)) {
    throw new Error("not uint32: " + value);
  }
  if (times < 0 || times >= 32) {
    throw new Error("invalid left shift amount: " + times);
  }
  return uint32(uint32(value << times) | (value >>> (32 - times)));
}

const table = [
  ["abc", "a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d"],
  ["", "da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709"],
  [
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1"
  ],
  [
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    "a49b2446 a02c645b f419f995 b6709125 3a04a259"
  ],
  [
    Array(1000000)
      .fill("a")
      .join(""),
    "34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f"
  ]
];

function check() {
  return table
    .map(function([val, hash]) {
      const got = sha1(val).join(" ");
      console.log(got == hash, got, hash);
      return got == hash;
    })
    .reduce((r, i) => r && i, true);
}

function run() {
  table.map(r => r[0]).forEach(sha1);
}

function time(func) {
  const n = 100;
  const t = Date.now();
  Array(n)
    .fill(0)
    .forEach(func);
  return (Date.now() - t) / n;
}

// console.log(sha1("abc"));
check() && console.log(time(run));
