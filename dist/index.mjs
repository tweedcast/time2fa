import crypto from 'crypto';

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
const SHA1 = "sha1";
const DEFAULT_TOTP_PERIOD = 30;
const DEFAULT_TOTP_DIGITS = 6;
const DEFAULT_TOTP_SECRET_SIZE = 10;
const DEFAULT_TOTP_ALGO = SHA1;
const INVALID_SECRET_ERR = "Invalid secret";

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
}

const Encode32 = (key) => {
  if (!Buffer.isBuffer(key)) {
    throw new TypeError("The input must be a Buffer");
  }
  let binary = "";
  for (let i = 0; i < key.length; i++) {
    binary += key[i].toString(2).padStart(8, "0");
  }
  let base32 = "";
  for (let i = 0; i < binary.length; i += 5) {
    const chunk = binary.substring(i, i + 5);
    base32 += BASE32_CHARS[parseInt(chunk, 2)];
  }
  const padding = base32.length % 8;
  if (padding > 0) {
    base32 += "=".repeat(8 - padding);
  }
  return base32;
};
const Decode32 = (s) => {
  const len = s.length;
  let bits = 0;
  let value = 0;
  let offset = 0;
  const result = Buffer.alloc(Math.ceil(len * 5 / 8));
  for (let i = 0; i < len; i++) {
    const char = s.charAt(i);
    const index = BASE32_CHARS.indexOf(char.toUpperCase());
    if (index === 32) {
      continue;
    }
    if (index === -1) {
      throw new ValidationError(INVALID_SECRET_ERR);
    }
    value = value << 5 | index;
    bits += 5;
    if (bits >= 8) {
      result[offset++] = value >> bits - 8;
      bits -= 8;
    }
  }
  return result.subarray(0, offset);
};

class HmacBased {
  generatePasscode(options, config) {
    const secretBytes = Buffer.from(Decode32(options.secret));
    if (secretBytes.length !== config.secretSize) {
      throw new ValidationError(INVALID_SECRET_ERR);
    }
    const buf = Buffer.alloc(8);
    buf.writeUInt32BE(options.counter, 4);
    const hmac = crypto.createHmac(config.algo, secretBytes);
    hmac.update(buf);
    const hmacResult = hmac.digest();
    const offset = hmacResult[hmacResult.length - 1] & 15;
    const value = (hmacResult[offset] & 127) << 24 | (hmacResult[offset + 1] & 255) << 16 | (hmacResult[offset + 2] & 255) << 8 | hmacResult[offset + 3] & 255;
    const mod = value % Math.pow(10, config.digits);
    return mod.toString().padStart(config.digits, "0");
  }
  validate(options, config) {
    const validatedConfig = generateConfig(config);
    const passcode = options?.passcode.replace(/\s/g, "") || "";
    if (passcode.length !== validatedConfig.digits) {
      throw new ValidationError("Invalid passcode");
    }
    const code = this.generatePasscode(options, validatedConfig);
    if (code === passcode) {
      return true;
    }
    return false;
  }
}

class GenerateKey {
  constructor(options, config) {
    if (!options?.issuer) {
      throw new Error("No issuer found");
    }
    if (!options?.user) {
      throw new Error("No user found");
    }
    this.issuer = options.issuer;
    this.user = options.user;
    this.config = generateConfig(config);
    this.secret = generateSecret(this.config.secretSize);
    this.url = generateUrl(
      {
        issuer: this.issuer,
        user: this.user,
        secret: this.secret
      },
      this.config
    );
  }
}

class TimeBased {
  generateKey(options, config) {
    return new GenerateKey(options, config);
  }
  generatePasscodes(options, config) {
    const validatedConfig = generateConfig(config);
    const epoch = Math.floor(Date.now() / 1e3);
    const counter = Math.floor(epoch / validatedConfig.period);
    const counters = [counter];
    if (options.drift && options.drift > 0) {
      for (let i = 1; i <= options.drift; i++) {
        counters.push(counter + i);
        counters.push(counter - i);
      }
    }
    const codes = [];
    const hmac = new HmacBased();
    for (let i = 0; i < counters.length; i++) {
      codes.push(
        hmac.generatePasscode(
          {
            secret: options.secret,
            counter: counters[i]
          },
          validatedConfig
        )
      );
    }
    return codes;
  }
  validate(options, config) {
    const validatedConfig = generateConfig(config);
    const passcode = options?.passcode.replace(/\s/g, "") || "";
    if (passcode.length !== validatedConfig.digits) {
      throw new ValidationError("Invalid passcode");
    }
    const codes = this.generatePasscodes(options, validatedConfig);
    if (codes.includes(passcode)) {
      return true;
    }
    return false;
  }
}

const generateConfig = (config) => {
  return {
    algo: config?.algo || DEFAULT_TOTP_ALGO,
    digits: config?.digits || DEFAULT_TOTP_DIGITS,
    period: config?.period || DEFAULT_TOTP_PERIOD,
    secretSize: config?.secretSize || DEFAULT_TOTP_SECRET_SIZE
  };
};
const generateSecret = (secretSize = DEFAULT_TOTP_SECRET_SIZE) => {
  const bytes = Buffer.from(crypto.randomBytes(secretSize));
  return Encode32(bytes);
};
const generateBackupCodes = (numCodes = 10, codeLength = DEFAULT_TOTP_DIGITS) => {
  const backupCodes = [];
  for (let i = 0; i < numCodes; i++) {
    let code = "";
    for (let j = 0; j < codeLength; j++) {
      code += crypto.randomInt(0, 10).toString();
    }
    backupCodes.push(code);
  }
  return backupCodes;
};
const generateUrl = (options, config) => {
  const url = new URL(`otpauth://totp`);
  url.pathname = `/${encodeURIComponent(options.issuer)}:${encodeURIComponent(
    options.user
  )}`;
  const params = new URLSearchParams({
    issuer: options.issuer,
    period: config.period.toString(),
    // Currently ignored by the google auth implementations
    secret: options.secret
  });
  if (config.algo !== DEFAULT_TOTP_ALGO) {
    params.set("algorithm", config.algo);
  }
  if (config.digits !== DEFAULT_TOTP_DIGITS) {
    params.set("digits", config.digits.toString());
  }
  url.search = params.toString();
  return url.toString();
};
const Totp = new TimeBased();
const Hotp = new HmacBased();

export { Hotp, Totp, generateBackupCodes, generateConfig, generateSecret, generateUrl };
