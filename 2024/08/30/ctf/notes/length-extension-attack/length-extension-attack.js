/**
 * 
 * @param {Uint8Array} u8a 
 * @returns {String}
 */
export const toHex = (u8a) => Array.from(u8a).map(byte => byte.toString(16).padStart(2, '0')).join('');

/**
 * 
 * @param {String} sHex 
 * @returns {Uint8Array}
 */
export const fromHex = (sHex) => new Uint8Array(sHex.match(/.{2}/g)?.map(sByte => parseInt(sByte, 16)));

export class Base64 {
  static #A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";
  static #rA = new Map(Array.from(Array.from(this.#A).entries()).map(([i, v]) => [v, i]));

  /**
   * 
   * @param {Uint8Array} u8a 
   * @returns {String}
   */
  static b64encode(u8a) {
    let enc = "";
    for (let i = 0; i < u8a.length; i += 3) {
      if (i+3 > u8a.length) {
        enc += this.#A.charAt(u8a[i]>>>2);
        if (i+1 == u8a.length) {
          enc += this.#A.charAt((u8a[i]&0x3)<<4);
          enc += "==";
        } else {
          enc += this.#A.charAt((u8a[i]&0x3)<<4 | (u8a[i+1]>>>4));
          enc += this.#A.charAt((u8a[i+1]&0xf)<<2);
          enc += '=';
        }
      } else {
        enc += [
          this.#A.charAt(u8a[i]>>>2),
          this.#A.charAt((u8a[i]&0x3)<<4 | (u8a[i+1]>>>4)),
          this.#A.charAt((u8a[i+1]&0xf)<<2 | (u8a[i+2]>>>6)),
          this.#A.charAt(u8a[i+2]&0x3f)
        ].join("")
      }
    }
    return enc;
  }

  /**
   * 
   * @param {String} enc 
   * @returns {Uint8Array}
   */
  static b64decode(enc) {
    console.assert((enc.length&0x3) == 0, "Length of Base64 should be divided by 4");

    let n = (enc.length>>>2)*3 - (enc.charCodeAt(enc.length-1) == 61?1:0) - (enc.charCodeAt(enc.length-2) == 61?1:0);
    let dec = new Uint8Array(n);

    let j;
    for (let i = 0; i < enc.length; i += 4) {
      j = (i>>>2)*3;
      if (i+4 == enc.length) {
        dec[j] = (this.#rA.get(enc.charAt(i))<<2)|(this.#rA.get(enc.charAt(i+1))>>>4);
        if (j+2 == dec.length) {
          dec[j+1] = ((this.#rA.get(enc.charAt(i+1))&0xf)<<4)|(this.#rA.get(enc.charAt(i+2))>>>2);
        } else {
          dec[j+2] = ((this.#rA.get(enc.charAt(i+2))&0x3)<<6)|(this.#rA.get(enc.charAt(i+3)));
        }
      } else {
        dec[j]   = (this.#rA.get(enc.charAt(i))<<2)|(this.#rA.get(enc.charAt(i+1))>>>4);
        dec[j+1] = ((this.#rA.get(enc.charAt(i+1))&0xf)<<4)|(this.#rA.get(enc.charAt(i+2))>>>2);
        dec[j+2] = ((this.#rA.get(enc.charAt(i+2))&0x3)<<6)|(this.#rA.get(enc.charAt(i+3)));
      }
    }
    return dec;
  }
}


/**
 * MD5 Hash Algorithm
 */
export class MD5 {
  static #T = new Uint32Array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
  ]);

  static #S = new Uint32Array([
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]);

  static #getDefaultIv = () => new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]);

  static #lrShift = (num, bits) => ((num<<bits)|(num>>>(32-bits)));
  static #F = (b,c,d) => ((b&c)|((~b)&d));
  static #G = (b,c,d) => ((b&d)|(c&(~d)));
  static #H = (b,c,d) => (b^c^d);
  static #I = (b,c,d) => (c^(b|(~d)));

  /**
   * 
   * @param {Uint32Array} blocks 
   * @param {Uint32Array} vector 
   */
  static #core(blocks, vector) {
    console.assert((blocks.length&0xf) == 0, "Length of blocks should be divided by 16");
    console.assert(vector.length == 4, "Length of vector should equal to 4");

    let res = new Uint32Array(4);
    let g, k, tmp;
    for (let bp = 0; bp < blocks.length; bp += 16) {
      for (let i = 0; i < 4; i++) {
        res[i] = vector[i];
      }

      for (let r = 0; r < 4; r++) {
        for (let i = 0; i < 16; i++) {
          switch (r) {
            case 0:
              g = this.#F(res[1], res[2], res[3]);
              k = i;
              break;
            case 1:
              g = this.#G(res[1], res[2], res[3]);
              k = (1+5*i)&0xf;
              break;
            case 2:
              g = this.#H(res[1], res[2], res[3]);
              k = (5+3*i)&0xf;
              break;
            case 3:
              g = this.#I(res[1], res[2], res[3]);
              k = (7*i)&0xf;
              break;
          }
          tmp = res[1] + this.#lrShift(
            (res[0] + g + blocks[bp+k] + this.#T[r*16 + i])&0xffffffff,
            this.#S[r*16 + i]
          );
          res[0] = res[3];
          res[3] = res[2];
          res[2] = res[1];
          res[1] = tmp;
        }
      }

      for (let i = 0; i < 4; i++) {
        vector[i] += res[i];
      }
    }
  }

  /**
   * 
   * @param {Uint8Array} msg 
   * @returns {Uint8Array}
   */
  static #pad(msg) {
    let res = new Uint8Array(
      ((msg.length+9)&0x3f)>0 ? (((msg.length+9)>>>6)+1)<<6 : ((msg.length+9)>>>6)<<6
    );
    // Copy origin data
    for (let i = 0; i < msg.length; i++) {
      res[i] = msg[i];
    }
    // Set 0x80
    res[msg.length] = 0x80;
    // Set length
    let n = msg.length << 3;
    for (let i = 0; i < 8; i++) {
      if (n > 0) {
        res[res.length - 8 + i] = (n&0xff);
        n >>>= 8;
      } else {
        break;
      }
    }
    return res;
  }

  /**
   * 
   * @param {Uint8Array} msg 
   * @returns {Uint8Array}
   */
  static digest(msg) {
    let vector = this.#getDefaultIv();
    let blocks = new Uint32Array(this.#pad(msg).buffer);
    this.#core(blocks, vector);
    return new Uint8Array(vector.buffer);
  }

  /**
   * 
   * @param {Uint8Array} msg 
   * @returns {String}
   */
  static hexDigest(msg) {
    return toHex(this.digest(msg));
  }

  /**
   * Generate payload for Length-Extension-Attack
   * @param {Number} msgLength 
   * @param {Uint8Array} extension 
   * @returns {Uint8Array}
   */
  static lengthExtensionAttackPayloadGen(msgLength, extension) {
    let payload = new Uint8Array(((119-(msgLength&0x3f))&0x3f)+9 + extension.length);
    payload[0] = 0x80;
    let n = msgLength << 3;
    for (let i = 0; i < 8; i++) {
      if (n > 0) {
        payload[payload.length - extension.length - 8 + i] = (n&0xff);
        n >>>= 8;
      } else {
        break;
      }
    }
    for (let i = 0; i < extension.length; i++) {
      payload[payload.length-1-i] = extension[extension.length-1-i];
    }
    return payload;
  }

  /**
   * Calculate `MD5.digest(msg || payload)` for Length-Extension-Attack
   * @param {String} msgMd5 
   * @param {Number} msgLength 
   * @param {Uint8Array} extension 
   * @returns {String}
   */
  static lengthExtensionAttackDigest(msgMd5, msgLength, extension) {
    let vector = new Uint32Array(fromHex(msgMd5).buffer);

    let extBytes = new Uint8Array(
      ((extension.length+9)&0x3f)>0 ? (((extension.length+9)>>>6)+1)<<6 : ((extension.length+9)>>>6)<<6
    );
    // Copy origin data
    for (let i = 0; i < extension.length; i++) {
      extBytes[i] = extension[i];
    }
    // Set 0x80
    extBytes[extension.length] = 0x80;
    // Set length
    let n = (
      (((msgLength+9)&0x3f)>0 ? (((msgLength+9)>>>6)+1)<<6 : ((msgLength+9)>>>6)<<6) + 
      extension.length
    ) << 3;
    for (let i = 0; i < 8; i++) {
      if (n > 0) {
        extBytes[extBytes.length - 8 + i] = (n&0xff);
        n >>>= 8;
      } else {
        break;
      }
    }

    this.#core(new Uint32Array(extBytes.buffer), vector);
    return new Uint8Array(vector.buffer);
  }

  /**
   * Calculate `MD5.hexDigest(msg || payload)` for Length-Extension-Attack
   * @param {String} msgMd5 
   * @param {Number} msgLength 
   * @param {Uint8Array} extension 
   * @returns {String}
   */
  static lengthExtensionAttackHexDigest(msgMd5, msgLength, extension) {
    return toHex(this.lengthExtensionAttackDigest(msgMd5, msgLength, extension));
  }
}
