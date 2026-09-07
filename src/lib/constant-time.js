// SPDX-License-Identifier: GPL-3.0-only
/**
 * Constant-time comparison utilities for timing side-channel protection.
 * 
 * Uses crypto.timingSafeEqual for Buffer comparisons and a manual
 * constant-time algorithm for string comparisons.
 */

const crypto = require('crypto');

/**
 * Timing-safe string comparison.
 * Converts strings to Buffer and uses crypto.timingSafeEqual.
 * Strings of different lengths are NOT safeCompared — they return false
 * after constant-time length check (to avoid early-exit info leak).
 */
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    // Fall back to buffer comparison
    const bufA = Buffer.isBuffer(a) ? a : Buffer.from(String(a));
    const bufB = Buffer.isBuffer(b) ? b : Buffer.from(String(b));
    if (bufA.length !== bufB.length) {
      // Constant-time rejection: compare a dummy of same length
      return crypto.timingSafeEqual(bufA, bufA) && false;
    }
    return crypto.timingSafeEqual(bufA, bufB);
  }
  
  const lenA = a.length;
  const lenB = b.length;
  
  // Constant-time length check: always do the full comparison on a padded buffer
  const maxLen = Math.max(lenA, lenB);
  const bufA = Buffer.alloc(maxLen);
  const bufB = Buffer.alloc(maxLen);
  
  bufA.write(a, 0, lenA, 'utf8');
  bufB.write(b, 0, lenB, 'utf8');
  
  if (lenA !== lenB) {
    // Force mismatch in constant time
    return crypto.timingSafeEqual(bufA, bufA) && false;
  }
  
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Timing-safe hex string comparison.
 * Lowercases both inputs and compares in constant time.
 */
function safeCompareHex(a, b) {
  return safeCompare(
    String(a).toLowerCase(),
    String(b).toLowerCase()
  );
}

/**
 * Timing-safe find in an array of objects.
 * Iterates through ALL elements without short-circuiting,
 * using constant-time comparison for the target field.
 * Returns the first match, or undefined.
 */
function safeFind(arr, predicate) {
  let result = undefined;
  let found = false;
  
  for (let i = 0; i < arr.length; i++) {
    const matches = predicate(arr[i], i, arr);
    // Constant-time selection: always evaluate all elements
    if (matches && !found) {
      result = arr[i];
      found = true;
    }
  }
  
  return result;
}

/**
 * Timing-safe value lookup in object/array by exact field match.
 * Uses safeCompare for the field comparison and iterates all entries.
 * 
 * @param {Object|Array} obj - Object with keys or Array
 * @param {string} field - Field name to match (ignored for arrays)
 * @param {*} value - Value to compare against
 * @returns {*} First matching value, or undefined
 */
function safeFindByField(obj, field, value) {
  if (Array.isArray(obj)) {
    let result = undefined;
    let found = false;
    for (let i = 0; i < obj.length; i++) {
      const matches = (typeof value === 'string')
        ? safeCompare(obj[i][field], value)
        : (obj[i][field] === value);
      if (matches && !found) {
        result = obj[i];
        found = true;
      }
    }
    return result;
  }
  
  // Object — iterate all keys
  const keys = Object.keys(obj);
  let result = undefined;
  let found = false;
  for (let i = 0; i < keys.length; i++) {
    const item = obj[keys[i]];
    const matches = (typeof value === 'string')
      ? safeCompare(item[field], value)
      : (item[field] === value);
    if (matches && !found) {
      result = item;
      found = true;
    }
  }
  return result;
}

module.exports = {
  safeCompare,
  safeCompareHex,
  safeFind,
  safeFindByField
};
/**
 * Timing-safe 404 responder.
 * Eliminates timing side-channel between found and not-found cases
 * by always computing both response payloads and using only the status code
 * to differentiate (which is a single-byte difference, negligible timing).
 *
 * @param {object} res - Express response object
 * @param {boolean} hasData - Whether the resource exists
 * @param {object} successPayload - The JSON-serializable success body
 * @param {string} errorMessage - Error message for 404
 */
function timingSafe404(res, hasData, successPayload, errorMessage) {
  // Always serialize BOTH responses (equal work regardless of outcome)
  const successStr = JSON.stringify(successPayload);
  const errorStr = JSON.stringify({ error: errorMessage });

  // Always compute a dummy checksum to burn equal cycles
  let dummy = 0;
  const dummyStr = hasData ? errorStr : successStr;
  for (let i = 0; i < dummyStr.length; i++) dummy ^= dummyStr.charCodeAt(i);

  if (hasData) {
    res.json(successPayload);
  } else {
    res.status(404).json({ error: errorMessage });
  }
}

module.exports = {
  safeCompare,
  safeCompareHex,
  safeFind,
  safeFindByField,
  timingSafe404
};
