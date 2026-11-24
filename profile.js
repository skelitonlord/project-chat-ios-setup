"use strict";

globalThis.ProjectChatProfile = (() => {
  const MIME = "application/x-apple-aspen-config";
  const alpha = /[^A-Za-z0-9_-]/;
  const MAX_DER = 512;

  function encode64(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }

  function decodeFragment(fragment) {
    const payload = fragment.startsWith("#pc-v1=") ? fragment.slice(7) : "";
    if (payload.length < 342 || payload.length > 683 || alpha.test(payload)) throw new Error("Invalid profile QR.");
    const bytes = Uint8Array.from(atob(payload.replaceAll("-", "+").replaceAll("_", "/")), (char) => char.charCodeAt(0));
    const canonical = encode64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    if (bytes.length > MAX_DER || canonical !== payload) throw new Error("Invalid profile QR.");
    return bytes;
  }

  // This decoder accepts the small DER subset emitted by the Ubuntu guided setup.
  function node(bytes, cursor, limit) {
    const start = cursor;
    const tag = bytes[cursor++];
    let length = bytes[cursor++];
    if (cursor > limit || (tag & 31) === 31) throw new Error("Invalid DER tag.");
    if (length >= 128) {
      const count = length - 128;
      if (count < 1 || count > 2 || cursor + count > limit || bytes[cursor] === 0) throw new Error("Invalid DER length.");
      length = 0;
      for (let n = 0; n < count; n++) length = length * 256 + bytes[cursor++];
      if (length < 128) throw new Error("Noncanonical DER length.");
    }
    const end = cursor + length;
    if (end > limit) throw new Error("Truncated DER.");
    return {tag, start, body: cursor, end};
  }

  function expect(value, tag) {
    if (!value || value.tag !== tag) throw new Error("Unsupported certificate structure.");
    return value;
  }

  function children(bytes, container, tag) {
    const parent = expect(container, tag);
    const result = [];
    for (let at = parent.body; at < parent.end;) {
      const child = node(bytes, at, parent.end);
      result.push(child);
      at = child.end;
      if (result.length > 12) throw new Error("Certificate has too many fields.");
    }
    return result;
  }

  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  const value = (bytes, part) => bytes.subarray(part.body, part.end);
  const raw = (bytes, part) => bytes.subarray(part.start, part.end);

  function requireHex(bytes, part, tag, expected) {
    if (hex(value(bytes, expect(part, tag))) !== expected) throw new Error("Certificate format changed.");
  }

  function requireAlgorithm(bytes, part) {
    const fields = children(bytes, part, 0x30);
    if (fields.length !== 1) throw new Error("Unexpected signature algorithm.");
    requireHex(bytes, fields[0], 0x06, "2a8648ce3d040302"); // ECDSA with SHA-256
  }

  function privateName(bytes, subject) {
    const names = children(bytes, subject, 0x30);
    if (names.length !== 1) throw new Error("Unexpected certificate name.");
    const set = children(bytes, names[0], 0x31);
    if (set.length !== 1) throw new Error("Unexpected certificate name.");
    const name = children(bytes, set[0], 0x30);
    if (name.length !== 2) throw new Error("Unexpected certificate name.");
    requireHex(bytes, name[0], 0x06, "550403"); // Common name
    const title = new TextDecoder("utf-8", {fatal: true}).decode(value(bytes, expect(name[1], 0x0c)));
    const match = /^Project Chat Companion CA \((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\)$/.exec(title);
    if (!match) throw new Error("This is not a guided Project Chat certificate.");
    const octets = match.slice(1).map(Number);
    if (octets.some((octet, index) => octet > 255 || String(octet) !== match[index + 1])
        || !(octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
             || (octets[0] === 192 && octets[1] === 168))) {
      throw new Error("The certificate is not for a private Wi-Fi address.");
    }
  }

  function requireExtensions(bytes, container) {
    const enclosed = children(bytes, container, 0xa3);
    if (enclosed.length !== 1) throw new Error("Unexpected certificate extensions.");
    const extensions = children(bytes, enclosed[0], 0x30);
    const results = new Set();
    for (const entry of extensions) {
      const parts = children(bytes, entry, 0x30);
      if (parts.length !== 2 && parts.length !== 3) throw new Error("Unexpected extension.");
      const oid = hex(value(bytes, expect(parts[0], 0x06)));
      if (results.has(oid)) throw new Error("Duplicate certificate extension.");
      results.add(oid);
      if (oid === "551d0e") { // Subject Key Identifier
        const key = value(bytes, expect(parts[1], 0x04));
        if (parts.length !== 2 || key.length !== 22 || key[0] !== 4 || key[1] !== 20) throw new Error("Invalid key identifier.");
      } else {
        if (parts.length !== 3) throw new Error("Missing critical certificate extension.");
        requireHex(bytes, parts[1], 0x01, "ff");
        if (oid === "551d13") requireHex(bytes, parts[2], 0x04, "30060101ff020100"); // CA true, path length 0
        else if (oid === "551d0f") requireHex(bytes, parts[2], 0x04, "03020106"); // Certificate and CRL signing
        else throw new Error("Unsupported certificate extension.");
      }
    }
    if (results.size !== 3) throw new Error("Incomplete certificate extensions.");
  }

  function verifyValidity(bytes, container) {
    const dates = children(bytes, container, 0x30);
    function parse(field) {
      if (field.tag !== 0x17 && field.tag !== 0x18) throw new Error("Invalid certificate validity.");
      const text = new TextDecoder().decode(value(bytes, field));
      const match = new RegExp("^(" + (field.tag === 0x17 ? "[0-9]{2}" : "[0-9]{4}")
        + ")([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$").exec(text);
      if (!match) throw new Error("Invalid certificate validity.");
      const [, year, month, day, hour, minute, second] = match;
      const fullYear = year.length === 4 ? year : (+year >= 50 ? "19" : "20") + year;
      return Date.parse(fullYear + "-" + month + "-" + day + "T" + hour + ":" + minute + ":" + second + "Z");
    }
    if (dates.length !== 2 || !(parse(dates[0]) <= Date.now() && Date.now() < parse(dates[1]))) {
      throw new Error("This certificate is expired or not yet valid.");
    }
  }

  function signature(bytes, part) {
    const bits = value(bytes, expect(part, 0x03));
    if (bits[0] !== 0) throw new Error("Invalid certificate signature.");
    const sequence = node(bits, 1, bits.length);
    const ints = children(bits, sequence, 0x30);
    if (sequence.end !== bits.length || ints.length !== 2) throw new Error("Invalid certificate signature.");
    const fixed = new Uint8Array(64);
    for (const [index, integer] of ints.entries()) {
      const data = value(bits, expect(integer, 0x02));
      if (!data.length || data[0] & 128 || (data.length > 1 && data[0] === 0 && !(data[1] & 128))) {
        throw new Error("Invalid signature integer.");
      }
      const magnitude = data[0] === 0 ? data.subarray(1) : data;
      if (!magnitude.length || magnitude.length > 32) throw new Error("Invalid signature width.");
      fixed.set(magnitude, index * 32 + 32 - magnitude.length);
    }
    return fixed;
  }

  async function validate(fragment) {
    const bytes = decodeFragment(fragment);
    const root = node(bytes, 0, bytes.length);
    const outer = children(bytes, root, 0x30);
    if (root.end !== bytes.length || outer.length !== 3) throw new Error("Invalid certificate.");
    const tbs = children(bytes, outer[0], 0x30);
    if (tbs.length !== 8) throw new Error("Unexpected certificate fields.");
    requireHex(bytes, tbs[0], 0xa0, "020102");
    expect(tbs[1], 0x02); // Serial number
    requireAlgorithm(bytes, tbs[2]);
    requireAlgorithm(bytes, outer[1]);
    if (hex(raw(bytes, expect(tbs[3], 0x30))) !== hex(raw(bytes, expect(tbs[5], 0x30)))) {
      throw new Error("Expected a self-issued trust certificate.");
    }
    verifyValidity(bytes, tbs[4]);
    privateName(bytes, tbs[5]);
    requireExtensions(bytes, tbs[7]);
    const key = await crypto.subtle.importKey("spki", raw(bytes, expect(tbs[6], 0x30)),
      {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
    if (!await crypto.subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, signature(bytes, outer[2]), raw(bytes, outer[0]))) {
      throw new Error("Certificate signature failed verification.");
    }
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return {base64: encode64(bytes), fingerprint: hex(digest).match(/../g).join(":").toUpperCase()};
  }

  function makeProfile(certificate) {
    return '<?xml version="1.0" encoding="UTF-8"?>\n'
      + '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
      + '<plist version="1.0"><dict>'
      + '<key>PayloadType</key><string>Configuration</string>'
      + '<key>PayloadVersion</key><integer>1</integer>'
      + '<key>PayloadUUID</key><string>' + crypto.randomUUID() + '</string>'
      + '<key>PayloadIdentifier</key><string>io.projectchat.companion.trust</string>'
      + '<key>PayloadDisplayName</key><string>Project Chat Companion Trust</string>'
      + '<key>PayloadDescription</key><string>Contains one public CA certificate for your private Project Chat companion.</string>'
      + '<key>PayloadContent</key><array><dict>'
      + '<key>PayloadType</key><string>com.apple.security.root</string>'
      + '<key>PayloadVersion</key><integer>1</integer>'
      + '<key>PayloadUUID</key><string>' + crypto.randomUUID() + '</string>'
      + '<key>PayloadIdentifier</key><string>io.projectchat.companion.trust.root</string>'
      + '<key>PayloadDisplayName</key><string>Project Chat Companion CA</string>'
      + '<key>PayloadCertificateFileName</key><string>project-chat-companion-ca.cer</string>'
      + '<key>PayloadContent</key><data>' + certificate.base64 + '</data>'
      + '</dict></array></dict></plist>\n';
  }

  return Object.freeze({MIME, validate, makeProfile});
})();
