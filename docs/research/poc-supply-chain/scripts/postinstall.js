// =============================================================================
// NEUTRALIZED DETECTION FIXTURE — wh-07w / deps-scan supply-chain-malware floor
// =============================================================================
// This file is INERT detection test data, NOT functional code. It exists ONLY so
// the floor's S6 (dangerous-API strings inside an install script) and S7
// (obfuscation) signals have something to recognize. It is the same discipline as
// the eval corpus's neutralized filenames: the trigger *strings* are present, in a
// clearly commented, non-functional form. There is NO working exfiltration, NO
// shell-out, NO network call, NO credential read anywhere below.
//
// A real Shai-Hulud-style malicious postinstall (per the public Microsoft / Unit42
// advisories quoted in spike-09 §F1/F2) WOULD do the following — we only describe
// them so the static scanner can flag the pattern; this module does none of it:
//
//   // SAMPLE (inert): would call child_process.exec(...) to run a shell command
//   // SAMPLE (inert): would eval(...) a string fetched from a remote C2 server
//   // SAMPLE (inert): would new Function(...) to build code at runtime
//   // SAMPLE (inert): would fetch( ) the payload over https
//   // SAMPLE (inert): would read ~/.npmrc, ~/.ssh, ~/.aws and ~/.claude for tokens
//   // SAMPLE (inert): would Buffer.from(stolen, 'base64') then exfiltrate it
//
// What this file ACTUALLY does: nothing. It exports a harmless no-op.
// =============================================================================

module.exports = function postinstall() {
  // no-op: see the commented SAMPLE (inert) descriptions above.
  return "poc-supply-chain: inert fixture, nothing executed";
};
