// One synthetic AWS key ID that the secret engine and several SAST secret packs all recognise.
// Expected: exactly one stored finding.
const awsKeyId = "AKIA6IJ2JINIGO2I42LG"; // SEC-DUP-001

module.exports = { awsKeyId };
