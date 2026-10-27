// Regular, developer-written JavaScript: counted.
function formatPrice(cents) {
  const units = Math.floor(cents / 100);
  const rest = String(cents % 100).padStart(2, "0");
  return `${units}.${rest}`;
}

module.exports = { formatPrice };
