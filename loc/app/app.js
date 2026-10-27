/**
 * Entry point for the LOC fixture.
 */
const { formatPrice } = require("../minified/widget");

function describe(order) {
  return `#${order.id}: ${formatPrice(order.cents)}`;
}

module.exports = { describe };
