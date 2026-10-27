"""Small service module for the LOC fixture."""

from dataclasses import dataclass


@dataclass
class Order:
    order_id: int
    total_cents: int

    def total(self) -> float:
        """Total in currency units."""
        return self.total_cents / 100


def summarize(orders):
    # Sum all orders.
    return sum(order.total() for order in orders)
