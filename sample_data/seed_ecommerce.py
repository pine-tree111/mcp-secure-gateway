"""Seed script for sample e-commerce SQLite database.

Ref: PRAGMA journal_mode = DELETE is mandatory for read-only SQLite mounts.
"""

import sqlite3
from pathlib import Path


def seed_database(db_path: Path) -> None:
    """Create and seed ecommerce database with test tables and sample records."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("PRAGMA journal_mode = DELETE")

    cursor.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            ssn TEXT NOT NULL,
            country TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total_amount REAL NOT NULL,
            status TEXT NOT NULL,
            ordered_at TEXT NOT NULL,
            FOREIGN KEY(customer_id) REFERENCES customers(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    """)

    customers_data = [
        (
            "Alice Cooper",
            "alice@example.com",
            "555-123-4567",
            "123-45-6789",
            "US",
            "2026-01-10T10:00:00Z",
        ),
        (
            "Bob Martin",
            "bob.martin@company.org",
            "555-987-6543",
            "987-65-4321",
            "UK",
            "2026-02-15T14:30:00Z",
        ),
        (
            "Carol White",
            "carol@service.net",
            "+1-555-456-7890",
            "456-78-1234",
            "CA",
            "2026-03-01T09:15:00Z",
        ),
        (
            "David Zhang",
            "david.z@domain.com",
            "555-321-7654",
            "321-76-5432",
            "SG",
            "2026-04-12T18:45:00Z",
        ),
    ]
    cursor.executemany(
        "INSERT INTO customers (name, email, phone, ssn, country, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        customers_data,
    )

    products_data = [
        ("Enterprise Gateway License", "Software", 4999.00, 50),
        ("Secure Enclave Micro-controller", "Hardware", 129.50, 200),
        ("Hardware Security Module (HSM)", "Hardware", 2499.00, 15),
        ("Zero-Trust Consulting Bundle", "Services", 8500.00, 10),
    ]
    cursor.executemany(
        "INSERT INTO products (title, category, price, stock) VALUES (?, ?, ?, ?)",
        products_data,
    )

    orders_data = [
        (1, 1, 1, 4999.00, "COMPLETED", "2026-05-01T11:00:00Z"),
        (2, 2, 2, 259.00, "SHIPPED", "2026-05-03T16:20:00Z"),
        (3, 3, 1, 2499.00, "PROCESSING", "2026-05-10T13:45:00Z"),
        (4, 4, 1, 8500.00, "COMPLETED", "2026-05-12T08:30:00Z"),
    ]
    cursor.executemany(
        "INSERT INTO orders (customer_id, product_id, quantity, total_amount, status, ordered_at) VALUES (?, ?, ?, ?, ?, ?)",
        orders_data,
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    target = Path("sample_data/ecommerce.db")
    seed_database(target)
    print(f"Database seeded successfully at {target}")
